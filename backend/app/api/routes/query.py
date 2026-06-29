import logging
import re
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_utils import require_auth
from app.config import settings
from app.core.agents.security_agent import analyse as security_analyse
from app.core.agents.supervisor import Intent, route
from app.core.rag.chain import query as general_query
from app.core.rag.retriever import retrieve
from app.db.session import get_db
from app.models.models import AuditLog, ChatSession, Finding, ScanUpload, User
from app.schemas.schemas import QueryRequest, QueryResponse, SessionHistoryResponse

logger = logging.getLogger("ragscan")
router = APIRouter(tags=["query"])
def _serialize_history(history: list[dict]) -> list[dict]:
    return [
        {
            "role": item.get("role", "assistant"),
            "text": item.get("text", ""),
            "ts": str(item.get("ts") or datetime.now(timezone.utc).isoformat()),
        }
        for item in history
    ]


def _clean_pdf_text(text: str) -> str:
    cleaned = text.strip()
    cleaned = re.sub(r"^\s{0,3}#{1,6}\s*", "", cleaned, flags=re.MULTILINE)
    cleaned = cleaned.replace("**", "").replace("__", "").replace("`", "")
    cleaned = re.sub(r"^\s*[-*+]\s+", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return cleaned.strip()


def _render_session_pdf(session_id: UUID, history: list[dict]) -> str:
    reports_dir = "reports"
    import os
    os.makedirs(reports_dir, exist_ok=True)
    path = f"{reports_dir}/chat_{session_id}.pdf"
    styles = getSampleStyleSheet()
    title = ParagraphStyle("ChatTitle", parent=styles["Title"], fontSize=18, spaceAfter=12)
    body = ParagraphStyle("ChatBody", parent=styles["Normal"], fontSize=10, spaceAfter=6)
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    story = [
        Paragraph("RAGScan Conversation Export", title),
        Spacer(1, 4 * mm),
    ]
    for item in history:
        role = str(item.get("role", "assistant")).title()
        text = _clean_pdf_text(str(item.get("text", "")))
        ts = str(item.get("ts", ""))
        story.append(Paragraph(f"{role} | {ts}", body))
        story.append(Paragraph(text.replace("\n", "<br/>") or " ", body))
        story.append(Spacer(1, 3 * mm))
    doc.build(story)
    return path


async def _load_session(db: AsyncSession, user_id: UUID, session_id: UUID | None) -> ChatSession:
    if session_id:
        session = await db.get(ChatSession, session_id)
        if not session or session.user_id != user_id:
            raise HTTPException(status_code=404, detail="Chat session not found")
        if not isinstance(session.history, list):
            session.history = []
        return session

    session = ChatSession(user_id=user_id, history=[])
    db.add(session)
    await db.flush()
    return session


_NO_LLM_MSG = (
    "LLM query features require ANTHROPIC_API_KEY to be set. "
    "Add it to backend/.env and restart the server. "
    "The /score and /ingest endpoints are fully functional without an API key."
)


@router.post("", response_model=QueryResponse)
async def chat(
    body: QueryRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    if not body.question.strip():
        raise HTTPException(status_code=422, detail="Question cannot be empty")

    if not settings.anthropic_api_key:
        return QueryResponse(answer=_NO_LLM_MSG, sources=[], intent="general", session_id=body.session_id)

    chat_session = await _load_session(db, user.id, body.session_id)

    try:
        intent = await route(body.question)
    except Exception as exc:
        logger.warning("Intent routing failed: %s", exc)
        intent = Intent.GENERAL

    findings: list[dict] = []
    scope_ids: list[UUID] = []
    if body.report_id:
        scope_ids.append(body.report_id)
    if body.report_ids:
        scope_ids.extend(body.report_ids)
    scope_ids = list(dict.fromkeys(scope_ids))

    user_upload_ids = (
        await db.execute(select(ScanUpload.id).where(ScanUpload.user_id == user.id))
    ).scalars().all()

    if scope_ids:
        owned_ids = (
            await db.execute(
                select(ScanUpload.id).where(
                    ScanUpload.id.in_(scope_ids),
                    ScanUpload.user_id == user.id,
                )
            )
        ).scalars().all()
        if len(owned_ids) != len(scope_ids):
            raise HTTPException(status_code=404, detail="One or more selected reports were not found")
    else:
        scope_ids = list(user_upload_ids)

    if body.finding_ids:
        findings = await _selected_findings(db, user.id, scope_ids, body.finding_ids)
    else:
        findings = await retrieve(body.question, db, report_ids=[str(i) for i in scope_ids])

    if not findings:
        chat_session.history = _serialize_history(
            list(chat_session.history)
            + [
                {"role": "user", "text": body.question, "ts": datetime.now(timezone.utc).isoformat()},
                {"role": "assistant", "text": "No relevant findings were retrieved for this query.", "ts": datetime.now(timezone.utc).isoformat()},
            ]
        )
        await db.commit()
        return QueryResponse(
            answer="No relevant findings were retrieved for this query.",
            sources=[],
            intent=intent.value,
            session_id=chat_session.id,
        )

    try:
        if intent == Intent.SECURITY:
            answer = await security_analyse(body.question, findings)
        else:
            answer = await general_query(body.question, findings)
    except Exception as exc:
        logger.error("LLM call failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM error: {exc}") from exc

    sources = [str(f.get("id", "")) for f in findings if f.get("id")]

    chat_session.history = _serialize_history(
        list(chat_session.history)
        + [
            {"role": "user", "text": body.question, "ts": datetime.now(timezone.utc).isoformat()},
            {"role": "assistant", "text": answer, "ts": datetime.now(timezone.utc).isoformat()},
        ]
    )

    db.add(AuditLog(user_id=user.id, action="query", entity=intent.value))
    await db.commit()

    return QueryResponse(answer=answer, sources=sources, intent=intent.value, session_id=chat_session.id)


@router.get("/sessions/{session_id}", response_model=SessionHistoryResponse)
async def get_session_history(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    session = await db.get(ChatSession, session_id)
    if not session or session.user_id != user.id:
        raise HTTPException(status_code=404, detail="Chat session not found")
    history = session.history if isinstance(session.history, list) else []
    return SessionHistoryResponse(session_id=session.id, history=history)


@router.get("/sessions/{session_id}/download")
async def download_session_pdf(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    session = await db.get(ChatSession, session_id)
    if not session or session.user_id != user.id:
        raise HTTPException(status_code=404, detail="Chat session not found")
    history = session.history if isinstance(session.history, list) else []
    path = _render_session_pdf(session.id, history)
    return FileResponse(path, media_type="application/pdf", filename=f"ragscan_chat_{session_id}.pdf")


async def _selected_findings(
    db: AsyncSession,
    user_id: UUID,
    report_ids: list[UUID],
    finding_ids: list[UUID],
) -> list[dict]:
    stmt = (
        select(Finding, ScanUpload)
        .join(ScanUpload, Finding.upload_id == ScanUpload.id)
        .where(Finding.id.in_(finding_ids), ScanUpload.user_id == user_id)
    )
    if report_ids:
        stmt = stmt.where(Finding.upload_id.in_(report_ids))

    rows = (await db.execute(stmt)).all()
    result: list[dict] = []
    for finding, _ in rows:
        result.append(
            {
                "id": str(finding.id),
                "cve_id": finding.cve_id,
                "title": finding.title,
                "description": finding.description,
                "solution": finding.solution,
                "severity_label": finding.severity_label,
                "cvss3_score": finding.cvss3_score,
                "epss_score": finding.epss_score,
                "epss_percentile": finding.epss_percentile,
                "cisa_kev": finding.cisa_kev,
                "risk_score": finding.risk_score,
                "hostname": finding.hostname,
                "host_ip": finding.host_ip,
                "port": finding.port,
            }
        )
    return result
