import logging
import re
from datetime import datetime, timezone
from uuid import UUID

import httpx
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
from app.models.models import AuditLog, ChatSession, Finding, ResponseMetric, ScanUpload, User
from app.schemas.schemas import QueryRequest, QueryResponse, SessionHistoryResponse


_CITATION_RE = re.compile(r"\[Finding:\s*([0-9a-fA-F-]{8,})\s*,\s*CVE:")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "were", "have", "has",
    "had", "you", "your", "their", "they", "them", "into", "over", "under", "than", "then", "not",
    "but", "can", "may", "might", "will", "would", "should", "could", "all", "any", "its", "our",
    "out", "use", "using", "used", "via", "per", "one", "two", "three", "also", "most", "more",
    "less", "high", "low", "medium", "critical", "risk", "finding", "findings", "cve", "host", "port",
}

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


def _scope_key(scope_ids: list[UUID]) -> str:
    return "__all__" if not scope_ids else "|".join(sorted(str(item) for item in scope_ids))


def _cited_ids(answer: str) -> list[str]:
    return list(dict.fromkeys(_CITATION_RE.findall(answer)))


def _tokenize(text: str) -> set[str]:
    tokens = set(_TOKEN_RE.findall(text.lower()))
    return {token for token in tokens if token not in _STOPWORDS}


def _finding_evidence_tokens(finding: dict) -> set[str]:
    evidence_parts = [
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("solution") or ""),
        str(finding.get("severity_label") or ""),
        str(finding.get("cve_id") or ""),
    ]
    return _tokenize(" ".join(evidence_parts))


def _semantic_supported(sentence: str, evidence_tokens: list[set[str]]) -> bool:
    sentence_tokens = _tokenize(sentence)
    if not sentence_tokens:
        return True
    best_overlap = 0.0
    best_hits = 0
    for tokens in evidence_tokens:
        if not tokens:
            continue
        hits = len(sentence_tokens & tokens)
        overlap = hits / max(1, len(sentence_tokens))
        if overlap > best_overlap:
            best_overlap = overlap
            best_hits = hits
    return best_overlap >= 0.18 or best_hits >= 3


def _hallucination_rate(answer: str, findings: list[dict], source_ids: list[str], cited_ids: list[str]) -> float:
    sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+", answer) if part.strip()]
    if not sentences:
        return 0.0
    evidence_tokens = [_finding_evidence_tokens(item) for item in findings]
    source_set = set(source_ids)
    cited_set = set(cited_ids)
    has_valid_citation = bool(source_set & cited_set)

    unsupported = 0
    for sentence in sentences:
        sentence_cites = _CITATION_RE.findall(sentence)
        sentence_has_valid_citation = any(item in source_set for item in sentence_cites)
        if sentence_has_valid_citation:
            continue
        if has_valid_citation and "[Finding:" in sentence and not sentence_has_valid_citation:
            unsupported += 1
            continue
        if not _semantic_supported(sentence, evidence_tokens):
            unsupported += 1
    return unsupported / len(sentences)


def _evidence_precision_at_10(source_ids: list[str], cited_ids: list[str]) -> float:
    top10 = source_ids[:10]
    if not top10:
        return 0.0
    cited = set(cited_ids)
    return len([item for item in top10 if item in cited]) / len(top10)


def _citation_accuracy(source_ids: list[str], cited_ids: list[str]) -> float:
    if not cited_ids:
        return 0.0
    source_set = set(source_ids)
    return len([item for item in cited_ids if item in source_set]) / len(cited_ids)


async def _fetch_secondary_context(findings: list[dict]) -> str | None:
    cves: list[str] = []
    kev: set[str] = set()
    for item in findings:
        cve = str(item.get("cve_id") or "").upper().strip()
        if _CVE_RE.fullmatch(cve):
            cves.append(cve)
            if item.get("cisa_kev"):
                kev.add(cve)

    cves = list(dict.fromkeys(cves))[:3]
    if not cves:
        return None

    headers = {"User-Agent": "RAGScan/1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    lines: list[str] = []
    timeout = httpx.Timeout(4.5)
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        for cve in cves:
            cvss: str | None = None
            epss: str | None = None

            try:
                nvd = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve},
                )
                if nvd.status_code == 200:
                    payload = nvd.json()
                    vuln = (payload.get("vulnerabilities") or [{}])[0].get("cve", {})
                    metrics = vuln.get("metrics", {})
                    v31 = metrics.get("cvssMetricV31") or []
                    v30 = metrics.get("cvssMetricV30") or []
                    chosen = (v31 or v30)
                    if chosen:
                        score = chosen[0].get("cvssData", {}).get("baseScore")
                        if score is not None:
                            cvss = str(score)
            except Exception:
                pass

            try:
                first = await client.get("https://api.first.org/data/v1/epss", params={"cve": cve})
                if first.status_code == 200:
                    data = first.json().get("data") or []
                    if data:
                        score = data[0].get("epss")
                        if score is not None:
                            epss = f"{float(score):.4f}"
            except Exception:
                pass

            kev_tag = "yes" if cve in kev else "no"
            parts = [f"{cve}", f"KEV: {kev_tag}"]
            if cvss is not None:
                parts.append(f"NVD CVSS: {cvss}")
            if epss is not None:
                parts.append(f"EPSS: {epss}")
            lines.append(" - " + " | ".join(parts))

    if not lines:
        return None
    return "Internet context (NVD/EPSS):\n" + "\n".join(lines)


def _render_session_pdf(session_id: UUID, history: list[dict], metrics_rows: list[ResponseMetric]) -> str:
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
        Paragraph(f"Session: {session_id}", body),
        Spacer(1, 4 * mm),
    ]
    if metrics_rows:
        avg_p10 = sum(item.retrieval_precision_at_10 for item in metrics_rows) / len(metrics_rows)
        avg_citation = sum(item.citation_accuracy for item in metrics_rows) / len(metrics_rows)
        avg_hallucination = sum(item.hallucination_rate for item in metrics_rows) / len(metrics_rows)
        source_total = sum(item.source_count for item in metrics_rows)
        citation_total = sum(item.citation_count for item in metrics_rows)
        story.append(Paragraph("Session Metrics", body))
        story.append(Paragraph(f"Queries: {len(metrics_rows)}", body))
        story.append(Paragraph(f"Avg P@10: {avg_p10:.3f}", body))
        story.append(Paragraph(f"Avg Citation Accuracy: {avg_citation:.3f}", body))
        story.append(Paragraph(f"Avg Hallucination Rate: {avg_hallucination:.3f}", body))
        story.append(Paragraph(f"Total Sources/Citations: {source_total}/{citation_total}", body))
        story.append(Spacer(1, 4 * mm))

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
        return QueryResponse(
            answer=_NO_LLM_MSG,
            sources=[],
            intent="general",
            session_id=body.session_id,
            metrics=None,
            secondary_context=None,
        )

    chat_session = await _load_session(db, user.id, body.session_id)

    try:
        intent = await route(body.question)
    except Exception as exc:
        logger.warning("Intent routing failed: %s", exc)
        intent = Intent.GENERAL

    findings: list[dict] = []
    scope_ids: list[UUID] = []
    explicit_scope_ids: list[UUID] = []
    if body.report_id:
        scope_ids.append(body.report_id)
        explicit_scope_ids.append(body.report_id)
    if body.report_ids:
        scope_ids.extend(body.report_ids)
        explicit_scope_ids.extend(body.report_ids)
    scope_ids = list(dict.fromkeys(scope_ids))
    explicit_scope_ids = list(dict.fromkeys(explicit_scope_ids))

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

    metric_scope_key = _scope_key(explicit_scope_ids)

    if not findings:
        answer = "No relevant findings were retrieved for this query."
        sources: list[str] = []
        cited_ids: list[str] = _cited_ids(answer)
        response_metrics = {
            "retrieval_precision_at_10": 0.0,
            "citation_accuracy": 0.0,
            "hallucination_rate": _hallucination_rate(answer, [], [], cited_ids),
            "source_count": 0,
            "citation_count": len(cited_ids),
        }
        chat_session.history = _serialize_history(
            list(chat_session.history)
            + [
                {"role": "user", "text": body.question, "ts": datetime.now(timezone.utc).isoformat()},
                {"role": "assistant", "text": answer, "ts": datetime.now(timezone.utc).isoformat()},
            ]
        )
        db.add(
            ResponseMetric(
                user_id=user.id,
                session_id=chat_session.id,
                scope_key=metric_scope_key,
                question=body.question,
                retrieval_precision_at_10=response_metrics["retrieval_precision_at_10"],
                citation_accuracy=response_metrics["citation_accuracy"],
                hallucination_rate=response_metrics["hallucination_rate"],
                source_count=response_metrics["source_count"],
                citation_count=response_metrics["citation_count"],
            )
        )
        await db.commit()
        return QueryResponse(
            answer=answer,
            sources=sources,
            intent=intent.value,
            session_id=chat_session.id,
            metrics=response_metrics,
            secondary_context=None,
        )

    try:
        secondary_context = await _fetch_secondary_context(findings) if body.include_internet_context else None
        if intent == Intent.SECURITY:
            answer = await security_analyse(body.question, findings, secondary_context)
        else:
            answer = await general_query(body.question, findings, secondary_context)
    except Exception as exc:
        logger.error("LLM call failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM error: {exc}") from exc

    sources = [str(f.get("id", "")) for f in findings if f.get("id")]
    cited_ids = _cited_ids(answer)
    response_metrics = {
        "retrieval_precision_at_10": _evidence_precision_at_10(sources, cited_ids),
        "citation_accuracy": _citation_accuracy(sources, cited_ids),
        "hallucination_rate": _hallucination_rate(answer, findings, sources, cited_ids),
        "source_count": len(sources),
        "citation_count": len(cited_ids),
    }

    chat_session.history = _serialize_history(
        list(chat_session.history)
        + [
            {"role": "user", "text": body.question, "ts": datetime.now(timezone.utc).isoformat()},
            {"role": "assistant", "text": answer, "ts": datetime.now(timezone.utc).isoformat()},
        ]
    )

    db.add(
        ResponseMetric(
            user_id=user.id,
            session_id=chat_session.id,
            scope_key=metric_scope_key,
            question=body.question,
            retrieval_precision_at_10=response_metrics["retrieval_precision_at_10"],
            citation_accuracy=response_metrics["citation_accuracy"],
            hallucination_rate=response_metrics["hallucination_rate"],
            source_count=response_metrics["source_count"],
            citation_count=response_metrics["citation_count"],
        )
    )
    db.add(AuditLog(user_id=user.id, action="query", entity=intent.value))
    await db.commit()

    return QueryResponse(
        answer=answer,
        sources=sources,
        intent=intent.value,
        session_id=chat_session.id,
        metrics=response_metrics,
        secondary_context=secondary_context,
    )


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
    metrics_rows = (
        await db.execute(
            select(ResponseMetric)
            .where(ResponseMetric.session_id == session.id, ResponseMetric.user_id == user.id)
            .order_by(ResponseMetric.created_at.asc())
        )
    ).scalars().all()
    path = _render_session_pdf(session.id, history, metrics_rows)
    return FileResponse(path, media_type="application/pdf", filename=f"ragscan_chat_{session_id}.pdf")


@router.delete("/sessions/{session_id}", status_code=204)
async def delete_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    session = await db.get(ChatSession, session_id)
    if not session or session.user_id != user.id:
        raise HTTPException(status_code=404, detail="Chat session not found")
    await db.delete(session)
    db.add(AuditLog(user_id=user.id, action="delete_session", entity=str(session_id)))
    await db.commit()


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
                "cwe_id": finding.cwe_id,
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
