import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_utils import require_auth
from app.config import settings
from app.core.agents.security_agent import analyse as security_analyse
from app.core.agents.supervisor import Intent, route
from app.core.rag.chain import query as general_query
from app.core.rag.retriever import retrieve
from app.db.session import get_db
from app.models.models import AuditLog, Finding, ScanUpload, User
from app.schemas.schemas import QueryRequest, QueryResponse

logger = logging.getLogger("ragscan")
router = APIRouter(tags=["query"])

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
        return QueryResponse(answer=_NO_LLM_MSG, sources=[], intent="general")

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
        return QueryResponse(
            answer="No relevant findings were retrieved for this query.",
            sources=[],
            intent=intent.value,
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

    db.add(AuditLog(user_id=user.id, action="query", entity=intent.value))
    await db.commit()

    return QueryResponse(answer=answer, sources=sources, intent=intent.value)


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
