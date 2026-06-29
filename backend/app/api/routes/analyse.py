import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_utils import require_auth
from app.core.agents.security_agent import analyse
from app.core.rag.embedder import finding_to_text
from app.db.session import get_db
from app.models.models import Finding, User
from app.schemas.schemas import FindingOut

router = APIRouter(tags=["analyse"])


@router.get("/{finding_id}", response_model=dict)
async def analyse_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
):
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    question = f"Explain this vulnerability and provide remediation steps."
    findings_ctx = [{
        "id": str(finding.id),
        "cve_id": finding.cve_id,
        "title": finding.title,
        "description": finding.description,
        "solution": finding.solution,
        "severity_label": finding.severity_label,
        "cvss3_score": finding.cvss3_score,
        "epss_score": finding.epss_score,
        "cisa_kev": finding.cisa_kev,
        "risk_score": finding.risk_score,
        "hostname": finding.hostname,
        "host_ip": finding.host_ip,
    }]
    narrative = await analyse(question, findings_ctx)

    return {
        "finding": FindingOut.model_validate(finding),
        "analysis": narrative,
    }
