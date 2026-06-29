import uuid
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_utils import require_auth
from app.core.nist.mapper import get_controls
from app.core.nist.mapper import compute_and_store_gaps
from app.core.reports.builder import build_report
from app.db.session import get_db
from app.models.models import AuditLog, Finding, Report, ScanUpload, User
from app.schemas.schemas import ReportOut, ReportRequest

router = APIRouter(tags=["report"])

_VALID_FRAMEWORKS = {"nist_csf", "iso27001", "executive"}


def _framework_filtered_findings(findings: list[Finding], framework: str) -> list[Finding]:
    if framework == "executive":
        return findings
    return [
        finding
        for finding in findings
        if get_controls(finding.cwe_id, finding.severity_label, framework)  # type: ignore[arg-type]
    ]


@router.post("", response_model=ReportOut, status_code=201)
async def generate_report(
    body: ReportRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    if body.framework not in _VALID_FRAMEWORKS:
        raise HTTPException(status_code=422, detail=f"framework must be one of {_VALID_FRAMEWORKS}")

    scope_ids: list[uuid.UUID] = []
    if body.report_id:
        scope_ids.append(body.report_id)
    if body.report_ids:
        scope_ids.extend(body.report_ids)
    scope_ids = list(dict.fromkeys(scope_ids))

    user_upload_ids = (
        await db.execute(select(ScanUpload.id).where(ScanUpload.user_id == user.id))
    ).scalars().all()

    stmt = select(Finding)
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
        stmt = stmt.where(Finding.upload_id.in_(scope_ids))
    elif user_upload_ids:
        stmt = stmt.where(Finding.upload_id.in_(list(user_upload_ids)))
    else:
        raise HTTPException(status_code=404, detail="No findings ingested yet")

    findings = (await db.execute(stmt)).scalars().all()
    if not findings:
        raise HTTPException(status_code=404, detail="No findings ingested yet")

    scoped_framework_findings = _framework_filtered_findings(list(findings), body.framework)
    if not scoped_framework_findings:
        raise HTTPException(
            status_code=404,
            detail=f"No framework-mapped findings for framework={body.framework} in selected scope",
        )

    framework = body.framework if body.framework != "executive" else "nist_csf"
    gaps = await compute_and_store_gaps(scoped_framework_findings, framework, db)

    path = await build_report(scoped_framework_findings, gaps, framework, db)

    report = Report(report_type=body.framework, path=path)
    db.add(report)
    db.add(AuditLog(user_id=user.id, action="generate_report", entity=body.framework))
    await db.commit()
    await db.refresh(report)

    return ReportOut.model_validate(report)


@router.get("/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
):
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report.path, media_type="application/pdf", filename=f"ragscan_{report_id}.pdf")


@router.get("", response_model=list[ReportOut])
async def list_reports(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
):
    rows = (await db.execute(select(Report).order_by(Report.created_at.desc()))).scalars().all()
    return [ReportOut.model_validate(r) for r in rows]
