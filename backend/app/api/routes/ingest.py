import logging
import httpx
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
import uuid

from app.api.auth_utils import require_auth
from app.config import settings
from app.core.enrichment.enricher import enrich_finding
from app.core.ingestion.nessus_parser import parse_nessus
from app.core.ingestion.openscap_parser import parse_openscap
from app.core.rag.embedder import embed_batch
from app.core.scoring.risk_scorer import score_finding
from app.db.session import get_db
from app.models.models import AuditLog, Finding, ScanUpload, User
from app.schemas.schemas import DemoIngestItem, DemoIngestResponse, IngestResponse, ScanUploadOut

log = logging.getLogger(__name__)

router = APIRouter(tags=["ingest"])

_MAX_SIZE = 50 * 1024 * 1024  # 50 MB


def _detect_format(filename: str, content: bytes) -> str:
    fname = filename.lower()
    if fname.endswith(".nessus"):
        return "nessus"
    if fname.endswith(".xml") or fname.endswith(".xccdf"):
        if b"xccdf" in content[:2000].lower() or b"oval" in content[:2000].lower():
            return "openscap"
        if b"reporthost" in content[:2000].lower() or b"nessusclientdata" in content[:2000].lower():
            return "nessus"
    raise ValueError(f"Unrecognised file format: {filename}")


async def _ingest_contents(
    filename: str,
    contents: bytes,
    db: AsyncSession,
    user: User,
) -> IngestResponse:
    if len(contents) > _MAX_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 50 MB)")

    try:
        fmt = _detect_format(filename, contents)
    except ValueError as exc:
        raise HTTPException(status_code=415, detail=str(exc))

    if fmt == "nessus":
        raw_findings = parse_nessus(contents)
    else:
        raw_findings = parse_openscap(contents)

    upload = ScanUpload(
        user_id=user.id,
        filename=filename or "unknown",
        source=fmt,
    )
    db.add(upload)
    await db.flush()

    if not raw_findings:
        await db.commit()
        await db.refresh(upload)
        return IngestResponse(
            upload_id=upload.id,
            filename=upload.filename,
            source=upload.source,
            uploaded_at=upload.uploaded_at,
            ingested=0,
            enriched=0,
            skipped=0,
        )

    db_findings: list[Finding] = []
    for fc in raw_findings:
        f = Finding(**fc.model_dump(), upload_id=upload.id)
        db.add(f)
        db_findings.append(f)
    await db.flush()

    enriched = 0
    skipped = 0
    async with httpx.AsyncClient() as client:
        for f in db_findings:
            if f.cve_id:
                await enrich_finding(f, client, db)
                enriched += 1
            else:
                skipped += 1
            score_finding(f)

    if settings.openai_api_key:
        await embed_batch(db_findings, db)
    else:
        log.warning("OPENAI_API_KEY not set — skipping embedding. Set the key to enable RAG queries.")
    db.add(AuditLog(user_id=user.id, action="ingest", entity=fmt))
    await db.commit()
    await db.refresh(upload)

    return IngestResponse(
        upload_id=upload.id,
        filename=upload.filename,
        source=upload.source,
        uploaded_at=upload.uploaded_at,
        ingested=len(db_findings),
        enriched=enriched,
        skipped=skipped,
    )


@router.post("", response_model=IngestResponse)
async def ingest_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    contents = await file.read()
    return await _ingest_contents(file.filename or "unknown", contents, db, user)


@router.post("/demo", response_model=DemoIngestResponse)
async def ingest_demo_data(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    repo_root = Path(__file__).resolve().parents[4]
    demo_files = [
        repo_root / "nessus_v_unknown.nessus",
        repo_root / "many_vuln_rhsa.xml",
    ]

    items: list[DemoIngestItem] = []
    for demo_file in demo_files:
        if not demo_file.exists():
            items.append(
                DemoIngestItem(
                    filename=demo_file.name,
                    status="missing",
                    detail="Demo file not found in runtime image",
                )
            )
            continue

        try:
            result = await _ingest_contents(demo_file.name, demo_file.read_bytes(), db, user)
            items.append(
                DemoIngestItem(
                    filename=result.filename,
                    source=result.source,
                    status="ingested",
                    upload_id=result.upload_id,
                    uploaded_at=result.uploaded_at,
                    ingested=result.ingested,
                    enriched=result.enriched,
                    skipped=result.skipped,
                )
            )
        except HTTPException as exc:
            items.append(
                DemoIngestItem(
                    filename=demo_file.name,
                    status="failed",
                    detail=str(exc.detail),
                )
            )

    db.add(AuditLog(user_id=user.id, action="ingest_demo", entity="demo_bundle"))
    await db.commit()
    return DemoIngestResponse(items=items)


@router.get("/reports", response_model=list[ScanUploadOut])
async def list_upload_reports(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    rows = (await db.execute(
        select(
            ScanUpload.id,
            ScanUpload.user_id,
            ScanUpload.filename,
            ScanUpload.source,
            ScanUpload.uploaded_at,
            func.count(Finding.id).label("finding_count"),
            User.email.label("user_email"),
        )
        .join(User, User.id == ScanUpload.user_id)
        .outerjoin(Finding, Finding.upload_id == ScanUpload.id)
        .where(ScanUpload.user_id == user.id)
        .group_by(
            ScanUpload.id,
            ScanUpload.user_id,
            ScanUpload.filename,
            ScanUpload.source,
            ScanUpload.uploaded_at,
            User.email,
        )
        .order_by(ScanUpload.uploaded_at.desc())
    )).mappings().all()
    out: list[ScanUploadOut] = []
    for upload in rows:
        out.append(
            ScanUploadOut(
                id=upload.id,
                user_id=upload.user_id,
                filename=upload.filename,
                source=upload.source,
                uploaded_at=upload.uploaded_at,
                finding_count=upload.finding_count,
                user_email=upload.user_email,
            )
        )
    return out


@router.delete("/reports/{report_id}", status_code=204)
async def delete_upload_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    upload = await db.get(ScanUpload, report_id)
    if not upload or upload.user_id != user.id:
        raise HTTPException(status_code=404, detail="Report not found")

    filename = upload.filename
    await db.execute(delete(Finding).where(Finding.upload_id == report_id))
    await db.delete(upload)
    db.add(AuditLog(user_id=user.id, action="delete_report", entity=filename))
    await db.commit()


@router.delete("/reports", status_code=204)
async def purge_all_upload_reports(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
):
    uploads = (
        await db.execute(select(ScanUpload.id).where(ScanUpload.user_id == user.id))
    ).scalars().all()
    if uploads:
        await db.execute(delete(Finding).where(Finding.upload_id.in_(uploads)))
        await db.execute(delete(ScanUpload).where(ScanUpload.id.in_(uploads)))

    db.add(AuditLog(user_id=user.id, action="purge_reports", entity="all_upload_reports"))
    await db.commit()
