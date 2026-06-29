import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select, false
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.api.auth_utils import require_auth
from app.db.session import get_db
from app.models.models import Finding, ScanUpload, User
from app.schemas.schemas import FindingOut, ScoreSummary

router = APIRouter(tags=["score"])


@router.get("", response_model=ScoreSummary)
async def get_scores(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
    limit: int = 200,
    report_id: uuid.UUID | None = None,
    report_ids: list[uuid.UUID] | None = None,
):
    scope_ids: list[uuid.UUID] = []
    if report_id:
        scope_ids.append(report_id)
    if report_ids:
        scope_ids.extend(report_ids)
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

    stmt = select(Finding)
    if scope_ids:
        stmt = stmt.where(Finding.upload_id.in_(scope_ids))
    else:
        stmt = stmt.where(false())  # no uploads for this user yet

    rows = (
        await db.execute(
            stmt
            .order_by(Finding.risk_score.desc().nullslast())
            .limit(limit)
        )
    ).scalars().all()

    counts = {sev: sum(1 for f in rows if f.severity_label == sev)
              for sev in ("critical", "high", "medium", "low", "info")}
    kev_count = sum(1 for f in rows if f.cisa_kev)
    avg = round(sum(f.risk_score or 0 for f in rows) / max(len(rows), 1), 1)

    return ScoreSummary(
        total=len(rows),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        kev_count=kev_count,
        avg_risk_score=avg,
        findings=[FindingOut.model_validate(f) for f in rows],
    )
