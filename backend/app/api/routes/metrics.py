import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_utils import require_auth
from app.db.session import get_db
from app.models.models import ResponseMetric, ScanUpload, User
from app.schemas.schemas import MetricsOverviewOut, MetricsTrendOut, MetricsTrendPointOut

router = APIRouter(tags=["metrics"])


def _scope_key(report_ids: list[uuid.UUID]) -> str:
    return "__all__" if not report_ids else "|".join(sorted(str(item) for item in report_ids))


async def _resolve_scope(
    db: AsyncSession,
    user: User,
    report_id: uuid.UUID | None,
    report_ids: list[uuid.UUID] | None,
) -> tuple[list[uuid.UUID], str]:
    scope_ids: list[uuid.UUID] = []
    if report_id:
        scope_ids.append(report_id)
    if report_ids:
        scope_ids.extend(report_ids)
    scope_ids = list(dict.fromkeys(scope_ids))
    scope_key = _scope_key(scope_ids)

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

    return scope_ids, scope_key


@router.get("/overview", response_model=MetricsOverviewOut)
async def overview(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
    report_id: uuid.UUID | None = None,
    report_ids: list[uuid.UUID] | None = None,
):
    _scope_ids, scope_key = await _resolve_scope(db, user, report_id, report_ids)

    stmt = select(ResponseMetric).where(ResponseMetric.user_id == user.id, ResponseMetric.scope_key == scope_key)
    rows = (await db.execute(stmt)).scalars().all()
    if not rows:
        return MetricsOverviewOut(
            scope_key=scope_key,
            total_queries=0,
            avg_retrieval_precision_at_10=0.0,
            avg_citation_accuracy=0.0,
            avg_hallucination_rate=0.0,
        )

    total = len(rows)
    avg_retrieval_precision_at_10 = round(sum(row.retrieval_precision_at_10 for row in rows) / total, 3)
    avg_citation_accuracy = round(sum(row.citation_accuracy for row in rows) / total, 3)
    avg_hallucination_rate = round(sum(row.hallucination_rate for row in rows) / total, 3)

    return MetricsOverviewOut(
        scope_key=scope_key,
        total_queries=total,
        avg_retrieval_precision_at_10=avg_retrieval_precision_at_10,
        avg_citation_accuracy=avg_citation_accuracy,
        avg_hallucination_rate=avg_hallucination_rate,
    )


@router.get("/trend", response_model=MetricsTrendOut)
async def trend(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
    report_id: uuid.UUID | None = None,
    report_ids: list[uuid.UUID] | None = None,
    days: int = 14,
):
    if days < 1 or days > 120:
        raise HTTPException(status_code=422, detail="days must be between 1 and 120")

    _scope_ids, scope_key = await _resolve_scope(db, user, report_id, report_ids)
    start = datetime.now(timezone.utc) - timedelta(days=days - 1)

    stmt = (
        select(ResponseMetric)
        .where(
            ResponseMetric.user_id == user.id,
            ResponseMetric.scope_key == scope_key,
            ResponseMetric.created_at >= start,
        )
        .order_by(ResponseMetric.created_at.asc())
    )
    rows = (await db.execute(stmt)).scalars().all()

    if not rows:
        return MetricsTrendOut(
            scope_key=scope_key,
            days=days,
            total_queries=0,
            avg_retrieval_precision_at_10=0.0,
            avg_citation_accuracy=0.0,
            avg_hallucination_rate=0.0,
            points=[],
        )

    by_day: dict[str, list[ResponseMetric]] = {}
    for row in rows:
        day = row.created_at.astimezone(timezone.utc).date().isoformat()
        by_day.setdefault(day, []).append(row)

    points: list[MetricsTrendPointOut] = []
    for day in sorted(by_day.keys()):
        daily = by_day[day]
        total_daily = len(daily)
        points.append(
            MetricsTrendPointOut(
                day=day,
                queries=total_daily,
                avg_retrieval_precision_at_10=round(sum(item.retrieval_precision_at_10 for item in daily) / total_daily, 3),
                avg_citation_accuracy=round(sum(item.citation_accuracy for item in daily) / total_daily, 3),
                avg_hallucination_rate=round(sum(item.hallucination_rate for item in daily) / total_daily, 3),
            )
        )

    total = len(rows)
    return MetricsTrendOut(
        scope_key=scope_key,
        days=days,
        total_queries=total,
        avg_retrieval_precision_at_10=round(sum(item.retrieval_precision_at_10 for item in rows) / total, 3),
        avg_citation_accuracy=round(sum(item.citation_accuracy for item in rows) / total, 3),
        avg_hallucination_rate=round(sum(item.hallucination_rate for item in rows) / total, 3),
        points=points,
    )
