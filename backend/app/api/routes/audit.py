from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_utils import require_auth
from app.db.session import get_db
from app.models.models import AuditLog, User
from app.schemas.schemas import AuditLogOut, AuditLogPageOut

router = APIRouter(tags=["audit"])


@router.get("", response_model=AuditLogPageOut)
async def list_audit_logs(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
    page: int = 1,
    page_size: int = 25,
):
    page = max(1, page)
    page_size = min(max(5, page_size), 100)
    offset = (page - 1) * page_size

    total = (await db.execute(select(func.count(AuditLog.id)))).scalar_one()

    rows = (
        await db.execute(
            select(
                AuditLog.id,
                AuditLog.user_id,
                User.email.label("user_email"),
                AuditLog.action,
                AuditLog.entity,
                AuditLog.ts,
            )
            .outerjoin(User, User.id == AuditLog.user_id)
            .order_by(AuditLog.ts.desc())
            .offset(offset)
            .limit(page_size)
        )
    ).mappings().all()

    return AuditLogPageOut(
        items=[
            AuditLogOut(
                id=r.id,
                user_id=r.user_id,
                user_email=r.user_email,
                action=r.action,
                entity=r.entity,
                ts=r.ts,
            )
            for r in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
    )
