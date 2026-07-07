import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_utils import create_token, hash_password, require_admin, require_auth, verify_password
from app.db.session import get_db
from app.models.models import User, AuditLog
from app.schemas.schemas import (
    AdminUserListOut,
    AdminUserUpdate,
    RegisterResponse,
    TokenResponse,
    UserLogin,
    UserProfileOut,
    UserRegister,
)

router = APIRouter(tags=["auth"])


ADMIN_SEED_EMAIL = "hameedyunusa@outlook.com"


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(body: UserRegister, db: AsyncSession = Depends(get_db)):
    normalized_email = body.email.lower()
    existing = (
        await db.execute(select(User).where(func.lower(User.email) == normalized_email))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    is_seed_admin = normalized_email == ADMIN_SEED_EMAIL
    user = User(
        email=normalized_email,
        role=body.role,
        pw_hash=hash_password(body.password),
        is_admin=is_seed_admin,
        is_approved=is_seed_admin,
        approved_at=datetime.now(timezone.utc) if is_seed_admin else None,
    )
    db.add(user)
    db.add(AuditLog(user_id=user.id, action="register", entity="user_pending_approval"))
    await db.commit()
    return RegisterResponse(
        status="approved" if is_seed_admin else "pending_approval",
        message="Account created. Awaiting admin approval before login."
        if not is_seed_admin
        else "Account created with admin access.",
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: UserLogin, db: AsyncSession = Depends(get_db)):
    user = (
        await db.execute(select(User).where(func.lower(User.email) == body.email.lower()))
    ).scalar_one_or_none()
    if not user or not verify_password(body.password, user.pw_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.is_blocked:
        raise HTTPException(status_code=403, detail="Account blocked")
    if not user.is_approved:
        raise HTTPException(status_code=403, detail="Account pending admin approval")
    db.add(AuditLog(user_id=user.id, action="login", entity="user"))
    await db.commit()
    return TokenResponse(access_token=create_token(user.id))


@router.get("/me", response_model=UserProfileOut)
async def me(user: User = Depends(require_auth)):
    return user


@router.get("/admin/users", response_model=AdminUserListOut)
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    users = (await db.execute(select(User).order_by(User.created_at.desc()))).scalars().all()
    return AdminUserListOut(items=users, total=len(users))


@router.patch("/admin/users/{user_id}", response_model=UserProfileOut)
async def update_user(
    user_id: str,
    body: AdminUserUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user id")

    target = await db.get(User, user_uuid)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == admin.id and body.is_blocked is True:
        raise HTTPException(status_code=400, detail="You cannot block your own account")
    if target.id == admin.id and body.is_admin is False:
        raise HTTPException(status_code=400, detail="You cannot remove your own admin access")

    if body.is_admin is not None:
        target.is_admin = body.is_admin
    if body.is_approved is not None:
        target.is_approved = body.is_approved
        target.approved_at = datetime.now(timezone.utc) if body.is_approved else None
    if body.is_blocked is not None:
        target.is_blocked = body.is_blocked
        target.blocked_at = datetime.now(timezone.utc) if body.is_blocked else None

    db.add(
        AuditLog(
            user_id=admin.id,
            action="admin_user_update",
            entity=f"user:{target.email}",
        )
    )
    await db.commit()
    await db.refresh(target)
    return target
