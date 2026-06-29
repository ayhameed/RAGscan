from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_utils import create_token, hash_password, verify_password
from app.db.session import get_db
from app.models.models import User, AuditLog
from app.schemas.schemas import UserRegister, UserLogin, TokenResponse

router = APIRouter(tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: UserRegister, db: AsyncSession = Depends(get_db)):
    existing = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(email=body.email, role=body.role, pw_hash=hash_password(body.password))
    db.add(user)
    db.add(AuditLog(user_id=user.id, action="register", entity="user"))
    await db.commit()
    return TokenResponse(access_token=create_token(user.id))


@router.post("/login", response_model=TokenResponse)
async def login(body: UserLogin, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if not user or not verify_password(body.password, user.pw_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    db.add(AuditLog(user_id=user.id, action="login", entity="user"))
    await db.commit()
    return TokenResponse(access_token=create_token(user.id))
