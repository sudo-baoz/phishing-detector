"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

Authentication Router - JWT, POST /auth/token, default admin on startup.
"""

import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext

from app.config import settings
from app.database import get_db, AsyncSessionLocal
from app.models import User
from app.schemas.user import UserCreate, UserResponse, UserLogin

logger = logging.getLogger(__name__)

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    query = select(User).where(User.email == email)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def get_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
    query = select(User).where(User.username == username)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: int) -> Optional[User]:
    query = select(User).where(User.id == user_id)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def create_default_admin():
    """Create default admin on startup: admin@cybersentinel.com / password123"""
    async with AsyncSessionLocal() as db:
        try:
            existing = await get_user_by_email(db, "admin@cybersentinel.com")
            if existing:
                logger.info("[Auth] Default admin already exists")
                return
            hashed = hash_password("password123")
            admin = User(
                email="admin@cybersentinel.com",
                username="admin",
                password_hash=hashed,
                role="admin",
                api_key="sk-live-" + secrets.token_hex(16),
            )
            db.add(admin)
            await db.commit()
            logger.info("[Auth] Default admin created: admin@cybersentinel.com")
        except Exception as e:
            logger.warning(f"[Auth] Could not create default admin: {e}")
            await db.rollback()


@router.post("/token")
async def login_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """
    OAuth2 compatible token login.
    CRITICAL: This route expects form-urlencoded body with keys "username" and "password".
    The frontend must send Content-Type: application/x-www-form-urlencoded and body like:
    username=admin@cybersentinel.com&password=password123
    (Use "username" even when the user types an email.)
    """
    try:
        # OAuth2PasswordRequestForm provides .username and .password (form fields)
        email_or_username = form_data.username
        user = await get_user_by_email(db, email_or_username)
        if not user:
            user = await get_user_by_username(db, email_or_username)
        if not user or not verify_password(form_data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        role = getattr(user, "role", "user")
        access_token = create_access_token({"sub": str(user.id), "email": user.email or "", "role": role})
        created_at = user.created_at
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": getattr(user, "email", None),
                "username": getattr(user, "username", None),
                "role": role,
                "created_at": created_at.isoformat() if created_at else None,
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Login token error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e) if settings.DEBUG else "Internal server error during login",
        )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register with email (use username field as email for compatibility)."""
    email = getattr(user_data, "email", None) or user_data.username
    if await get_user_by_email(db, email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    if await get_user_by_username(db, user_data.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    hashed = hash_password(user_data.password)
    new_user = User(
        email=email,
        username=user_data.username,
        password_hash=hashed,
        role="user",
        api_key="sk-live-" + secrets.token_hex(16),
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return UserResponse(
        id=new_user.id,
        username=new_user.username or new_user.email,
        created_at=new_user.created_at,
    )


@router.post("/login")
async def login_user(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    """Login (JSON body). Returns JWT. Prefer POST /auth/token for OAuth2."""
    user = await get_user_by_email(db, credentials.username) or await get_user_by_username(db, credentials.username)
    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    access_token = create_access_token({"sub": str(user.id), "email": user.email or "", "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "role": user.role,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
    }


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Dependency: current user from JWT Bearer token."""
    token = credentials.credentials
    payload = verify_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    user_id = int(payload["sub"])
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Dependency: current user if token present, else None."""
    if not credentials:
        return None
    payload = verify_token(credentials.credentials)
    if not payload or "sub" not in payload:
        return None
    user = await get_user_by_id(db, int(payload["sub"]))
    return user


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    return UserResponse(
        id=user.id,
        username=user.username or user.email or "",
        email=user.email,
        role=user.role,
        created_at=user.created_at,
    )


@router.post("/logout")
async def logout_user():
    return {"message": "Logout successful"}
