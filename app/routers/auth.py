"""Authentication Router - User Registration and Login"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext

from app.database import get_db
from app.models import User
from app.schemas.user import UserCreate, UserResponse, UserLogin

logger = logging.getLogger(__name__)

router = APIRouter()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token
security = HTTPBearer()


def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)


async def get_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
    """Get user by username"""
    query = select(User).where(User.username == username)
    result = await db.execute(query)
    return result.scalar_one_or_none()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user
    
    - **username**: Unique username (3-100 characters)
    - **password**: Password (minimum 6 characters)
    """
    
    logger.info(f"Attempting to register user: {user_data.username}")
    
    try:
        # Check if username already exists
        existing_user = await get_user_by_username(db, user_data.username)
        if existing_user:
            logger.warning(f"Registration failed: Username '{user_data.username}' already exists")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        
        # Create new user
        hashed_pw = hash_password(user_data.password)
        new_user = User(
            username=user_data.username,
            password_hash=hashed_pw,
            created_at=datetime.utcnow()
        )
        
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        logger.info(f"[OK] User registered successfully: {new_user.username} (ID: {new_user.id})")
        
        return UserResponse(
            id=new_user.id,
            username=new_user.username,
            created_at=new_user.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during registration: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user"
        )


@router.post("/login")
async def login_user(
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Login user
    
    - **username**: Username
    - **password**: Password
    
    Returns access token (simplified - in production use JWT)
    """
    
    logger.info(f"Login attempt for user: {credentials.username}")
    
    try:
        # Get user
        user = await get_user_by_username(db, credentials.username)
        
        if not user:
            logger.warning(f"Login failed: User '{credentials.username}' not found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Verify password
        if not verify_password(credentials.password, user.password_hash):
            logger.warning(f"Login failed: Invalid password for user '{credentials.username}'")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        logger.info(f"[OK] User logged in successfully: {user.username}")
        
        # TODO: Generate proper JWT token in production
        # For now, return simplified response
        return {
            "message": "Login successful",
            "access_token": f"token_{user.id}_{user.username}",
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "created_at": user.created_at.isoformat()
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to login"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user information (requires authentication)
    
    NOTE: This is a simplified implementation
    In production, use proper JWT token validation
    """
    
    try:
        # Simplified token parsing (token format: token_{user_id}_{username})
        token = credentials.credentials
        
        if not token.startswith("token_"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format"
            )
        
        # Extract user_id from token
        parts = token.split("_")
        if len(parts) < 3:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format"
            )
        
        user_id = int(parts[1])
        
        # Get user from database
        query = select(User).where(User.id == user_id)
        result = await db.execute(query)
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return UserResponse(
            id=user.id,
            username=user.username,
            created_at=user.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting current user: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )


@router.post("/logout")
async def logout_user():
    """
    Logout user
    
    NOTE: In production with JWT, implement token blacklisting
    For now, just return success message
    """
    return {
        "message": "Logout successful",
        "detail": "Please remove the token from client storage"
    }
