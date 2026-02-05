"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

"""
API Endpoints - Consolidated Router
Combines all API routes: Health, Scanning, Authentication
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, text

from app.database import get_db
from app.models import ScanHistory, User
from app.schemas.scan import ScanRequest, ScanResponse, ScanHistoryResponse, OSINTData
from app.schemas.user import UserCreate, UserResponse, UserLogin
from app.schemas.chat import ChatRequest, ChatResponse
from app.services.ai_engine import phishing_predictor
from app.services.osint import collect_osint_data, get_osint_summary
from app.services.chatbot import get_chatbot_response, is_chatbot_available
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

# Create main API router
router = APIRouter()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ==================== Health Check Endpoints ====================

@router.get("/health", tags=["Health"])
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "message": "Phishing URL Detection API is running"
    }


@router.get("/health/db", tags=["Health"])
async def health_check_db(db: AsyncSession = Depends(get_db)):
    """Health check with database connection test"""
    try:
        # Test database connection
        result = await db.execute(text("SELECT 1"))
        result.scalar()
        
        return {
            "status": "healthy",
            "message": "API and database are running",
            "database": "connected"
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "message": "Database connection failed",
            "database": "disconnected",
            "error": str(e)
        }


@router.get("/health/model", tags=["Health"])
async def health_check_model():
    """Health check for ML model"""
    model_info = phishing_predictor.get_model_info()
    
    if model_info["loaded"]:
        return {
            "status": "healthy",
            "message": "ML model is loaded and ready",
            "model": model_info
        }
    else:
        return {
            "status": "unhealthy",
            "message": "ML model is not loaded",
            "model": model_info
        }


# ==================== URL Scanning Endpoints ====================

@router.post("/scan", response_model=ScanResponse, tags=["Scanning"])
async def scan_url(
    scan_request: ScanRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Scan a URL for phishing detection with optional OSINT enrichment
    
    - **url**: URL to scan (must be valid HTTP/HTTPS URL)
    - **include_osint**: Include OSINT data (WHOIS, DNS, Geolocation) - default: true
    
    Returns prediction with confidence score, threat type, and OSINT data
    """
    
    logger.info(f"Scanning URL: {scan_request.url} (OSINT: {scan_request.include_osint})")
    
    try:
        # Check if model is loaded
        if not phishing_predictor.is_loaded():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML model is not loaded. Please try again later."
            )
        
        # Make prediction using AI engine
        prediction_result = phishing_predictor.predict(str(scan_request.url))
        
        is_phishing = prediction_result["is_phishing"]
        confidence_score = round(prediction_result["confidence_score"] * 100, 2)
        threat_type = prediction_result["threat_type"]
        
        logger.info(f"Prediction: {'PHISHING' if is_phishing else 'SAFE'} (Confidence: {confidence_score:.2f}%)")
        
        # Collect OSINT data if requested
        osint_data = None
        if scan_request.include_osint:
            try:
                logger.info("Collecting OSINT data...")
                osint_full = collect_osint_data(str(scan_request.url))
                osint_summary = get_osint_summary(osint_full)
                osint_data = OSINTData(**osint_summary)
                logger.info(f"[OK] OSINT data collected: {osint_summary.get('server_location')}")
            except Exception as e:
                logger.warning(f"Failed to collect OSINT data: {e}")
                # Continue without OSINT data
        
        # Save to database
        scan_record = ScanHistory(
            url=str(scan_request.url),
            is_phishing=is_phishing,
            confidence_score=confidence_score,
            threat_type=threat_type,
            scanned_at=datetime.utcnow(),
            user_id=None  # TODO: Add user_id when authentication is implemented
        )
        
        db.add(scan_record)
        await db.commit()
        await db.refresh(scan_record)
        
        logger.info(f"Scan result saved to database (ID: {scan_record.id})")
        
        return ScanResponse(
            id=scan_record.id,
            url=scan_record.url,
            is_phishing=scan_record.is_phishing,
            confidence_score=scan_record.confidence_score,
            threat_type=scan_record.threat_type,
            scanned_at=scan_record.scanned_at,
            user_id=scan_record.user_id,
            osint=osint_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning URL: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to scan URL: {str(e)}"
        )


@router.get("/scan/history", response_model=ScanHistoryResponse, tags=["Scanning"])
async def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan history
    
    - **limit**: Maximum number of results (default: 50, max: 100)
    - **offset**: Number of results to skip (default: 0)
    """
    
    # Validate parameters
    if limit > 100:
        limit = 100
    if offset < 0:
        offset = 0
    
    try:
        # Get total count
        count_query = select(ScanHistory)
        result = await db.execute(count_query)
        total = len(result.scalars().all())
        
        # Get paginated results
        query = select(ScanHistory).order_by(desc(ScanHistory.scanned_at)).limit(limit).offset(offset)
        result = await db.execute(query)
        scans = result.scalars().all()
        
        logger.info(f"Retrieved {len(scans)} scan records (offset: {offset}, limit: {limit})")
        
        return ScanHistoryResponse(
            total=total,
            scans=[
                ScanResponse(
                    id=scan.id,
                    url=scan.url,
                    is_phishing=scan.is_phishing,
                    confidence_score=scan.confidence_score,
                    threat_type=scan.threat_type,
                    scanned_at=scan.scanned_at,
                    user_id=scan.user_id
                )
                for scan in scans
            ]
        )
        
    except Exception as e:
        logger.error(f"Error retrieving scan history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan history"
        )


@router.get("/scan/{scan_id}", response_model=ScanResponse, tags=["Scanning"])
async def get_scan_by_id(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get specific scan result by ID"""
    
    try:
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        return ScanResponse(
            id=scan.id,
            url=scan.url,
            is_phishing=scan.is_phishing,
            confidence_score=scan.confidence_score,
            threat_type=scan.threat_type,
            scanned_at=scan.scanned_at,
            user_id=scan.user_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan"
        )


@router.delete("/scan/{scan_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Scanning"])
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete a scan record"""
    
    try:
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        await db.delete(scan)
        await db.commit()
        
        logger.info(f"Deleted scan record {scan_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete scan"
        )


# ==================== Authentication Endpoints ====================

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


@router.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
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


@router.post("/auth/login", tags=["Authentication"])
async def login_user(
    user_data: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Login user
    
    - **username**: Username
    - **password**: Password
    
    Returns user info and authentication token (placeholder)
    """
    
    logger.info(f"Login attempt for user: {user_data.username}")
    
    try:
        # Get user from database
        user = await get_user_by_username(db, user_data.username)
        
        if not user:
            logger.warning(f"Login failed: User '{user_data.username}' not found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Verify password
        if not verify_password(user_data.password, user.password_hash):
            logger.warning(f"Login failed: Invalid password for user '{user_data.username}'")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        logger.info(f"[OK] User logged in successfully: {user.username}")
        
        # TODO: Generate JWT token
        # For now, return user info with placeholder token
        return {
            "message": "Login successful",
            "user": UserResponse(
                id=user.id,
                username=user.username,
                created_at=user.created_at
            ),
            "token": "placeholder_token"  # TODO: Implement JWT
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to login"
        )


# ==================== Chat Endpoint ====================

@router.post("/chat", response_model=ChatResponse, tags=["Chat"])
async def chat_with_ai(chat_request: ChatRequest):
    """
    Chat with AI assistant about phishing scan results
    
    Send a message to the AI chatbot to get explanations about scan results.
    Optionally include scan context for more specific answers.
    
    **Example without scan context:**
    ```json
    {
        "message": "What is phishing?"
    }
    ```
    
    **Example with scan context:**
    ```json
    {
        "message": "Why is this link dangerous?",
        "scan_context": {
            "url": "https://suspicious-site.com",
            "is_phishing": true,
            "confidence_score": 95.5,
            "threat_type": "Credential Harvesting",
            "osint": {
                "domain_age_days": 5,
                "server_location": "Unknown",
                "has_mail_server": false
            }
        }
    }
    ```
    
    **Returns:**
    - AI-generated response explaining the scan results
    - Security recommendations
    - Risk assessment
    """
    try:
        logger.info(f"Chat request received: {chat_request.message[:100]}")
        
        # Check if chatbot is available
        if not is_chatbot_available():
            logger.warning("Chatbot service not available - GEMINI_API_KEY not configured")
            return ChatResponse(
                success=False,
                message=chat_request.message,
                response=None,
                error="Chatbot service is not available. Please configure GEMINI_API_KEY environment variable."
            )
        
        # Get AI response
        result = get_chatbot_response(
            message=chat_request.message,
            scan_context=chat_request.scan_context
        )
        
        # Return formatted response
        return ChatResponse(
            success=result['success'],
            message=chat_request.message,
            response=result.get('response'),
            error=result.get('error')
        )
        
    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}", exc_info=True)
        return ChatResponse(
            success=False,
            message=chat_request.message,
            response=None,
            error=f"Internal server error: {str(e)}"
        )
