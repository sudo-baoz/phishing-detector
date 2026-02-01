"""
FastAPI Main Application - Minimal Setup
Clean Architecture: Separation of concerns
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.database import init_db, close_db
from app.services.ai_engine import phishing_predictor
from app.api.endpoints import router

# ==================== Logging Configuration ====================
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


# ==================== Application Lifespan ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events
    Handles startup and shutdown tasks
    """
    
    # ========== STARTUP ==========
    logger.info("=" * 70)
    logger.info("STARTING PHISHING URL DETECTION API")
    logger.info("=" * 70)
    
    # Load ML Model
    logger.info("Loading ML Model...")
    try:
        phishing_predictor.load_model(settings.MODEL_PATH)
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        logger.warning("[WARNING] API will start but URL scanning will not work")
    
    # Initialize Database
    logger.info("Initializing Database...")
    logger.info(f"Database Type: {settings.DB_TYPE}")
    
    if settings.DB_TYPE == "sqlite":
        logger.info(f"Database File: {settings.DB_NAME}.db")
    else:
        logger.info(f"Database: {settings.DB_HOST}:{settings.DB_PORT or 'default'}/{settings.DB_NAME}")
    
    try:
        await init_db()
        logger.info("[OK] Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        logger.warning("[WARNING] API will start but database operations will fail")
    
    logger.info(f"Host: {settings.HOST}")
    logger.info(f"Port: {settings.PORT}")
    logger.info(f"CORS Origins: {settings.cors_origins_list}")
    logger.info("=" * 70)
    logger.info("[SUCCESS] API STARTED SUCCESSFULLY")
    logger.info(f"API: {settings.server_url}")
    logger.info(f"Docs: {settings.server_url}/docs")
    logger.info("=" * 70)
    
    yield
    
    # ========== SHUTDOWN ==========
    logger.info("Shutting down API...")
    await close_db()
    logger.info("[OK] Shutdown complete")


# ==================== FastAPI Application ====================
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    lifespan=lifespan
)


# ==================== CORS Middleware ====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info(f"CORS enabled for: {settings.cors_origins_list}")


# ==================== Global Exception Handler ====================
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Handle all unhandled exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "error": str(exc) if settings.DEBUG else "An unexpected error occurred"
        }
    )


# ==================== Include API Routers ====================
app.include_router(router)


# ==================== Root Endpoint ====================
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Phishing URL Detection API",
        "version": settings.APP_VERSION,
        "documentation": "/docs",
        "health": "/health"
    }
