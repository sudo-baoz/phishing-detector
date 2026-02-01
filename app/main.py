"""
Complete FastAPI Main Application
Phishing URL Detection System for Linux VPS (aaPanel)
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
import joblib

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import init_db, close_db
from app.routers import health, scan, auth

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Global ML model storage
ml_model = None
ml_scaler = None
ml_feature_names = None


def load_ml_model():
    """Load trained ML model from file"""
    global ml_model, ml_scaler, ml_feature_names
    
    model_path = Path("models/phishing_model.pkl")
    
    try:
        if not model_path.exists():
            logger.error(f"Model file not found at {model_path}")
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        logger.info(f"Loading ML model from {model_path}")
        model_package = joblib.load(model_path)
        
        ml_model = model_package['model']
        ml_scaler = model_package['scaler']
        ml_feature_names = model_package['feature_names']
        
        logger.info("[OK] ML Model loaded successfully")
        logger.info(f"  - Model type: {type(ml_model).__name__}")
        logger.info(f"  - Features: {len(ml_feature_names)}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        raise


def get_ml_model():
    """Get loaded ML model"""
    if ml_model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML model not loaded"
        )
    return ml_model


def get_ml_scaler():
    """Get loaded ML scaler"""
    if ml_scaler is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML scaler not loaded"
        )
    return ml_scaler


def get_ml_feature_names():
    """Get ML feature names"""
    if ml_feature_names is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML feature names not loaded"
        )
    return ml_feature_names


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    
    # ========== STARTUP ==========
    logger.info("=" * 70)
    logger.info("STARTING PHISHING URL DETECTION API")
    logger.info("=" * 70)
    
    # Load ML Model
    logger.info("Loading ML Model...")
    try:
        load_ml_model()
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
    
    logger.info(f"Port: {settings.PORT}")
    logger.info(f"CORS Origins: {settings.cors_origins_list}")
    logger.info("=" * 70)
    logger.info("[SUCCESS] API STARTED SUCCESSFULLY")
    logger.info(f"API: http://0.0.0.0:{settings.PORT}")
    logger.info(f"Docs: http://0.0.0.0:{settings.PORT}/docs")
    logger.info("=" * 70)
    
    yield
    
    # ========== SHUTDOWN ==========
    logger.info("Shutting down API...")
    await close_db()
    logger.info("[OK] Shutdown complete")


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="API for detecting phishing URLs using Machine Learning",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info(f"CORS enabled for: {settings.cors_origins_list}")


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error": str(exc) if settings.DEBUG else "An unexpected error occurred"
        }
    )


# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(scan.router, prefix="/scan", tags=["URL Scanning"])
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint"""
    return {
        "message": "Phishing URL Detection API",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs",
        "endpoints": {
            "scan_url": "POST /scan",
            "scan_history": "GET /scan/history",
            "login": "POST /auth/login",
            "register": "POST /auth/register"
        }
    }


# Model info endpoint
@app.get("/model/info", tags=["Model"])
async def model_info():
    """Get ML model information"""
    return {
        "model_type": type(ml_model).__name__ if ml_model else "Not loaded",
        "model_loaded": ml_model is not None,
        "features": ml_feature_names if ml_feature_names else [],
        "feature_count": len(ml_feature_names) if ml_feature_names else 0,
        "status": "ready" if ml_model and ml_scaler else "not_ready"
    }


# Export functions for routers
app.state.get_ml_model = get_ml_model
app.state.get_ml_scaler = get_ml_scaler
app.state.get_ml_feature_names = get_ml_feature_names


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.DEBUG
    )
