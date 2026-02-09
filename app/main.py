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
Complete FastAPI Main Application
Phishing URL Detection System with God Mode Integration
"""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import joblib

from fastapi import FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.core.logger import configure_logging, log_startup_banner, log_shutdown_banner, get_logger
from app.security.turnstile import verify_turnstile
from app.database import init_db, close_db
from app.routers import health, scan, auth, chat, feedback
from app.services.ai_engine import phishing_predictor
from app.services.cert_monitor import start_cert_monitor, stop_cert_monitor, get_cache_stats

# ============================================================================
# SMART LOGGING - "QUIET MODE" (Silence 3rd party noise)
# ============================================================================
# This MUST be called BEFORE any other imports that use logging
logger = configure_logging(
    debug_mode=settings.DEBUG,
    log_file="app.log",
    quiet_mode=not settings.DEBUG  # Quiet in production, verbose in dev
)

# ============================================================================
# CONCURRENCY CONTROL - Prevent server hang from too many scans
# ============================================================================
# Semaphore limits concurrent heavy scan operations
# If 3 scans are running, new requests get 503 immediately (fail-fast)
SCAN_SEMAPHORE = asyncio.Semaphore(3)
SCAN_TIMEOUT = 60.0  # Hard timeout for entire scan operation (seconds)

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



from apscheduler.schedulers.background import BackgroundScheduler
from scripts.ingest_threats import ingest_data_from_phishtank
from app.services.knowledge_base import knowledge_base

# Initialize Scheduler
scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    
    # ========== STARTUP ==========
    # Start CertStream Real-time Monitor (Zero-Day Detection)
    try:
        cert_started = start_cert_monitor()
        if not cert_started:
            logger.warning("[STARTUP] CertStream monitor failed to start")
    except Exception as cert_error:
        logger.error(f"[STARTUP] CertStream error: {cert_error}")
    
    # Initialize Scheduler (runs in background, no log spam)
    scheduler.add_job(ingest_data_from_phishtank, 'interval', hours=12, args=[1000])
    scheduler.start()
    
    # Load ML Model (auto-discovery enabled)
    try:
        model_loaded = phishing_predictor.load_model()
        if not model_loaded:
            logger.error("[STARTUP] PhishingPredictor model failed to load")
    except FileNotFoundError:
        # Model not found - trigger auto-training for VPS deployment
        logger.warning("[STARTUP] No model found, initiating auto-training...")
        try:
            train_success = phishing_predictor.auto_train()
            if not train_success:
                logger.error("[STARTUP] Auto-training failed!")
        except Exception as train_error:
            logger.error(f"[STARTUP] Auto-training error: {train_error}")
    except Exception as e:
        logger.error(f"[STARTUP] ML model error: {e}")
    
    # Initialize Database
    try:
        await init_db()
    except Exception as e:
        logger.error(f"[STARTUP] Database init failed: {e}")
    
    # Print startup banner (always visible)
    log_startup_banner(logger, settings.PORT, settings.DEBUG)
    
    yield
    
    # ========== SHUTDOWN ==========
    log_shutdown_banner(logger)
    
    # Stop CertStream monitor
    try:
        stop_cert_monitor()
    except Exception as e:
        logger.warning(f"CertStream shutdown warning: {e}")
    
    if scheduler.running:
        scheduler.shutdown()
    await close_db()


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="API for detecting phishing URLs using Machine Learning",
    version="1.0.0",
    lifespan=lifespan
)

# ============================================================
# CORS CONFIGURATION - Environment-Aware
# ============================================================
# IMPORTANT: In production with Nginx reverse proxy, Nginx handles CORS.
# FastAPI CORS middleware should ONLY run in development to prevent duplicate headers.
# 
# The error "Access-Control-Allow-Origin contains multiple values" happens when
# BOTH Nginx AND FastAPI add CORS headers.
# 
# Solution:
# - Development (no Nginx): FastAPI handles CORS ✅
# - Production (with Nginx): Nginx handles CORS, FastAPI disabled ❌
# ============================================================

ALLOWED_ORIGINS = settings.cors_origins_list

# Only add CORS middleware in DEVELOPMENT mode
# In production, Nginx adds CORS headers (see nginx-cors.conf)
if settings.DEBUG:
    logger.info("[DEV MODE] Enabling FastAPI CORS middleware for development")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=[
            "Content-Type",
            "Authorization",
            "Accept",
            "Origin",
            "User-Agent",
            "DNT",
            "Cache-Control",
            "X-Requested-With",
            "cf-turnstile-response",     # Cloudflare Turnstile token
        ],
        expose_headers=["Content-Length", "Content-Range"],
        max_age=3600,
    )
    logger.info(f"[OK] CORS configured for origins: {ALLOWED_ORIGINS}")
else:
    logger.info("[PRODUCTION MODE] CORS handled by Nginx - FastAPI middleware disabled")
    logger.info(f"[INFO] Allowed origins (Nginx): {ALLOWED_ORIGINS}")



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
app.include_router(chat.router, prefix="/chat", tags=["Chat"])
app.include_router(feedback.router, prefix="/feedback", tags=["Feedback"])


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
            "register": "POST /auth/register",
            "chat_ai": "POST /chat",
            "feedback": "POST /feedback"
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

# Export concurrency controls for scan router
app.state.scan_semaphore = SCAN_SEMAPHORE
app.state.scan_timeout = SCAN_TIMEOUT


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.DEBUG
    )
