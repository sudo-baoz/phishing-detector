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
Smart Logging Configuration - "Quiet Mode"

ARCHITECTURE:
- Root logger set to WARNING (blocks INFO/DEBUG from 3rd parties)
- Application loggers set to DEBUG (allows granular control)
- Explicitly silences noisy libraries (httpx, chromadb, uvicorn.access)

LOG LEVEL GUIDELINES:
- logger.debug()    → Development info (hidden by default)
- logger.info()     → AVOID - use debug() instead
- logger.warning()  → Suspicious activity (phishing detected, bot check triggered)
- logger.error()    → System failures (API timeout, browser crash)
- logger.critical() → Application lifecycle (startup/shutdown)
"""

import logging
import sys
from typing import Optional

# ============================================================================
# NOISY 3RD PARTY LOGGERS TO SILENCE
# ============================================================================
NOISY_LOGGERS = [
    # HTTP clients
    "httpx",
    "httpcore",
    "httpcore.http11",
    "httpcore.connection",
    "urllib3",
    "urllib3.connectionpool",
    "requests",
    
    # Database & Vector stores
    "chromadb",
    "chromadb.config",
    "chromadb.db",
    "chromadb.segment",
    "chromadb.telemetry",
    "sqlalchemy",
    "sqlalchemy.engine",
    "aiosqlite",
    
    # Web server
    "uvicorn",
    "uvicorn.access",
    "uvicorn.error",
    "fastapi",
    
    # AI/ML libraries
    "openai",
    "google.auth",
    "google.auth.transport",
    "google.generativeai",
    "transformers",
    "sentence_transformers",
    "huggingface_hub",
    
    # Async & networking
    "asyncio",
    "websockets",
    "multipart",
    "multipart.multipart",
    
    # Playwright (browser automation)
    "playwright",
    
    # APScheduler
    "apscheduler",
    "apscheduler.scheduler",
    "apscheduler.executors",
]

# Application loggers (our code - allow DEBUG level)
APP_LOGGERS = [
    "app",
    "app.main",
    "app.routers",
    "app.routers.scan",
    "app.routers.chat",
    "app.routers.auth",
    "app.routers.health",
    "app.services",
    "app.services.ai_engine",
    "app.services.vision_scanner",
    "app.services.deep_scan",
    "app.services.osint",
    "app.services.chat_agent",
    "app.services.knowledge_base",
    "app.services.network_forensics",
    "app.services.graph_builder",
    "app.services.yara_scanner",
    "app.services.report_generator",
    "app.services.cert_monitor",
]


class QuietModeFilter(logging.Filter):
    """
    Filter that allows WARNING+ from noisy loggers
    but allows DEBUG+ from application loggers.
    """
    
    def __init__(self, allowed_prefixes: list):
        super().__init__()
        self.allowed_prefixes = allowed_prefixes
    
    def filter(self, record: logging.LogRecord) -> bool:
        # Always allow WARNING and above
        if record.levelno >= logging.WARNING:
            return True
        
        # Allow DEBUG+ for application loggers
        for prefix in self.allowed_prefixes:
            if record.name.startswith(prefix):
                return True
        
        # Block INFO/DEBUG from 3rd party
        return False


def configure_logging(
    debug_mode: bool = False,
    log_file: Optional[str] = "app.log",
    quiet_mode: bool = True
) -> logging.Logger:
    """
    Configure application logging with "Quiet Mode".
    
    Args:
        debug_mode: If True, show DEBUG logs from app code
        log_file: Path to log file (None to disable file logging)
        quiet_mode: If True, silence 3rd party INFO/DEBUG logs
    
    Returns:
        Root application logger
    """
    
    # ========================================================================
    # STEP 1: Configure Root Logger
    # ========================================================================
    root_logger = logging.getLogger()
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Set root level based on mode
    if debug_mode:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.WARNING)  # Block 3rd party noise
    
    # ========================================================================
    # STEP 2: Create Formatters
    # ========================================================================
    # Concise format for production
    concise_formatter = logging.Formatter(
        fmt="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
        datefmt="%H:%M:%S"
    )
    
    # Detailed format for file
    detailed_formatter = logging.Formatter(
        fmt="%(asctime)s │ %(levelname)-8s │ %(name)s:%(lineno)d │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # ========================================================================
    # STEP 3: Console Handler (Quiet Mode)
    # ========================================================================
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(concise_formatter)
    
    if quiet_mode:
        # Only show WARNING+ from 3rd party, but DEBUG+ from app
        console_handler.addFilter(QuietModeFilter(["app", "__main__"]))
    
    root_logger.addHandler(console_handler)
    
    # ========================================================================
    # STEP 4: File Handler (Full logs for debugging)
    # ========================================================================
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # Capture everything in file
        file_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(file_handler)
    
    # ========================================================================
    # STEP 5: Explicitly Silence Noisy Loggers
    # ========================================================================
    for logger_name in NOISY_LOGGERS:
        noisy_logger = logging.getLogger(logger_name)
        noisy_logger.setLevel(logging.WARNING)
        noisy_logger.propagate = False  # Don't send to root
    
    # ========================================================================
    # STEP 6: Configure Application Loggers
    # ========================================================================
    app_level = logging.DEBUG if debug_mode else logging.WARNING
    
    for logger_name in APP_LOGGERS:
        app_logger = logging.getLogger(logger_name)
        app_logger.setLevel(app_level)
    
    # ========================================================================
    # STEP 7: Return main application logger
    # ========================================================================
    main_logger = logging.getLogger("app.main")
    main_logger.setLevel(logging.DEBUG if debug_mode else logging.WARNING)
    
    return main_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.
    Ensures consistent configuration.
    
    Usage:
        from app.core.logger import get_logger
        logger = get_logger(__name__)
    """
    return logging.getLogger(name)


# ============================================================================
# STARTUP MESSAGE (Always show regardless of log level)
# ============================================================================
def log_startup_banner(logger: logging.Logger, port: int, debug: bool):
    """
    Print startup banner at CRITICAL level (always visible).
    """
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    PHISHING URL DETECTION API - GOD MODE                     ║
║══════════════════════════════════════════════════════════════════════════════║
║  Mode:     {'DEVELOPMENT' if debug else 'PRODUCTION'}                                                        ║
║  Port:     {port:<10}                                                          ║
║  Docs:     http://0.0.0.0:{port}/docs                                           ║
║  Logging:  {'VERBOSE (DEBUG)' if debug else 'QUIET MODE (WARNING+)'}                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    # Force print even if logger is silenced
    print(banner)
    logger.critical(f"API started on port {port} in {'DEBUG' if debug else 'PRODUCTION'} mode")


def log_shutdown_banner(logger: logging.Logger):
    """Print shutdown message."""
    print("\n⏹️  Shutting down Phishing API...")
    logger.critical("API shutdown initiated")
