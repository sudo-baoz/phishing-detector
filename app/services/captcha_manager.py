"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

Captcha solver factory: returns the solver instance based on CAPTCHA_PROVIDER.
"""

import logging
from typing import Optional

from app.config import settings
from app.services.solvers.base import BaseCaptchaSolver
from app.services.solvers.strategies import (
    CapSolverSolver,
    StealthClickSolver,
    TwoCaptchaSolver,
)

logger = logging.getLogger(__name__)


class CaptchaFactory:
    """
    Factory for captcha solvers.
    - FREE -> StealthClickSolver (Playwright click)
    - 2CAPTCHA -> TwoCaptchaSolver(api_key)
    - CAPSOLVER -> CapSolverSolver(api_key)
    """

    @staticmethod
    def get_solver() -> BaseCaptchaSolver:
        provider = (settings.CAPTCHA_PROVIDER or "FREE").strip().upper()
        if provider == "FREE":
            return StealthClickSolver()
        if provider == "2CAPTCHA":
            api_key = (settings.CAPTCHA_API_KEY or "").strip()
            if not api_key:
                logger.warning("[CaptchaFactory] CAPTCHA_PROVIDER=2CAPTCHA but CAPTCHA_API_KEY is empty; falling back to FREE.")
                return StealthClickSolver()
            return TwoCaptchaSolver(api_key)
        if provider == "CAPSOLVER":
            api_key = (settings.CAPTCHA_API_KEY or "").strip()
            if not api_key:
                logger.warning("[CaptchaFactory] CAPTCHA_PROVIDER=CAPSOLVER but CAPTCHA_API_KEY is empty; falling back to FREE.")
                return StealthClickSolver()
            return CapSolverSolver(api_key)
        logger.warning(f"[CaptchaFactory] Unknown CAPTCHA_PROVIDER={provider}; using FREE.")
        return StealthClickSolver()
