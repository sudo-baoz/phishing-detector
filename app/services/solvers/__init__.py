"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

Captcha solver strategies (Strategy Pattern).
"""

from app.services.solvers.base import BaseCaptchaSolver
from app.services.solvers.strategies import StealthClickSolver, TwoCaptchaSolver, CapSolverSolver

__all__ = [
    "BaseCaptchaSolver",
    "StealthClickSolver",
    "TwoCaptchaSolver",
    "CapSolverSolver",
]
