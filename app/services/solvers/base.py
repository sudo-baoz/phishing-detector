"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

Abstract base class for captcha solving strategies.
"""

from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseCaptchaSolver(ABC):
    """
    Abstract base for all captcha solvers (Strategy Pattern).
    Implementations: StealthClick (free), 2Captcha, CapSolver (paid).
    """

    @abstractmethod
    async def solve(
        self,
        page: Any,
        sitekey: Optional[str] = None,
        url: Optional[str] = None,
    ) -> bool:
        """
        Attempt to solve the captcha on the given page.

        :param page: Playwright Page object (for clicks or JS injection).
        :param sitekey: Detected sitekey (for API-based solvers).
        :param url: Current page URL (for API-based solvers).
        :return: True if solved, False if failed.
        """
        pass
