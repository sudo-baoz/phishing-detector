"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

Concrete captcha solver strategies: StealthClick (free), 2Captcha, CapSolver.
"""

import asyncio
import logging
import random
from typing import Any, Optional

import httpx

from app.services.solvers.base import BaseCaptchaSolver

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# StealthClickSolver (FREE) – Playwright-based human-like click
# ---------------------------------------------------------------------------

class StealthClickSolver(BaseCaptchaSolver):
    """
    Free solver: finds Turnstile/ReCaptcha iframes, hovers, random delay, clicks.
    Waits up to 5s for the challenge to disappear.
    """

    VERIFY_WAIT_SEC = 5
    POLL_INTERVAL_MS = 300

    async def solve(
        self,
        page: Any,
        sitekey: Optional[str] = None,
        url: Optional[str] = None,
    ) -> bool:
        try:
            # Selectors for Turnstile / ReCaptcha widget iframes
            turnstile_frame = await page.query_selector(
                'iframe[src*="challenges.cloudflare.com"], iframe[title*="Widget containing a checkbox"]'
            )
            recaptcha_frame = await page.query_selector(
                'iframe[src*="recaptcha"], iframe[title*="reCAPTCHA"]'
            )
            frame = turnstile_frame or recaptcha_frame
            if not frame:
                # Try within main frame: clickable div that looks like checkbox
                box = await page.query_selector(
                    '[class*="turnstile"], [class*="recaptcha"], [data-sitekey]'
                )
                if box:
                    await box.hover()
                    await asyncio.sleep(random.uniform(0.3, 0.8))
                    await box.click()
                    await asyncio.sleep(self.VERIFY_WAIT_SEC)
                    return True
                logger.warning("[StealthClick] No Turnstile/ReCaptcha iframe or widget found.")
                return False

            # Switch to iframe and find checkbox area
            frame_content = await frame.content_frame()
            if not frame_content:
                return False
            checkbox = await frame_content.query_selector(
                'input[type="checkbox"], .mark, body'
            )
            target = checkbox or frame_content
            await target.hover()
            await asyncio.sleep(random.uniform(0.2, 0.6))
            await target.click()
            await asyncio.sleep(self.VERIFY_WAIT_SEC)
            return True
        except Exception as e:
            logger.warning(f"[StealthClick] Solve failed: {e}")
            return False


# ---------------------------------------------------------------------------
# TwoCaptchaSolver (PAID) – 2captcha.com API
# ---------------------------------------------------------------------------

class TwoCaptchaSolver(BaseCaptchaSolver):
    """Paid solver: send sitekey + url to 2captcha, poll for token, inject and submit."""

    API_CREATE = "https://api.2captcha.com/createTask"
    API_RESULT = "https://api.2captcha.com/getTaskResult"
    POLL_INTERVAL = 5
    MAX_POLLS = 24  # ~2 min

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def solve(
        self,
        page: Any,
        sitekey: Optional[str] = None,
        url: Optional[str] = None,
    ) -> bool:
        if not sitekey or not url:
            logger.warning("[2Captcha] sitekey and url are required.")
            return False
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Create task (TurnstileTaskProxyless)
                payload = {
                    "clientKey": self.api_key,
                    "task": {
                        "type": "TurnstileTaskProxyless",
                        "websiteURL": url,
                        "websiteKey": sitekey,
                    },
                }
                r = await client.post(self.API_CREATE, json=payload)
                data = r.json()
                if data.get("errorId", 1) != 0:
                    logger.warning(f"[2Captcha] createTask error: {data.get('errorDescription', data)}")
                    return False
                task_id = data.get("taskId")
                if not task_id:
                    return False

                # Poll for result
                for _ in range(self.MAX_POLLS):
                    await asyncio.sleep(self.POLL_INTERVAL)
                    r2 = await client.post(
                        self.API_RESULT,
                        json={"clientKey": self.api_key, "taskId": task_id},
                    )
                    resp = r2.json()
                    if resp.get("errorId", 1) != 0:
                        logger.warning(f"[2Captcha] getTaskResult error: {resp}")
                        return False
                    if resp.get("status") == "ready":
                        token = (resp.get("solution") or {}).get("token")
                        if not token:
                            return False
                        # Inject token into page
                        injected = await page.evaluate(
                            """
                            (token) => {
                                const sel = '[name="cf-turnstile-response"], #g-recaptcha-response, textarea[name="g-recaptcha-response"]';
                                const el = document.querySelector(sel);
                                if (el) { el.value = token; el.dispatchEvent(new Event('input', { bubbles: true })); return true; }
                                return false;
                            }
                            """,
                            token,
                        )
                        if not injected:
                            logger.warning("[2Captcha] Could not find response input to inject token.")
                            return False
                        # Click submit/callback button if present
                        submit = await page.query_selector(
                            'input[type="submit"], button[type="submit"], [type="submit"], form button, .submit, [data-callback]'
                        )
                        if submit:
                            await submit.click()
                            await asyncio.sleep(2)
                        return True
                    # status "processing", continue polling
                logger.warning("[2Captcha] Polling timed out.")
                return False
        except Exception as e:
            logger.warning(f"[2Captcha] Solve failed: {e}")
            return False


# ---------------------------------------------------------------------------
# CapSolverSolver (PAID) – capsolver.com API (speed-optimized for Turnstile)
# ---------------------------------------------------------------------------

class CapSolverSolver(BaseCaptchaSolver):
    """Paid solver: CapSolver API (Turnstile-optimized, fast)."""

    API_CREATE = "https://api.capsolver.com/createTask"
    API_RESULT = "https://api.capsolver.com/getTaskResult"
    POLL_INTERVAL = 2
    MAX_POLLS = 60

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def solve(
        self,
        page: Any,
        sitekey: Optional[str] = None,
        url: Optional[str] = None,
    ) -> bool:
        if not sitekey or not url:
            logger.warning("[CapSolver] sitekey and url are required.")
            return False
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                payload = {
                    "clientKey": self.api_key,
                    "task": {
                        "type": "AntiTurnstileTaskProxyLess",
                        "websiteURL": url,
                        "websiteKey": sitekey,
                    },
                }
                r = await client.post(self.API_CREATE, json=payload)
                data = r.json()
                if data.get("errorId", 1) != 0:
                    logger.warning(f"[CapSolver] createTask error: {data.get('errorDescription', data)}")
                    return False
                task_id = data.get("taskId")
                if not task_id:
                    return False

                for _ in range(self.MAX_POLLS):
                    await asyncio.sleep(self.POLL_INTERVAL)
                    r2 = await client.post(
                        self.API_RESULT,
                        json={"clientKey": self.api_key, "taskId": task_id},
                    )
                    resp = r2.json()
                    if resp.get("errorId", 1) != 0:
                        return False
                    if resp.get("status") == "ready":
                        solution = resp.get("solution") or {}
                        token = solution.get("token") or solution.get("turnstileToken")
                        if not token:
                            return False
                        injected = await page.evaluate(
                            """
                            (token) => {
                                const sel = '[name="cf-turnstile-response"], #g-recaptcha-response, textarea[name="g-recaptcha-response"]';
                                const el = document.querySelector(sel);
                                if (el) { el.value = token; el.dispatchEvent(new Event('input', { bubbles: true })); return true; }
                                return false;
                            }
                            """,
                            token,
                        )
                        if not injected:
                            return False
                        submit = await page.query_selector(
                            'input[type="submit"], button[type="submit"], [type="submit"], form button, .submit'
                        )
                        if submit:
                            await submit.click()
                            await asyncio.sleep(2)
                        return True
                return False
        except Exception as e:
            logger.warning(f"[CapSolver] Solve failed: {e}")
            return False
