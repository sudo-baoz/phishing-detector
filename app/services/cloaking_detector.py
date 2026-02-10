"""
Multi-vantage cloaking detection: compare bot (requests) vs user (playwright) content.
If similarity < 80%, flag as CLOAKING DETECTED.
"""
import logging
import re
from difflib import SequenceMatcher
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

SIMILARITY_THRESHOLD = 0.80  # Below this -> cloaking
REQUEST_TIMEOUT = 15
MAX_HTML_LEN = 500_000  # Cap for comparison


def _normalize_html(html: str) -> str:
    """Reduce noise: strip script/style, collapse whitespace."""
    if not html or len(html) > MAX_HTML_LEN:
        return (html or "")[:MAX_HTML_LEN]
    # Remove script and style content
    html = re.sub(r"<script[^>]*>[\s\S]*?</script>", "", html, flags=re.IGNORECASE)
    html = re.sub(r"<style[^>]*>[\s\S]*?</style>", "", html, flags=re.IGNORECASE)
    html = re.sub(r"\s+", " ", html)
    return html.strip()


def _fetch_bot(url: str) -> tuple[str, int]:
    """Request A: minimal headers (dumb bot). Returns (body, status_code)."""
    try:
        import requests
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "Bot/1.0"},
            allow_redirects=True,
        )
        text = (r.text or "")[:MAX_HTML_LEN]
        return text, r.status_code
    except Exception as e:
        logger.warning(f"[Cloaking] Bot fetch failed: {e}")
        return "", 0


def _fetch_user(url: str) -> tuple[str, int]:
    """Request B: Playwright with full browser. Returns (body, status_code)."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.set_default_timeout(REQUEST_TIMEOUT * 1000)
                resp = page.goto(url, wait_until="domcontentloaded")
                status = resp.status if resp else 0
                body = page.content() if page else ""
                return (body or "")[:MAX_HTML_LEN], status
            finally:
                browser.close()
    except Exception as e:
        logger.warning(f"[Cloaking] User (playwright) fetch failed: {e}")
        return "", 0


def detect_cloaking(url: str) -> Dict[str, Any]:
    """
    Compare bot vs user HTML; if similarity < threshold, return cloaking detected.

    Returns:
        {
            "cloaking_detected": bool,
            "similarity_ratio": float,
            "bot_content_length": int,
            "user_content_length": int,
            "bot_html_preview": str (first 2k),
            "user_html_preview": str (first 2k),
        }
    """
    result = {
        "cloaking_detected": False,
        "similarity_ratio": 1.0,
        "bot_content_length": 0,
        "user_content_length": 0,
        "bot_html_preview": "",
        "user_html_preview": "",
    }

    bot_html, bot_status = _fetch_bot(url)
    user_html, user_status = _fetch_user(url)

    result["bot_content_length"] = len(bot_html)
    result["user_content_length"] = len(user_html)
    result["bot_html_preview"] = (bot_html or "")[:2000]
    result["user_html_preview"] = (user_html or "")[:2000]

    if not bot_html and not user_html:
        return result

    norm_bot = _normalize_html(bot_html)
    norm_user = _normalize_html(user_html)
    if not norm_bot or not norm_user:
        result["similarity_ratio"] = 0.0
        result["cloaking_detected"] = True
        return result

    ratio = SequenceMatcher(None, norm_bot, norm_user).ratio()
    result["similarity_ratio"] = round(ratio, 4)
    result["cloaking_detected"] = ratio < SIMILARITY_THRESHOLD

    if result["cloaking_detected"]:
        logger.warning(f"[Cloaking] Detected: similarity={ratio:.2%} for {url[:80]}")

    return result
