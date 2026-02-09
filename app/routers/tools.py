"""
Phishing Detector - Security Suite Tools
Copyright (c) 2026 BaoZ

Breach check (XposedOrNot), link unshortener, security news ticker.
"""

import logging
import time
from typing import Any, Dict, List, Tuple

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory cache for news: (timestamp, data)
_news_cache: Tuple[float, List[Dict[str, str]]] = (0, [])
NEWS_CACHE_TTL = 600  # 10 minutes
HACKER_NEWS_RSS = "https://feeds.feedburner.com/TheHackersNews"
XPOSED_OR_NOT_BASE = "https://api.xposedornot.com/v1/check-email"


class BreachCheckInput(BaseModel):
    email: str = Field(..., min_length=1, description="Email to check for breaches")


class UnshortenInput(BaseModel):
    url: str = Field(..., min_length=1, description="Short URL to expand")


@router.post("/breach-check")
async def breach_check(body: BreachCheckInput) -> Dict[str, Any]:
    """
    Check if an email appears in known data breaches via XposedOrNot API.
    Returns SAFE (404) or LEAKED (200) with list of breach names.
    """
    email = body.email.strip().lower()
    try:
        r = requests.get(
            f"{XPOSED_OR_NOT_BASE}/{email}",
            timeout=10,
            headers={"User-Agent": "CyberSentinel-SecuritySuite/1.0"},
        )
    except requests.RequestException as e:
        logger.warning("Breach check request failed: %s", e)
        raise HTTPException(status_code=502, detail="Breach check service unavailable.")

    if r.status_code == 404:
        return {"status": "SAFE", "breaches": [], "count": 0}

    if r.status_code == 429:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    if r.status_code >= 500:
        raise HTTPException(status_code=502, detail="Breach check service error. Try again later.")

    if r.status_code != 200:
        return {"status": "SAFE", "breaches": [], "count": 0}

    try:
        data = r.json()
    except Exception:
        return {"status": "SAFE", "breaches": [], "count": 0}

    # XposedOrNot returns Breaches as list of lists e.g. [["BreachName", "Desc..."], ...]
    breaches_raw = data.get("Breaches") or data.get("breaches") or data.get("data") or data.get("found") or []
    if not isinstance(breaches_raw, list):
        breaches_raw = []

    breaches = []
    for b in breaches_raw:
        if isinstance(b, list) and len(b) > 0:
            breaches.append(str(b[0]))  # First item is the breach name
        elif isinstance(b, dict):
            breaches.append(str(b.get("name", b.get("Name", "Unknown"))))
        else:
            breaches.append(str(b))

    return {"status": "LEAKED", "breaches": breaches, "count": len(breaches)}


@router.post("/unshorten")
async def unshorten(body: UnshortenInput) -> Dict[str, Any]:
    """Expand a short URL to its final destination using HTTP HEAD with redirects."""
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = requests.head(url, allow_redirects=True, timeout=5)
        final_url = r.url
    except requests.RequestException as e:
        logger.debug("Unshorten failed: %s", e)
        raise HTTPException(status_code=400, detail=f"Could not resolve URL: {e!s}")
    return {
        "original_url": body.url,
        "final_url": final_url,
        "status_code": r.status_code,
    }


def _fetch_news_cached() -> List[Dict[str, str]]:
    global _news_cache
    now = time.time()
    if _news_cache[0] + NEWS_CACHE_TTL > now and _news_cache[1]:
        return _news_cache[1]
    try:
        import feedparser
        feed = feedparser.parse(HACKER_NEWS_RSS, request_headers={"User-Agent": "CyberSentinel/1.0"})
        entries = getattr(feed, "entries", [])[:5]
        items = [{"title": e.get("title", ""), "link": e.get("link", "")} for e in entries]
        _news_cache = (now, items)
        return items
    except Exception as e:
        logger.warning("News feed failed: %s", e)
        return _news_cache[1] if _news_cache[1] else []


@router.get("/news")
async def security_news() -> List[Dict[str, str]]:
    """Return top 5 security headlines from The Hacker News RSS (cached 10 min)."""
    return _fetch_news_cached()
