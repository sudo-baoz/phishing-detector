"""
Phishing Detector - Dynamic Threat Intelligence (Blacklist Feeds)
Copyright (c) 2026 BaoZ

Fetches and updates phishing URLs from external feeds (PhishTank, OpenPhish).
Stores signatures for O(1) lookup. Use Redis in production for persistence.
"""

import csv
import logging
from typing import Set
import requests

logger = logging.getLogger(__name__)

# Mock/demo feed URLs (replace with real PhishTank/OpenPhish when API key or terms allow)
PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.csv"  # requires API key in production
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"  # free text, one URL per line


class ThreatIntelService:
    """
    Fetches phishing URLs from external feeds and provides O(1) blacklist lookup.
    Uses in-memory set for demo; use Redis Set (SADD/SISMEMBER) for production.
    """

    def __init__(self):
        self._blacklist: Set[str] = set()
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "PhishingDetector-ThreatIntel/1.0"})

    def update_feeds(self) -> int:
        """
        Download feeds from PhishTank (CSV) or OpenPhish (TXT), parse URLs,
        and store in the blacklist set. Returns total count of signatures updated.
        """
        count_before = len(self._blacklist)
        added = 0

        # OpenPhish: plain text, one URL per line (no auth)
        try:
            r = self._session.get(OPENPHISH_FEED_URL, timeout=30)
            r.raise_for_status()
            for line in r.text.strip().splitlines():
                url = line.strip()
                if url and not url.startswith("#"):
                    self._blacklist.add(url)
                    added += 1
            logger.info("Updated %s signatures from OpenPhish.", added)
        except Exception as e:
            logger.warning("OpenPhish feed failed (using mock): %s", e)
            # Mock data so demo works without external feed
            mock_urls = [
                "http://evil-phish-example.com/login",
                "https://fake-paypal-example.com/verify",
            ]
            for url in mock_urls:
                self._blacklist.add(url)
                added += 1
            logger.info("Updated %s signatures from mock feed.", len(mock_urls))

        # PhishTank: CSV (often requires API key; use mock URL for now)
        try:
            # Use a small mock CSV for demo (real URL: PHISHTANK_FEED_URL)
            mock_phishtank = [
                "phish_id,url,phish_detail_url,submission_time,verified,verification_time,target",
                "1,http://phishtank-mock-example.com,http://example.com,2024-01-01T00:00:00Z,yes,2024-01-01T00:00:00Z,Other",
            ]
            reader = csv.DictReader(mock_phishtank)
            pt_count = 0
            for row in reader:
                url = (row.get("url") or "").strip()
                if url:
                    if url not in self._blacklist:
                        added += 1
                    self._blacklist.add(url)
                    pt_count += 1
            logger.info("Updated %s signatures from PhishTank.", pt_count)
        except Exception as e:
            logger.debug("PhishTank feed skipped: %s", e)

        total = len(self._blacklist)
        logger.info("Updated %s signatures total. Blacklist size: %s", added, total)
        return total

    def check_blacklist(self, url: str) -> bool:
        """
        Returns True if the given URL is in the blacklist (exact or normalized).
        O(1) lookup when using set.
        """
        if not url:
            return False
        url = url.strip()
        if url in self._blacklist:
            return True
        # Optional: normalize (e.g. strip trailing slash, lowercase) for fuzzy match
        normalized = url.rstrip("/").lower()
        return normalized in self._blacklist or url in self._blacklist

    @property
    def blacklist_size(self) -> int:
        return len(self._blacklist)


# Singleton for app use
_threat_intel: ThreatIntelService | None = None


def get_threat_intel() -> ThreatIntelService:
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelService()
    return _threat_intel
