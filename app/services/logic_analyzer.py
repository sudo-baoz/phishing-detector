"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

Legitimacy checker: prevents false positives when the scanned URL is the
official domain of the detected brand (e.g. google.com for Google).
"""

import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Database of Truth: official root domains per brand. Subdomains implied (e.g. mail.google.com -> google.com).
# Used for Absolute Immunity: if URL matches, verdict is FORCIBLY SAFE, score 0, evasion cleared.
OFFICIAL_BRANDS: Dict[str, List[str]] = {
    "Google": ["google.com", "google.co.vn", "google.com.vn", "youtube.com", "accounts.google.com", "mail.google.com", "drive.google.com", "docs.google.com", "gstatic.com"],
    "Facebook": ["facebook.com", "fb.com", "fb.me", "messenger.com", "meta.com", "instagram.com", "whatsapp.com"],
    "Microsoft": ["microsoft.com", "live.com", "office.com", "azure.com", "outlook.com", "hotmail.com", "skype.com", "linkedin.com", "github.com"],
    "Netflix": ["netflix.com", "netflix.net"],
    "PayPal": ["paypal.com", "paypalobjects.com"],
    "Amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp", "aws.amazon.com", "amazonaws.com"],
    "Apple": ["apple.com", "icloud.com", "apple.co.uk", "itunes.apple.com"],
    "Twitter": ["twitter.com", "x.com", "t.co"],
    "LinkedIn": ["linkedin.com", "lnkd.in"],
    "Adobe": ["adobe.com", "adobe.io"],
    "Yahoo": ["yahoo.com", "yahoo.co.jp"],
    "Dropbox": ["dropbox.com", "db.tt"],
    "Spotify": ["spotify.com"],
    "Telegram": ["telegram.org", "t.me"],
    "Discord": ["discord.com", "discord.gg"],
    "Zoom": ["zoom.us", "zoom.com"],
    "Slack": ["slack.com"],
    "GitHub": ["github.com", "github.io"],
    "Stripe": ["stripe.com"],
    "Shopify": ["shopify.com", "myshopify.com"],
    "Cloudflare": ["cloudflare.com"],
    "DHL": ["dhl.com", "dhl.de"],
    "FedEx": ["fedex.com"],
    "UPS": ["ups.com"],
    "Bank": [],  # No single "Bank" root; leave empty so we never mark as official
}


def _extract_root_domain(url: str) -> str:
    """
    Extract root domain (registrable: SLD + TLD) from URL.
    e.g. https://mail.google.com/path -> google.com
         https://sub.accounts.google.co.vn -> google.co.vn
    """
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or parsed.path or "").strip().lower()
        if not hostname or "/" in hostname:
            return ""
        # Remove port
        if ":" in hostname:
            hostname = hostname.split(":")[0]
        parts = hostname.split(".")
        if len(parts) >= 2:
            # Use last two parts (e.g. google.com); handle co.uk / com.vn style
            if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov") and len(parts[-1]) <= 3:
                return ".".join(parts[-3:])  # e.g. google.co.uk
            return ".".join(parts[-2:])
        return hostname
    except Exception:
        return ""


def check_immunity(url: str, detected_brand: Optional[str]) -> bool:
    """
    Absolute Immunity: True if the URL is an official domain for the given brand.
    When True, caller must return SAFE, score 0, and clear evasion/impersonation.
    """
    return LegitimacyChecker.is_authorized(url, detected_brand)


def get_whitelist_brand(url: str) -> Optional[str]:
    """
    If the URL's root domain is in any OFFICIAL_BRANDS whitelist, return that brand name.
    Use for early immunity: run before evasion/YARA so whitelisted sites are never boosted.
    """
    root = _extract_root_domain(url)
    if not root:
        return None
    root_lower = root.lower()
    for brand_name, domains in OFFICIAL_BRANDS.items():
        if not domains:
            continue
        for d in domains:
            d_lower = d.lower()
            if root_lower == d_lower or root_lower.endswith("." + d_lower):
                return brand_name
    return None


class LegitimacyChecker:
    """
    Checks if a scanned URL belongs to the official domain set of a detected brand.
    Used to avoid false positives (e.g. google.com flagged as impersonating Google).
    """

    @staticmethod
    def is_authorized(url: str, detected_brand: Optional[str]) -> bool:
        """
        Return True if the URL is an official domain for the given brand (SAFE).
        Return False if the brand is known but the domain is not in the whitelist (impersonation),
        or if the brand is not in the database (caller should use standard AI analysis).

        Args:
            url: Scanned URL (e.g. https://www.google.com/search)
            detected_brand: Brand name as returned by AI (e.g. "Google", "PayPal")

        Returns:
            True only when the URL's root domain is in the brand's official list.
        """
        if not url or not detected_brand:
            return False
        brand_clean = (detected_brand or "").strip()
        if not brand_clean or brand_clean.lower() == "none":
            return False
        root = _extract_root_domain(url)
        if not root:
            return False
        # Normalize brand key (match case-insensitively against OFFICIAL_BRANDS keys)
        for brand_name, domains in OFFICIAL_BRANDS.items():
            if brand_name.lower() == brand_clean.lower():
                if not domains:
                    return False
                root_lower = root.lower()
                for d in domains:
                    # Exact match or subdomain: e.g. mail.google.com -> google.com in list
                    d_lower = d.lower()
                    if root_lower == d_lower or root_lower.endswith("." + d_lower):
                        logger.info(f"[LegitimacyChecker] Official domain: {url} -> {brand_name} ({root})")
                        return True
                logger.info(f"[LegitimacyChecker] Impersonation: {url} (root={root}) not in {brand_name} whitelist")
                return False
        # Brand not in database: do not override (proceed with standard analysis)
        return False
