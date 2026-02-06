"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

DeepAnalyst - OSINT metadata (domain age, registrar, SSL) for evidence-based AI decisions.
Data that scammers cannot easily fake: WHOIS creation date, certificate issuer.
"""

import logging
import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    whois = None
    logger.warning("python-whois not installed. Install with: pip install python-whois")


def _normalize_domain(url_or_domain: str) -> str:
    """Extract hostname from URL or return as-is if already a domain."""
    s = (url_or_domain or "").strip()
    if not s:
        return ""
    if "://" in s:
        try:
            parsed = urlparse(s)
            s = parsed.netloc or parsed.path or s
        except Exception:
            pass
    if ":" in s:
        s = s.split(":")[0]
    if s.lower().startswith("www."):
        s = s[4:]
    return s.strip().lower()


class DeepAnalyst:
    """
    Extracts OSINT metadata (domain age, registrar, SSL issuer) for use in
    phishing analysis. Heuristics (e.g. very new domain, DV-only SSL) are
    added as risk_factors for the AI to consider.
    """

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyze a domain for WHOIS (age, registrar) and SSL certificate.
        domain: Can be a full URL or a hostname (e.g. google.com or https://evil.com/path).
        """
        domain = _normalize_domain(domain)
        result: Dict[str, Any] = {
            "domain": domain,
            "age_days": 0,
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "ssl_issuer": "Unknown",
            "ssl_info_note": None,
            "risk_factors": [],
        }

        if not domain:
            result["risk_factors"].append("WARNING: No domain to analyze.")
            return result

        # 1. WHOIS LOOKUP (Domain Age)
        if WHOIS_AVAILABLE and whois:
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    creation_date = (
                        w.creation_date[0]
                        if isinstance(w.creation_date, list)
                        else w.creation_date
                    )
                    if hasattr(creation_date, "date"):
                        creation_date = creation_date.date()
                    age = (datetime.now().date() - creation_date).days if creation_date else 0
                    result["age_days"] = max(0, age)
                    result["creation_date"] = str(creation_date)

                    if age < 30:
                        result["risk_factors"].append(
                            f"CRITICAL: Domain is only {age} days old."
                        )
                    elif age < 180:
                        result["risk_factors"].append(
                            f"WARNING: Domain is relatively new ({age} days)."
                        )

                if getattr(w, "registrar", None):
                    result["registrar"] = w.registrar if isinstance(w.registrar, str) else (w.registrar[0] if w.registrar else "Unknown")
            except Exception as e:
                logger.debug("WHOIS lookup failed for %s: %s", domain, e)
                result["risk_factors"].append(
                    "WARNING: WHOIS data hidden or privacy-protected."
                )
        else:
            result["risk_factors"].append("WARNING: WHOIS library not available.")

        # 2. SSL CERTIFICATE CHECK
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
                sock.settimeout(8)
                sock.connect((domain, 443))
                cert = sock.getpeercert()
                issuer_list = cert.get("issuer", [])
                issuer = dict(issuer_list) if issuer_list else {}
                common_name = issuer.get("commonName", "")
                organization = issuer.get("organizationName", "Unknown")

                result["ssl_issuer"] = f"{organization} ({common_name})"

                if "Let's Encrypt" in (common_name or "") or "Cloudflare" in (common_name or ""):
                    result["ssl_info_note"] = (
                        "Certificate is Domain Validated (DV) - Common for phishing."
                    )
                else:
                    result["ssl_info_note"] = (
                        "Certificate is Organization Validated (OV/EV) - Higher trust."
                    )
        except ssl.SSLError as e:
            logger.debug("SSL error for %s: %s", domain, e)
            result["risk_factors"].append("SSL connection failed or invalid certificate.")
        except (socket.timeout, socket.gaierror, OSError) as e:
            logger.debug("Socket/connection error for %s: %s", domain, e)
            result["risk_factors"].append("SSL connection failed or no SSL.")

        return result


# Singleton for reuse
_deep_analyst: Optional[DeepAnalyst] = None


def get_deep_analyst() -> DeepAnalyst:
    global _deep_analyst
    if _deep_analyst is None:
        _deep_analyst = DeepAnalyst()
    return _deep_analyst
