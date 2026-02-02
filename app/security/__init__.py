"""Security module for Phishing Detector API"""

from .turnstile import verify_turnstile, verify_turnstile_optional

__all__ = ["verify_turnstile", "verify_turnstile_optional"]
