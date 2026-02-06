"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

"""
Cloudflare Turnstile Security Middleware
Verifies bot protection tokens before allowing access to protected endpoints
"""

import logging
import os
from typing import Optional
import httpx

from fastapi import Request, HTTPException, status
from app.config import settings

logger = logging.getLogger(__name__)


def _skip_turnstile_env() -> bool:
    """True if SKIP_TURNSTILE=true in env (for debugging)."""
    return os.getenv("SKIP_TURNSTILE", "").strip().lower() == "true"


async def verify_turnstile(request: Request) -> dict:
    """
    Verify Cloudflare Turnstile token (single use per request).
    
    Call this ONCE per request—e.g. in the stream generator or at endpoint entry.
    Do not use Depends(verify_turnstile) and also call inside a generator/helper
    or the token will be consumed twice and the second check will fail.
    
    Validates the cf-turnstile-response token against Cloudflare's API.
    Raises HTTPException(403/400) if token is missing or invalid.
    
    Args:
        request: FastAPI Request object (token from header or JSON body)
        
    Returns:
        dict: Validation result from Cloudflare
    """
    # Dev bypass: skip verification when SKIP_TURNSTILE=true
    if _skip_turnstile_env():
        logger.debug("Turnstile verification skipped (SKIP_TURNSTILE=true)")
        return {"success": True, "skipped": True}
    
    # Skip verification if Turnstile is disabled (for testing/development)
    if not settings.TURNSTILE_ENABLED:
        logger.debug("Turnstile verification skipped (disabled in settings)")
        return {"success": True, "skipped": True}
    
    # Skip verification if secret key is not configured
    if not settings.CLOUDFLARE_SECRET_KEY:
        logger.warning("Turnstile enabled but CLOUDFLARE_SECRET_KEY not set - skipping verification")
        return {"success": True, "skipped": True}
    
    # Extract token from multiple possible sources
    turnstile_token: Optional[str] = None
    
    # 1. Try header (recommended for API calls)
    turnstile_token = request.headers.get("cf-turnstile-response")
    
    # 2. Try form data (for form submissions)
    if not turnstile_token:
        try:
            form_data = await request.form()
            turnstile_token = form_data.get("cf-turnstile-response")
        except:
            pass
    
    # 3. Try JSON body (for JSON API calls)
    if not turnstile_token:
        try:
            body = await request.json()
            turnstile_token = body.get("cf_turnstile_response") or body.get("turnstileToken")
        except:
            pass
    
    # Token is required
    if not turnstile_token:
        logger.warning(f"Turnstile token missing from {request.client.host}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "bot_protection_required",
                "message": "Cloudflare Turnstile verification required. Please complete the challenge."
            }
        )
    
    # Verify token with Cloudflare
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                json={
                    "secret": settings.CLOUDFLARE_SECRET_KEY,
                    "response": turnstile_token,
                    "remoteip": request.client.host  # Optional: IP verification
                },
                timeout=10.0
            )
            
            result = response.json()
            
            if not result.get("success", False):
                error_codes = result.get("error-codes", [])
                
                # Handle timeout-or-duplicate specifically (user error, not system error)
                if 'timeout-or-duplicate' in error_codes:
                    logger.warning(
                        f"Turnstile token expired/reused for {request.client.host}. "
                        f"This is a user error (double-click or stale page)."
                    )
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail={
                            "error": "token_expired",
                            "message": "Captcha expired or already used. Please refresh the page and try again.",
                            "error_codes": error_codes
                        }
                    )
                
                # Other verification failures (potential bot)
                logger.warning(
                    f"Turnstile verification failed for {request.client.host}. "
                    f"Errors: {error_codes}"
                )
                
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "bot_protection_failed",
                        "message": "Bot protection verification failed. Please try again.",
                        "error_codes": error_codes
                    }
                )
            
            logger.debug(f"Turnstile verification successful for {request.client.host}")
            return result
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Turnstile verification error: {e}", exc_info=True)
        
        # Fail-safe: Allow request if Cloudflare API is down (configurable)
        # In production, you might want to change this to raise HTTPException
        logger.warning("Turnstile API error - allowing request (fail-safe mode)")
        return {"success": True, "error": str(e), "fail_safe": True}


async def verify_turnstile_optional(request: Request) -> dict:
    """
    Optional Turnstile verification that doesn't raise exceptions.
    Useful for logging/monitoring bot activity without blocking requests.
    
    Returns:
        dict: Verification result with 'verified' boolean
    """
    try:
        result = await verify_turnstile(request)
        return {"verified": True, "result": result}
    except HTTPException:
        return {"verified": False}
    except Exception as e:
        logger.error(f"Turnstile verification error: {e}")
        return {"verified": False, "error": str(e)}
