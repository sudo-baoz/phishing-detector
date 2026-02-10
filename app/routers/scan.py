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

"""URL Scanning Router - Phishing Detection"""

import asyncio
import json
import logging
import traceback
from datetime import datetime
from typing import Optional, Callable, Awaitable

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.models import ScanHistory, ScanLog, User
from app.routers.auth import get_current_user_optional
from app.schemas.scan_new import (
    ScanRequest, ScanResponse, ScanHistoryResponse,
    VerdictData, NetworkData, ForensicsData, 
    ContentData, AdvancedData, IntelligenceData
)
from app.services.ai_engine import phishing_predictor
from app.services.osint import collect_osint_data, get_osint_summary
from app.services.knowledge_base import knowledge_base
from app.services.response_builder import response_builder
from app.security.turnstile import verify_turnstile  # Cloudflare Turnstile
from app.services.logic_analyzer import LegitimacyChecker, get_whitelist_brand  # Absolute immunity (whitelist)
from app.services.deep_scan import deep_scanner
from app.services.cert_monitor import check_realtime_threat  # Zero-Day Detection
from app.services.chat_agent import analyze_url_god_mode, is_god_mode_available, is_quota_exceeded  # God Mode AI
from app.services.vision_scanner import scan_url_vision, is_vision_scanner_available  # Vision Scanner
from app.services.graph_builder import build_threat_graph  # SOC: Threat Graph
from app.services.yara_scanner import scan_content_with_yara  # SOC: YARA Scanner
from app.services.report_generator import generate_abuse_report  # SOC: Takedown Report
from app.services.kit_detector import KitDetector  # Phishing Kit Fingerprinting
from app.services.geoip_locator import get_geolocation
from app.services.uncertainty import apply_uncertainty_to_verdict  # Enterprise: Conformal abstain
from app.utils.stix import generate_stix_bundle  # Enterprise: STIX 2.1 export
from app.services.cloaking_detector import detect_cloaking  # Enterprise: Multi-vantage cloaking
from app.routers.websocket import live_map_manager
from fastapi.concurrency import run_in_threadpool

logger = logging.getLogger(__name__)


def _client_ip(request: Request) -> Optional[str]:
    """Get client IP (supports X-Forwarded-For behind proxy)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.strip().split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


async def _broadcast_scan_event(
    request: Request,
    osint_dict: Optional[dict],
    is_phishing: bool,
) -> None:
    """Fire-and-forget: broadcast scan event to Live Map WebSocket clients."""
    try:
        target_lat = osint_dict.get("lat") if osint_dict else None
        target_lon = osint_dict.get("lon") if osint_dict else None
        if target_lat is None or target_lon is None:
            return
        source_lat, source_lon = None, None
        client_ip = _client_ip(request)
        if client_ip and not client_ip.startswith("127.") and client_ip != "::1":
            geo = await run_in_threadpool(get_geolocation, client_ip)
            if geo.get("lat") is not None and geo.get("lon") is not None:
                source_lat, source_lon = geo["lat"], geo["lon"]
        payload = {
            "source": {"lat": source_lat, "lon": source_lon},
            "target": {"lat": target_lat, "lon": target_lon},
            "type": "PHISHING" if is_phishing else "SAFE",
        }
        await live_map_manager.broadcast(payload)
    except Exception as e:
        logger.debug("[LiveMap] Broadcast skipped or failed: %s", e)

router = APIRouter()


def determine_threat_type(is_phishing: bool, confidence: float, url: str) -> Optional[str]:
    """Determine threat type based on URL patterns"""
    if not is_phishing:
        return None
    
    url_lower = url.lower()
    
    # Check for specific threat patterns
    if any(keyword in url_lower for keyword in ['login', 'signin', 'account', 'verify', 'update']):
        return "credential_theft"
    elif any(keyword in url_lower for keyword in ['download', 'install', 'exe', 'apk']):
        return "malware"
    elif any(keyword in url_lower for keyword in ['prize', 'win', 'claim', 'gift']):
        return "scam"
    elif any(keyword in url_lower for keyword in ['bank', 'paypal', 'payment']):
        return "financial_fraud"
    else:
        return "phishing"


@router.post("", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def scan_url(
    scan_request: ScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional["User"] = Depends(get_current_user_optional),
):
    """
    Scan a URL for phishing detection (Protected by Cloudflare Turnstile)
    
    RELIABILITY FEATURES:
    - Semaphore: Max 3 concurrent scans (503 if busy)
    - Timeout: 60 second hard limit (408 if exceeded)
    - Error Boundary: Clean JSON error on any failure
    """
    
    # ============================================================
    # CONCURRENCY CONTROL: Fail fast if server is overloaded
    # ============================================================
    semaphore = request.app.state.scan_semaphore
    timeout = request.app.state.scan_timeout
    
    # Check if semaphore is locked (all 3 slots taken)
    if semaphore.locked():
        logger.warning(f"[THROTTLE] Server busy, rejecting scan: {scan_request.url}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server busy, please try again in a few seconds"
        )
    
    # ============================================================
    # VERIFY TURNSTILE ONCE (no Depends — token is one-time-use)
    # ============================================================
    try:
        await verify_turnstile(request)
    except HTTPException:
        raise
    
    # ============================================================
    # ACQUIRE SEMAPHORE + TIMEOUT WRAPPER
    # ============================================================
    try:
        async with semaphore:
            # Wrap entire scan in timeout
            try:
                result = await asyncio.wait_for(
                    _perform_scan(scan_request, request, db, user_id=current_user.id if current_user else None),
                    timeout=timeout
                )
                return result
            except asyncio.TimeoutError:
                logger.error(f"[TIMEOUT] Scan exceeded {timeout}s: {scan_request.url}")
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail=f"Scan timed out after {int(timeout)} seconds"
                )
    except HTTPException:
        raise
    except Exception as e:
        # Global error boundary
        logger.error(f"[FATAL] Scan crashed: {e}\n{traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan failed due to internal error"
        )


@router.post("/stream")
async def scan_url_stream(
    scan_request: ScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Scan a URL with NDJSON streaming: log lines first, then final result.
    All failures (Turnstile, timeout, crash) are yielded as {"type": "error", "message": "..."}
    so we never raise after the response has started.
    """
    semaphore = request.app.state.scan_semaphore
    timeout = request.app.state.scan_timeout
    if semaphore.locked():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server busy, please try again in a few seconds",
        )

    async def event_generator():
        try:
            # 1. Turnstile check inside generator – if it fails, we yield error instead of raising
            await verify_turnstile(request)
            yield json.dumps({"type": "log", "message": "🚀 Captcha verified. Starting scan..."}) + "\n"
        except HTTPException as e:
            if isinstance(e.detail, str):
                error_msg = e.detail
            elif isinstance(e.detail, dict):
                error_msg = e.detail.get("message", e.detail.get("detail", str(e.detail)))
            else:
                error_msg = str(e.detail)
            yield json.dumps({"type": "error", "message": error_msg}) + "\n"
            return
        except Exception as e:
            logger.exception("Stream: Turnstile/early error: %s", e)
            yield json.dumps({"type": "error", "message": "Security verification failed."}) + "\n"
            return

        async with semaphore:
            queue = asyncio.Queue()
            async def log_cb(msg: str) -> None:
                await queue.put(("log", msg))

            async def run_scan() -> None:
                try:
                    result = await asyncio.wait_for(
                        _perform_scan(
                            scan_request, request, db,
                            log_callback=log_cb,
                            user_id=current_user.id if current_user else None,
                        ),
                        timeout=timeout,
                    )
                    await queue.put(("result", result))
                except asyncio.TimeoutError:
                    await queue.put(("error", "Scan timed out."))
                except HTTPException as e:
                    error_msg = e.detail if isinstance(e.detail, str) else str(e.detail)
                    await queue.put(("error", error_msg))
                except Exception as e:
                    logger.exception("Stream: scan error: %s", e)
                    await queue.put(("error", "Internal server error during scan."))

            task = asyncio.create_task(run_scan())
            try:
                while True:
                    item = await queue.get()
                    if item[0] == "log":
                        yield json.dumps({"type": "log", "message": item[1]}) + "\n"
                    elif item[0] == "result":
                        res = item[1]
                        if hasattr(res, "model_dump"):
                            data = res.model_dump(mode="json")
                        elif hasattr(res, "dict"):
                            data = res.dict()
                        else:
                            data = res
                        yield json.dumps({"type": "result", "data": data}) + "\n"
                        break
                    elif item[0] == "error":
                        yield json.dumps({"type": "error", "message": item[1]}) + "\n"
                        break
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    return StreamingResponse(
        event_generator(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store"},
    )


async def _perform_scan(
    scan_request: ScanRequest,
    request: Request,
    db: AsyncSession,
    *,
    log_callback: Optional[Callable[[str], Awaitable[None]]] = None,
    user_id: Optional[int] = None,
) -> ScanResponse:
    """
    Internal scan implementation (wrapped by semaphore + timeout).
    Optional log_callback(msg) is awaited to stream progress (e.g. NDJSON).
    """
    async def _log(msg: str) -> None:
        if log_callback:
            await log_callback(msg)

    # Turnstile is verified once by the caller (stream generator or scan_url), not here.

    # ============================================================
    # STEP 1: ZERO-DAY DETECTION (CertStream Real-time Check)
    # ============================================================
    url_str = str(scan_request.url)
    await _log("[*] Checking zero-day / CertStream...")
    if check_realtime_threat(url_str):
        logger.warning(f"[ZERO-DAY] Real-time threat detected: {url_str}")
        
        # Immediate PHISHING verdict without AI analysis
        zero_day_response = response_builder.build_response(
            url=url_str,
            final_url=url_str,
            is_phishing=True,
            confidence_score=100.0,
            threat_type="zero_day_phishing",
            model_version="certstream_realtime",
            deep_scan=None,
            osint=None,
            network=None,
            similar_threats=[{
                "source": "CertStream",
                "reason": "Domain registered very recently with suspicious patterns",
                "similarity_score": 1.0
            }],
            typo_result={"risk": True, "reason": "Real-time certificate monitoring detected this domain"},
            redirect_result=None,
            ai_analysis={
                "verdict": "PHISHING",
                "risk_score": 100,
                "summary": "ZERO-DAY THREAT: This domain was registered very recently and matches known phishing patterns. It was caught in real-time by our Certificate Transparency monitoring system.",
                "impersonation_target": None,
                "risk_factors": [
                    "Recently registered domain",
                    "Matches suspicious keyword patterns",
                    "Detected via real-time certificate monitoring"
                ],
                "technical_analysis": {
                    "url_integrity": "Spoofed",
                    "domain_age": "New (Zero-Day)"
                },
                "recommendation": "DO NOT VISIT THIS SITE. This is a freshly registered phishing domain."
            }
        )
        
        await _log("[!] Zero-day threat detected (CertStream).")
        return zero_day_response

    await _log("[+] Zero-day check clear.")
    # ============================================================
    # STEP 2: REDIRECT TRACE & ANALYSIS PREP
    # ============================================================
    logger.debug(f"[2/4] Starting analysis for: {scan_request.url}")
    await _log("[*] Tracing redirect chain...")
    try:
        url_str = str(scan_request.url)
        redirect_res = await run_in_threadpool(deep_scanner.trace_redirects, url_str)
        final_url = redirect_res.get('final_url', url_str)
        await _log(f"[+] Final URL: {final_url[:60]}{'...' if len(final_url) > 60 else ''}")
        
        if final_url != url_str:
            logger.debug(f"[Redirect] Followed chain: {url_str} -> {final_url}")
            if redirect_res.get('is_open_redirect'):
                logger.warning(f"[RISK] Open Redirect Abuse detected: {url_str}")

        # Initialize results & flags explicitly to prevent UnboundLocalError
        deep_scan_results = None
        network_results = None
        is_phishing = False
        confidence_score = 0.0
        threat_type = None
        similar_threats = None
        typo_result = {'risk': False}  # Default safe

        # STEP 0: Absolute Immunity - if URL is in official whitelist, do not run evasion/risk overrides later
        immune_brand = get_whitelist_brand(final_url)
        immunity_granted = immune_brand is not None
        if immunity_granted:
            await _log(f"[+] Whitelisted: {immune_brand} (immunity granted).")
            logger.info(f"[Immunity] {final_url} is official domain for {immune_brand}")
        
        await _log("[*] Checking PhishTank / RAG database...")
        # [NEW] 1.5.1 PhishTank Local Exact Match (Fail Fast)
        pt_result = knowledge_base.check_known_phish(final_url)
        if pt_result['match']:
             await _log("[!] PhishTank local block: known phishing URL.")
             logger.warning(f"[FAIL-FAST] PhishTank Local Block: {final_url}")
             is_phishing = True
             confidence_score = 100.0
             threat_type = "phishing (known)"
             
             # Create a synthetic Deep Scan result
             deep_scan_results = deep_scanner.scan(url_str, existing_redirects=redirect_res)
             
        # [NEW] 1.5.2 Google Safe Browsing Check (Primary Validation)
        if not is_phishing:
            await _log("[*] Checking Google Safe Browsing...")
            from app.services.external_intel import external_intel
            gsb_result = await run_in_threadpool(external_intel.check_google_safe_browsing, final_url)
            if not gsb_result['safe']:
                 await _log("[!] Google Safe Browsing: threat matched.")
                 logger.warning(f"[FAIL-FAST] Google Safe Browsing Block: {final_url}")
                 is_phishing = True
                 confidence_score = 100.0
                 threat_type = "malware" if "MALWARE" in str(gsb_result['matches']) else "phishing"
                 
                 deep_scan_results = deep_scanner.scan(url_str, existing_redirects=redirect_res)
             
        if not is_phishing:
            await _log("[+] Safe Browsing check passed.")
            # [NEW] 2. Semantic RAG Search using ChromaDB (on Final URL)
            await _log("[*] RAG similarity search...")
            similar_threats = knowledge_base.search_similar_threats(final_url)
            if similar_threats:
                logger.debug(f"[RAG] Found {len(similar_threats)} similar threats")
                await _log(f"[+] RAG: {len(similar_threats)} similar threat(s) found.")
            # [NEW] 3. Pre-AI Typosquatting Check (Fail Fast) (on Final URL)
            await _log("[*] Typosquatting / homograph check...")
            typo_result = deep_scanner.check_typosquatting(final_url)
        
        # Initialize results
        deep_scan_results = None
        network_results = None
        
        # FAIL FAST LOGIC (Typosquatting)
        # Note: If GSB already flagged it, we skip this block or it doesn't matter (is_phishing already true)
        if not is_phishing and typo_result.get('risk'):
            await _log("[!] Typosquatting detected.")
            logger.warning(f"[FAIL-FAST] Typosquatting detected on final URL: {typo_result}")
            is_phishing = True
            confidence_score = 100.0
            threat_type = "impersonation"
            
            # Create a synthetic Deep Scan result that includes the redirect info
            deep_scan_results = deep_scanner.scan(url_str, existing_redirects=redirect_res)
            
        elif not is_phishing:
            await _log("[+] No typosquatting.")
            # ============================================================
            # PARALLEL EXECUTION: Run Network + AI + DeepScan simultaneously
            # ============================================================
            await _log("[*] Running Network + ML + Deep Scan (parallel)...")
            from app.services.network_forensics import network_forensics
            async def _run_network():
                try:
                    return await run_in_threadpool(network_forensics.analyze, final_url)
                except Exception as e:
                    logger.error(f"Network forensics failed: {e}")
                    return None
            
            async def _run_ai_prediction():
                try:
                    return await run_in_threadpool(phishing_predictor.predict, final_url)
                except Exception as e:
                    logger.error(f"AI prediction failed: {e}")
                    return {'is_phishing': False, 'confidence_score': 0.0}
            
            async def _run_deep_scan():
                if scan_request.deep_analysis:
                    try:
                        return await run_in_threadpool(
                            deep_scanner.scan, 
                            url_str, 
                            existing_redirects=redirect_res
                        )
                    except Exception as e:
                        logger.error(f"Deep Analysis failed: {e}")
                        return None
                return None
            
            logger.debug("[PARALLEL] Running Network + AI + DeepScan simultaneously...")
            network_results, prediction_result, deep_scan_results = await asyncio.gather(
                _run_network(),
                _run_ai_prediction(),
                _run_deep_scan()
            )
            
            # Process AI prediction result
            is_phishing = prediction_result['is_phishing']
            confidence_score = prediction_result['confidence_score']
            threat_type = determine_threat_type(is_phishing, confidence_score, final_url)
            
            await _log("[+] Network, ML, and Deep Scan completed.")
            if network_results:
                logger.debug(f"[Network] Trust Score: {network_results['network_trust_score']}")
            if deep_scan_results:
                logger.debug(f"[DeepScan] Technical Risk Score: {deep_scan_results.get('technical_risk_score', 0)}")
            # Adjust confidence based on Network Score
            if network_results and network_results['network_trust_score'] < 30:
                 if not is_phishing:
                     logger.warning("[Override] Low Network Trust -> Flagging as Phishing")
                     is_phishing = True
                     confidence_score = max(confidence_score, 85.0)
            
            # Boost if Open Redirect + Suspicious Final
            if redirect_res.get('is_open_redirect'):
                confidence_score = max(confidence_score, 90.0)
                is_phishing = True
                threat_type = "open_redirect_abuse"
        
        # Log verdict (WARNING for phishing, DEBUG for safe)
        if is_phishing:
            logger.warning(f"[PHISHING] {final_url} (Confidence: {confidence_score:.1f}%)")
        else:
            logger.debug(f"[SAFE] {final_url} (Confidence: {confidence_score:.1f}%)")
        
        # ============================================================
        # PARALLEL EXECUTION PHASE 2: OSINT + Vision Scanner
        # ============================================================
        await _log("[*] Running OSINT + Vision Scanner...")
        osint_dict = None
        vision_result = None
        async def _run_osint():
            if scan_request.include_osint:
                try:
                    osint_full = await run_in_threadpool(collect_osint_data, final_url)
                    return get_osint_summary(osint_full)
                except Exception as e:
                    logger.warning(f"Failed to collect OSINT data: {e}")
                    return None
            return None
        
        async def _run_vision():
            if is_vision_scanner_available() and scan_request.deep_analysis:
                try:
                    result = await scan_url_vision(final_url)
                    # Null safety
                    if not result or not isinstance(result, dict):
                        return {'evasion': {}, 'connections': {}, 'error': 'Scanner returned invalid result'}
                    return result
                except Exception as e:
                    logger.error(f"Vision Scanner failed: {e}")
                    return None
            return None
        
        osint_dict, vision_result = await asyncio.gather(
            _run_osint(),
            _run_vision()
        )
        await _log("[+] OSINT and Vision scan completed.")
        if osint_dict:
            logger.debug(f"[OK] OSINT data collected")
        
        # Process Vision results (skip evasion boost when immunity granted)
        if vision_result:
            evasion = vision_result.get('evasion') or {}
            connections = vision_result.get('connections') or {}
            logger.debug(f"[VisionScan] Evasion detected: {evasion.get('evasion_detected', False)}")
            logger.debug(f"[VisionScan] External domains: {len(connections.get('external_domains', []))}")
            if immunity_granted:
                # Clear evasion for response so UI does not show "Evasion Detected" for whitelisted sites
                if isinstance(vision_result.get('evasion'), dict):
                    vision_result = dict(vision_result)
                    vision_result['evasion'] = dict(vision_result['evasion'])
                    vision_result['evasion']['evasion_detected'] = False
            else:
                # Boost confidence if evasion techniques detected
                if evasion.get('evasion_detected'):
                    if not is_phishing:
                        logger.warning("[VISION OVERRIDE] Evasion techniques detected")
                        is_phishing = True
                        confidence_score = max(confidence_score, 80)
                        threat_type = "evasion_detected"
                    else:
                        confidence_score = min(confidence_score + 10, 100)
                if connections.get('suspicious_ips'):
                    logger.warning(f"[VisionScan] Suspicious IP connections detected")
                    confidence_score = min(confidence_score + 15, 100)
        
        # ============================================================
        # PHISHING KIT FINGERPRINTING (HTML + URL path signatures)
        # ============================================================
        kit_result = None
        if deep_scan_results and deep_scan_results.get('raw_html'):
            await _log("[*] Scanning for phishing kit signatures (Z118/16Shop/etc.)...")
            try:
                kit_result = await run_in_threadpool(
                    KitDetector.detect,
                    deep_scan_results['raw_html'],
                    final_url,
                )
                if kit_result and kit_result.get('detected') and not immunity_granted:
                    await _log(f"[!] Phishing kit detected: {kit_result.get('kit_name')}.")
                    logger.warning(f"[KitDetector] Phishing kit: {kit_result.get('kit_name')} ({kit_result.get('confidence')})")
                    if not is_phishing:
                        is_phishing = True
                        confidence_score = max(confidence_score, 80)
                        threat_type = threat_type or "phishing_kit_detected"
                    else:
                        confidence_score = min(confidence_score + 10, 100)
            except Exception as e:
                logger.error(f"Kit Detector failed: {e}")
                kit_result = None

        # ============================================================
        # GOD MODE AI ANALYSIS (needs OSINT data, runs after)
        # ============================================================
        god_mode_result = None
        if is_god_mode_available():
            await _log("[*] Initializing God Mode AI...")
            try:
                logger.debug("[3.7/4] Running God Mode AI Analysis...")
                
                # Prepare context for God Mode analysis (include kit fingerprint for AI)
                dom_text = None
                deep_tech_data = deep_scan_results if deep_scan_results else {}
                if isinstance(deep_tech_data, dict):
                    deep_tech_data = dict(deep_tech_data)
                if osint_dict:
                    deep_tech_data['osint'] = osint_dict
                if network_results:
                    deep_tech_data['network'] = network_results
                if kit_result:
                    deep_tech_data['phishing_kit'] = kit_result
                
                god_mode_result = await run_in_threadpool(
                    analyze_url_god_mode,
                    final_url,
                    dom_text,
                    deep_tech_data,
                    similar_threats,
                    scan_request.language or "en",
                )
                
                await _log(f"[+] God Mode verdict: {god_mode_result.get('verdict', 'UNKNOWN')}.")
                logger.debug(f"[GOD MODE] Verdict: {god_mode_result.get('verdict', 'UNKNOWN')}")
                # Override verdict if God Mode detects PHISHING but ML said SAFE
                if god_mode_result.get('verdict') == 'PHISHING' and not is_phishing:
                    logger.warning("[GOD MODE OVERRIDE] AI detected phishing, overriding ML verdict")
                    is_phishing = True
                    confidence_score = max(confidence_score, god_mode_result.get('risk_score', 85))
                    threat_type = "ai_detected_phishing"
                
                # Boost confidence if both agree on phishing
                elif god_mode_result.get('verdict') == 'PHISHING' and is_phishing:
                    confidence_score = max(confidence_score, god_mode_result.get('risk_score', confidence_score))
                
            except Exception as e:
                logger.error(f"God Mode Analysis failed: {e}")
                god_mode_result = None
        
        # ============================================================
        # LEGITIMACY / ABSOLUTE IMMUNITY: Whitelisted URL -> SAFE, score 0, clear evasion
        # ============================================================
        official_site_override = None
        if immunity_granted and immune_brand:
            is_phishing = False
            confidence_score = 0.0
            threat_type = None
            official_site_override = {
                "brand": immune_brand,
                "summary": f"Verified official website of {immune_brand}. (Authorized domain)",
            }
            if god_mode_result:
                god_mode_result = dict(god_mode_result)
                god_mode_result["verdict"] = "SAFE"
                god_mode_result["risk_score"] = 0
                god_mode_result["impersonation_target"] = None
                god_mode_result["summary"] = official_site_override["summary"]
            logger.info(f"[Immunity] Forcing SAFE for whitelisted {immune_brand}")
        else:
            detected_brand = None
            if god_mode_result:
                detected_brand = god_mode_result.get("impersonation_target") or god_mode_result.get("brand_impersonated")
            if detected_brand and (str(detected_brand).strip() or "").lower() not in ("none", ""):
                if LegitimacyChecker.is_authorized(final_url, detected_brand):
                    logger.info(f"[LegitimacyChecker] Overriding verdict: {final_url} is official {detected_brand}")
                    is_phishing = False
                    confidence_score = 0.0
                    threat_type = None
                    official_site_override = {
                        "brand": detected_brand,
                        "summary": f"Verified official website of {detected_brand}.",
                    }
                    if god_mode_result:
                        god_mode_result = dict(god_mode_result)
                        god_mode_result["verdict"] = "SAFE"
                        god_mode_result["risk_score"] = 0
                        god_mode_result["impersonation_target"] = None
                        god_mode_result["summary"] = official_site_override["summary"]
        
        # ============================================================
        # STEP 3.9: SOC PLATFORM FEATURES
        # ============================================================
        await _log("[*] Building threat graph...")
        threat_graph = None
        yara_result = None
        abuse_report = None
        try:
            logger.debug("[3.9/4] Building Threat Graph...")
            
            # Extract redirect chain from deep_scan_results
            redirect_chain = None
            if deep_scan_results:
                details = deep_scan_results.get('details', {})  
                redirects = details.get('redirects', {})
                redirect_chain = redirects.get('chain', [final_url])
            
            threat_graph = await run_in_threadpool(
                build_threat_graph,
                final_url,
                redirect_chain,           # Redirect chain URLs
                osint_dict or {},         # DNS/OSINT data (IP, ASN, registrar)
                deep_scan_results or {},  # Technical analysis data
                is_phishing,              # Is phishing flag
                confidence_score          # Confidence score
            )
            await _log("[+] Threat graph built.")
            logger.debug(f"[ThreatGraph] Nodes: {len(threat_graph.get('nodes', []))}, Edges: {len(threat_graph.get('edges', []))}")
        except Exception as e:
            logger.error(f"Threat Graph failed: {e}")
        try:
            if deep_scan_results and deep_scan_results.get('raw_html'):
                await _log("[*] Running YARA pattern match...")
                logger.debug("[3.9/4] Running YARA Scanner...")
                yara_result = await run_in_threadpool(
                    scan_content_with_yara,
                    deep_scan_results['raw_html']
                )
                
                if yara_result.get('triggered_rules'):
                    logger.warning(f"[YARA] Matches: {yara_result['triggered_rules']}")
                    # Boost confidence if malicious patterns found
                    if not is_phishing and len(yara_result['triggered_rules']) >= 2:
                        is_phishing = True
                        confidence_score = max(confidence_score, 85)
                        threat_type = "yara_detected"
                    elif is_phishing:
                        confidence_score = min(confidence_score + 10, 100)
        except Exception as e:
            logger.error(f"YARA Scanner failed: {e}")
        
        if is_phishing and confidence_score >= 75:
            await _log("[*] Generating abuse report...")
            try:
                logger.debug("[3.9/4] Generating Abuse Report...")
                abuse_report = await run_in_threadpool(
                    generate_abuse_report,
                    final_url,
                    {
                        'verdict': {'is_phishing': is_phishing, 'confidence_score': confidence_score, 'threat_type': threat_type},
                        'god_mode_analysis': god_mode_result,
                        'yara_analysis': yara_result,
                        'vision_analysis': vision_result,
                        'forensics': {'redirect_chain': redirect_res.get('chain', [])},
                        'rag_matches': similar_threats
                    },
                    osint_dict
                )
                logger.debug(f"[AbuseReport] Generated: {abuse_report.get('report_id')}")
            except Exception as e:
                logger.error(f"Abuse Report generation failed: {e}")
        
        # ============================================================
        # ENTERPRISE: Conformal uncertainty, STIX export, cloaking
        # ============================================================
        abstain, suggested_level, credibility_interval, _ = apply_uncertainty_to_verdict(is_phishing, confidence_score)
        stix_bundle = generate_stix_bundle(url_str, suggested_level, confidence_score, threat_type)
        cloaking_result = None
        if scan_request.deep_analysis:
            try:
                await _log("[*] Checking for cloaking (bot vs user content)...")
                cloaking_result = await run_in_threadpool(detect_cloaking, final_url)
                if cloaking_result.get("cloaking_detected"):
                    await _log("[!] Cloaking detected.")
            except Exception as e:
                logger.warning(f"Cloaking check failed: {e}")
        
        # ============================================================
        # STEP 4: SAVE TO DATABASE & BUILD RESPONSE
        # ============================================================
        await _log("[*] Saving result and building response...")
        logger.debug("[4/4] Saving scan result to database...")
        # Save to database
        scan_record = ScanHistory(
            url=url_str,
            is_phishing=is_phishing,
            confidence_score=round(confidence_score, 2),
            threat_type=threat_type,
            scanned_at=datetime.utcnow(),
            user_id=None
        )
        
        db.add(scan_record)
        await db.commit()
        await db.refresh(scan_record)
        
        await _log("[+] Scan complete.")
        logger.debug(f"Scan result saved (ID: {scan_record.id})")
        # Build complete response using ResponseBuilder with deep analysis
        response_data = response_builder.build_complete_response(
            scan_id=scan_record.id,
            url=url_str,
            scanned_at=scan_record.scanned_at,
            is_phishing=is_phishing,
            confidence_score=confidence_score,
            threat_type=threat_type,
            osint_data=osint_dict,
            deep_analysis=scan_request.deep_analysis,
            deep_scan_results=deep_scan_results,
            rag_results=similar_threats,
            language=scan_request.language,
            god_mode_result=god_mode_result,  # God Mode AI Analysis result
            vision_result=vision_result,  # Vision Scanner result
            threat_graph=threat_graph,  # SOC: Threat Graph
            yara_result=yara_result,  # SOC: YARA Analysis
            abuse_report=abuse_report,  # SOC: Takedown Report
            kit_result=kit_result,  # Phishing Kit Fingerprinting
            official_site_override=official_site_override,  # LegitimacyChecker: verified official domain
            uncertainty_abstain=abstain,
            credibility_interval=credibility_interval,
            stix_bundle=stix_bundle,
            cloaking_result=cloaking_result,
        )
        
        # Live Map: broadcast scan event (source -> target) to WebSocket clients
        asyncio.create_task(_broadcast_scan_event(request, osint_dict, is_phishing))

        # Save to ScanLog for share link and analytics
        verdict_level = (response_data.get("verdict") or {}).get("level") or ("PHISHING" if is_phishing else "SAFE")
        verdict_score = float((response_data.get("verdict") or {}).get("score") or confidence_score)
        scan_log = ScanLog(
            user_id=user_id,
            url=url_str,
            verdict=verdict_level,
            score=verdict_score,
            timestamp=scan_record.scanned_at,
            full_result_json=json.dumps(response_data, default=str),
        )
        db.add(scan_log)
        await db.commit()
        await db.refresh(scan_log)
        response_data["share_id"] = scan_log.id

        # Cache full result for PDF report download
        cache = getattr(request.app.state, "scan_result_cache", None)
        if cache is not None:
            cache[scan_record.id] = response_data
            if len(cache) > 100:
                oldest = next(iter(cache))
                del cache[oldest]

        return ScanResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning URL: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to scan URL: {str(e)}"
        )


@router.get("/history", response_model=ScanHistoryResponse)
async def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan history
    
    - **limit**: Maximum number of results (default: 50, max: 100)
    - **offset**: Number of results to skip (default: 0)
    """
    
    # Validate parameters
    if limit > 100:
        limit = 100
    if offset < 0:
        offset = 0
    
    try:
        # Get total count
        count_query = select(ScanHistory)
        result = await db.execute(count_query)
        total = len(result.scalars().all())
        
        # Get paginated results
        query = select(ScanHistory).order_by(desc(ScanHistory.scanned_at)).limit(limit).offset(offset)
        result = await db.execute(query)
        scans = result.scalars().all()
        
        logger.info(f"Retrieved {len(scans)} scan records (offset: {offset}, limit: {limit})")
        
        # Reconstruct ScanResponse from sparse DB data
        # Note: DB only stores minimal info, so we fill rest with defaults
        response_list = []
        for scan in scans:
            # Reconstruct basic hierarchy
            verdict = {
               "score": int(scan.confidence_score) if scan.is_phishing else int(100 - scan.confidence_score),
               "level": "CRITICAL" if scan.confidence_score > 90 and scan.is_phishing else "HIGH" if scan.is_phishing else "SAFE",
               "target_brand": None,
               "threat_type": scan.threat_type,
               "risk_factors": [],
               "ai_conclusion": None
            }
            # Fill dummy data for required fields
            scan_obj = ScanResponse(
                id=scan.id,
                url=scan.url,
                scanned_at=scan.scanned_at,
                verdict=VerdictData(**verdict),
                network=NetworkData(domain_age=None),
                forensics=ForensicsData(),
                content=ContentData(),
                advanced=AdvancedData(),
                intelligence=IntelligenceData()
            )
            response_list.append(scan_obj)

        return ScanHistoryResponse(
            total=total,
            scans=response_list
        )
        
    except Exception as e:
        logger.error(f"Error retrieving scan history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan history"
        )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_by_id(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get specific scan result by ID"""
    
    try:
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        # Reconstruct from DB (Similar to history)
        verdict = {
            "score": int(scan.confidence_score) if scan.is_phishing else int(100 - scan.confidence_score),
            "level": "CRITICAL" if scan.confidence_score > 90 and scan.is_phishing else "HIGH" if scan.is_phishing else "SAFE",
            "target_brand": None,
            "threat_type": scan.threat_type,
            "risk_factors": [],
            "ai_conclusion": None
        }
        
        return ScanResponse(
            id=scan.id,
            url=scan.url,
            scanned_at=scan.scanned_at,
            verdict=VerdictData(**verdict),
            network=NetworkData(domain_age=None),
            forensics=ForensicsData(),
            content=ContentData(),
            advanced=AdvancedData(),
            intelligence=IntelligenceData()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving scan {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan"
        )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete a scan record"""
    
    try:
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        await db.delete(scan)
        await db.commit()
        
        logger.info(f"Deleted scan record {scan_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete scan"
        )
