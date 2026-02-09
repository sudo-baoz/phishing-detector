"""
Phishing Detector - Attack Heatmap / GeoIP Location
Copyright (c) 2026 BaoZ

Resolves IP to geolocation (lat, lon, country) for heatmap visualization.
Uses ip-api.com (free, no key). Optional: geoip2 for offline use.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


def get_geolocation(ip_address: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Resolve IP to geolocation for heatmap/attack visualization.

    Args:
        ip_address: IPv4 or IPv6 address.
        timeout: Request timeout in seconds.

    Returns:
        {"lat": float, "lon": float, "country": str, "city": Optional[str], "error": Optional[str]}
    """
    result: Dict[str, Any] = {
        "lat": None,
        "lon": None,
        "country": None,
        "city": None,
        "region": None,
        "isp": None,
        "error": None,
    }
    if not ip_address or not (ip_address.strip()):
        result["error"] = "No IP provided"
        return result
    ip_address = ip_address.strip()
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not available"
        return result
    try:
        # ip-api.com: free, no key, 45 req/min from same IP
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,isp,lat,lon"
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "success":
            result["lat"] = data.get("lat")
            result["lon"] = data.get("lon")
            result["country"] = data.get("country")
            result["city"] = data.get("city")
            result["region"] = data.get("regionName")
            result["isp"] = data.get("isp")
        else:
            result["error"] = data.get("message", "Lookup failed")
    except Exception as e:
        logger.debug("GeoIP lookup failed for %s: %s", ip_address, e)
        result["error"] = str(e)
    return result
