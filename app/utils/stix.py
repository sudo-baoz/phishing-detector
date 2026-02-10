"""
STIX 2.1 / MISP-compatible threat intel export.
Generates a STIX bundle with an indicator for the scanned URL.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict


def _stix_id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def generate_stix_bundle(
    url: str,
    verdict: str,
    score: float,
    threat_type: str | None = None,
) -> Dict[str, Any]:
    """
    Build a STIX 2.1 bundle with one indicator for the URL.

    Args:
        url: Scanned URL.
        verdict: "PHISHING" or "SAFE" or "UNCERTAIN".
        score: Risk score 0–100.
        threat_type: Optional threat type string.

    Returns:
        STIX 2.1 bundle dict (JSON-serializable).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    indicator_id = _stix_id("indicator")

    # STIX pattern: url:value (escape backslash and single quote per STIX 2.1)
    escaped = (url or "").replace("\\", "\\\\").replace("'", "\\'")
    pattern = f"[url:value = '{escaped}']"
    pattern_type = "stix"

    labels = []
    if verdict == "PHISHING":
        labels = ["phishing", "malicious"]
    elif verdict == "UNCERTAIN":
        labels = ["suspicious", "needs-review"]

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now,
        "modified": now,
        "name": f"Phishing URL: {url[:80]}{'...' if len(url) > 80 else ''}",
        "description": f"CyberSentinel scan result: {verdict} (score={score}). Threat type: {threat_type or 'N/A'}.",
        "indicator_types": ["malicious-activity"] if verdict == "PHISHING" else ["anomalous-activity"],
        "pattern": pattern,
        "pattern_type": pattern_type,
        "pattern_version": "2.1",
        "valid_from": now,
        "labels": labels,
    }

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": [indicator],
    }
    return bundle


def generate_stix_json(url: str, verdict: str, score: float, threat_type: str | None = None) -> str:
    """Return STIX bundle as JSON string for download."""
    bundle = generate_stix_bundle(url, verdict, score, threat_type)
    return json.dumps(bundle, indent=2)
