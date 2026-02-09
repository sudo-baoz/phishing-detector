"""
Phishing Detector - Community Feedback Loop (False Positive / False Negative)
Copyright (c) 2026 BaoZ

Strict privacy: no email, name, or IP stored. Data used solely for ML retraining.
"""

import csv
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter()

# Paths: community feedback CSV (no PII)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATASETS_DIR = PROJECT_ROOT / "datasets"
USER_FEEDBACK_CSV = DATASETS_DIR / "user_feedback.csv"
TRAIN_COUNT_FILE = DATASETS_DIR / ".feedback_train_count"
TRIGGER_EVERY = 100


class FeedbackSchema(BaseModel):
    url: str
    predicted_verdict: Literal["SAFE", "PHISHING"]
    user_correction: Literal["SAFE", "PHISHING"]
    reason: Optional[str] = Field(default=None, max_length=200)


def _sanitize_reason(text: Optional[str]) -> str:
    """Remove HTML tags and limit length to prevent XSS/injection."""
    if not text or not isinstance(text, str):
        return ""
    # Strip HTML tags
    clean = re.sub(r"<[^>]+>", "", text)
    # Normalize whitespace
    clean = " ".join(clean.split())
    return clean[:200]


def _ensure_datasets_dir():
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)


def _ensure_feedback_csv_header():
    if not USER_FEEDBACK_CSV.exists():
        with open(USER_FEEDBACK_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "url", "predicted", "user_label", "reason"])


def _append_feedback(
    url: str,
    predicted: str,
    user_label: str,
    reason: str,
) -> int:
    _ensure_datasets_dir()
    _ensure_feedback_csv_header()
    ts = datetime.now(timezone.utc).isoformat()
    with open(USER_FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([ts, url, predicted, user_label, reason])
    with open(USER_FEEDBACK_CSV, "r", encoding="utf-8") as f:
        line_count = sum(1 for _ in f) - 1
    return max(0, line_count)


def _get_last_train_count() -> int:
    if not TRAIN_COUNT_FILE.exists():
        return 0
    try:
        return int(TRAIN_COUNT_FILE.read_text().strip())
    except Exception:
        return 0


def _set_last_train_count(count: int):
    _ensure_datasets_dir()
    TRAIN_COUNT_FILE.write_text(str(count))


def _train_model() -> None:
    """Mock retraining. Replace with actual model training (e.g. scripts/model_train.py)."""
    print("🚀 Retraining model with new data... Done.")


@router.post("")
async def submit_feedback(body: FeedbackSchema):
    """
    Submit community feedback (false positive / false negative).
    Appends to datasets/user_feedback.csv. No PII stored.
    When total entries grow by 100, triggers a background retrain (mock).
    """
    try:
        reason = _sanitize_reason(body.reason)
        count = _append_feedback(
            url=body.url,
            predicted=body.predicted_verdict,
            user_label=body.user_correction,
            reason=reason,
        )
        last_triggered = _get_last_train_count()
        if count >= last_triggered + TRIGGER_EVERY:
            _set_last_train_count(count)
            try:
                _train_model()
            except Exception as e:
                logger.exception("Retrain task failed: %s", e)
            return {
                "status": "ok",
                "message": "Thanks! Our AI will learn from this. Retraining triggered (100 new entries).",
                "total_entries": count,
            }
        return {
            "status": "ok",
            "message": "Thanks! Our AI will learn from this.",
            "total_entries": count,
        }
    except Exception as e:
        logger.exception("Feedback save failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to save feedback.")
