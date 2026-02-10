"""
Conformal Prediction / Uncertainty Quantification.
If prediction probability is in the uncertainty band (e.g. 0.4–0.7), verdict becomes UNCERTAIN (abstain).
"""
import logging
from typing import Tuple, List

logger = logging.getLogger(__name__)

# Probability band: inside this range the model must abstain (human review)
UNCERTAINTY_BAND_LOW = 0.40   # 40%
UNCERTAINTY_BAND_HIGH = 0.70  # 70%
# Credibility interval half-width (e.g. ±15% -> interval width 30%)
CREDIBILITY_MARGIN = 0.15


def apply_conformal(
    probability: float,
    is_phishing: bool,
    score_0_100: float,
) -> Tuple[bool, str, List[float]]:
    """
    Apply simple inductive conformal logic: abstain if in uncertainty band.

    Args:
        probability: P(phishing) in [0, 1].
        is_phishing: Model prediction (True = phishing).
        score_0_100: Risk score 0–100 (for display).

    Returns:
        (abstain, suggested_level, credibility_interval)
        - abstain: True if we should show UNCERTAIN / human review.
        - suggested_level: "UNCERTAIN" if abstain, else "PHISHING" or "SAFE".
        - credibility_interval: [low, high] in 0–100 scale (for UI).
    """
    in_band = UNCERTAINTY_BAND_LOW <= probability <= UNCERTAINTY_BAND_HIGH
    abstain = in_band

    low = max(0.0, (probability - CREDIBILITY_MARGIN) * 100)
    high = min(100.0, (probability + CREDIBILITY_MARGIN) * 100)
    interval = [round(low, 1), round(high, 1)]
    interval_width = high - low

    # If interval is too wide, also abstain (high epistemic uncertainty)
    if interval_width > 40.0:
        abstain = True

    if abstain:
        suggested_level = "UNCERTAIN"
        logger.info(f"[Uncertainty] Abstain: prob={probability:.2f} in band, interval=[{low:.1f}, {high:.1f}]")
    else:
        suggested_level = "PHISHING" if is_phishing else "SAFE"

    return abstain, suggested_level, interval


def apply_uncertainty_to_verdict(
    is_phishing: bool,
    confidence_score: float,
) -> Tuple[bool, str, List[float], bool]:
    """
    Convenience: take current verdict and score, return abstain flag and interval.
    confidence_score is 0–100 (phishing confidence when is_phishing, else safe confidence).

    Returns:
        (abstain, suggested_level, credibility_interval, is_uncertain)
    """
    # As probability of "phishing" in [0,1]
    if is_phishing:
        prob = confidence_score / 100.0
    else:
        prob = 1.0 - (confidence_score / 100.0)
    abstain, suggested_level, interval = apply_conformal(prob, is_phishing, confidence_score)
    return abstain, suggested_level, interval, abstain
