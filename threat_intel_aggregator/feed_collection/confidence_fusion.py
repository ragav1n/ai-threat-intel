"""
Confidence Fusion Model.

Combines regex-based confidence scores with LLM verification confidence
using a weighted fusion approach:
    fused = weight_regex × regex_confidence + weight_llm × llm_confidence

Default weights: 0.4 × regex + 0.6 × LLM
Falls back to regex-only (1.0 × regex) when LLM is unavailable.
"""
from dataclasses import dataclass, field
from typing import Optional
import logging
import os

logger = logging.getLogger(__name__)


@dataclass
class FusionConfig:
    """Configuration for confidence fusion."""
    weight_regex: float = 0.4
    weight_llm: float = 0.6
    
    def __post_init__(self):
        """Validate weights sum to 1.0."""
        total = self.weight_regex + self.weight_llm
        if abs(total - 1.0) > 0.001:
            raise ValueError(
                f"Fusion weights must sum to 1.0, got {total:.3f} "
                f"(regex={self.weight_regex}, llm={self.weight_llm})"
            )


# Default fusion configuration
DEFAULT_FUSION_CONFIG = FusionConfig(weight_regex=0.4, weight_llm=0.6)


# ── Post-hoc confidence calibration ─────────────────────────
#
# The calibration study (scripts/run_calibration_study.py) showed the raw
# weighted fusion is miscalibrated (ECE ~0.33). An isotonic calibrator fitted
# by scripts/fit_calibrator.py corrects it (out-of-fold ECE ~0.03). If no
# fitted calibrator file is present the pipeline degrades gracefully to the
# raw fused score.
_CALIBRATOR_PATH = os.getenv(
    "CONFIDENCE_CALIBRATOR_PATH", "data/evaluation/fitted_calibrator.json"
)
_calibrator = None
_calibrator_loaded = False


def _get_calibrator():
    """Lazily load the fitted confidence calibrator (cached; None if absent)."""
    global _calibrator, _calibrator_loaded
    if not _calibrator_loaded:
        _calibrator_loaded = True
        try:
            if os.path.exists(_CALIBRATOR_PATH):
                from threat_intel_aggregator.evaluation.calibrators import load_calibrator
                _calibrator = load_calibrator(_CALIBRATOR_PATH)
                logger.info(f"Loaded confidence calibrator from {_CALIBRATOR_PATH}")
            else:
                logger.info(
                    "No fitted confidence calibrator found "
                    f"({_CALIBRATOR_PATH}); using raw fused scores"
                )
        except Exception as e:
            logger.warning(f"Could not load confidence calibrator: {e}")
            _calibrator = None
    return _calibrator


def calibrate_confidence(score: float) -> float:
    """Apply the fitted calibrator to a fused confidence score.

    Returns the score unchanged when no calibrator is available.
    """
    calibrator = _get_calibrator()
    if calibrator is None:
        return score
    try:
        return calibrator.transform([score])[0]
    except Exception as e:
        logger.warning(f"Calibration failed, returning raw score: {e}")
        return score


def fuse_confidence(
    regex_confidence: float,
    llm_confidence: Optional[float] = None,
    source_reliability: float = 1.0,
    config: Optional[FusionConfig] = None,
) -> float:
    """
    Fuse regex and LLM confidence scores.
    
    Args:
        regex_confidence: Confidence from regex-based extraction (0.0-1.0).
        llm_confidence: Confidence from LLM verification (0.0-1.0), or None if unavailable.
        config: Fusion configuration. Uses defaults if not provided.
        
    Returns:
        Fused confidence score between 0.0 and 1.0.
    """
    if config is None:
        config = DEFAULT_FUSION_CONFIG
    
    # Fallback: LLM unavailable → use regex-only
    if llm_confidence is None:
        logger.debug("LLM confidence unavailable, using regex-only confidence")
        return max(0.0, min(1.0, regex_confidence))
    
    # Weighted fusion
    fused = (config.weight_regex * regex_confidence) + (config.weight_llm * llm_confidence)
    
    # Scale by source reliability (Admiralty Scale)
    fused *= source_reliability
    
    # Clamp to [0.0, 1.0]
    fused = max(0.0, min(1.0, fused))
    
    logger.debug(
        f"Confidence fusion: regex={regex_confidence:.2f} × {config.weight_regex} + "
        f"llm={llm_confidence:.2f} × {config.weight_llm} = {fused:.2f}"
    )
    
    return round(fused, 4)


def fuse_with_penalty(
    regex_confidence: float,
    llm_confidence: Optional[float] = None,
    llm_is_valid: Optional[bool] = None,
    source_reliability: float = 1.0,
    config: Optional[FusionConfig] = None,
    apply_calibration: bool = False,
) -> float:
    """
    Fuse confidence with an additional penalty when LLM flags IOC as invalid.

    If the LLM says the IOC is NOT valid (is_valid_ioc=False),
    the LLM confidence is inverted before fusion, significantly
    lowering the final score.

    Args:
        regex_confidence: Confidence from regex extraction.
        llm_confidence: Confidence from LLM verification.
        llm_is_valid: Whether LLM considers this a valid IOC.
        config: Fusion configuration.
        apply_calibration: When True, apply the fitted post-hoc calibrator to
            the fused score. Only applied when an LLM confidence is present —
            the calibrator was fitted on genuine regex+LLM fused scores, not on
            the regex-only fallback path.

    Returns:
        Fused confidence score between 0.0 and 1.0.
    """
    had_llm = llm_confidence is not None
    if had_llm and llm_is_valid is False:
        # Invert LLM confidence as a penalty
        llm_confidence = 1.0 - llm_confidence

    fused = fuse_confidence(regex_confidence, llm_confidence, source_reliability, config)

    if apply_calibration and had_llm:
        fused = round(calibrate_confidence(fused), 4)
    return fused
