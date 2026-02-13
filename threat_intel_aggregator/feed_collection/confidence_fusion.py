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


def fuse_confidence(
    regex_confidence: float,
    llm_confidence: Optional[float] = None,
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
    config: Optional[FusionConfig] = None,
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
        
    Returns:
        Fused confidence score between 0.0 and 1.0.
    """
    if llm_confidence is not None and llm_is_valid is False:
        # Invert LLM confidence as a penalty
        llm_confidence = 1.0 - llm_confidence
    
    return fuse_confidence(regex_confidence, llm_confidence, config)
