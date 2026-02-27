"""
Bootstrap Confidence Intervals for evaluation metrics.

Computes 95% confidence intervals for Precision, Recall, and F1 Score
using non-parametric bootstrap resampling (Efron, 1979).
"""

import random
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ConfidenceInterval:
    """Represents a metric with its 95% confidence interval."""
    metric_name: str
    point_estimate: float
    ci_lower: float
    ci_upper: float
    ci_width: float = 0.0
    n_iterations: int = 0

    def __post_init__(self):
        self.ci_width = self.ci_upper - self.ci_lower

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metric": self.metric_name,
            "point_estimate": round(self.point_estimate, 4),
            "ci_lower": round(self.ci_lower, 4),
            "ci_upper": round(self.ci_upper, 4),
            "ci_width": round(self.ci_width, 4),
            "n_iterations": self.n_iterations,
        }

    def __repr__(self) -> str:
        return (
            f"{self.metric_name}: {self.point_estimate:.4f} "
            f"[{self.ci_lower:.4f}, {self.ci_upper:.4f}] (95% CI)"
        )


@dataclass
class BootstrapResult:
    """Collection of confidence intervals from a bootstrap analysis."""
    precision_ci: ConfidenceInterval = None
    recall_ci: ConfidenceInterval = None
    f1_ci: ConfidenceInterval = None
    n_samples: int = 0
    n_iterations: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "n_samples": self.n_samples,
            "n_iterations": self.n_iterations,
            "precision": self.precision_ci.to_dict() if self.precision_ci else None,
            "recall": self.recall_ci.to_dict() if self.recall_ci else None,
            "f1": self.f1_ci.to_dict() if self.f1_ci else None,
        }


def _compute_prf(samples: list) -> Tuple[float, float, float]:
    """Compute P, R, F1 from a list of sample-level (tp, fp, fn) tuples."""
    total_tp = sum(s[0] for s in samples)
    total_fp = sum(s[1] for s in samples)
    total_fn = sum(s[2] for s in samples)

    p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    return p, r, f


def _normalize(v: str) -> str:
    return v.strip().lower()


def compute_bootstrap_ci(
    eval_samples: list,
    n_iterations: int = 1000,
    confidence_level: float = 0.95,
    seed: int = 42,
) -> BootstrapResult:
    """
    Compute bootstrap confidence intervals for P/R/F1.

    Args:
        eval_samples: List of dicts with 'expected_iocs' and 'extracted_iocs'.
        n_iterations: Number of bootstrap iterations (default 1000).
        confidence_level: Confidence level for intervals (default 0.95).
        seed: Random seed for reproducibility.

    Returns:
        BootstrapResult with 95% CIs for precision, recall, and F1.
    """
    rng = random.Random(seed)

    # Pre-compute per-sample TP/FP/FN
    sample_scores = []
    for sample in eval_samples:
        expected_set: Set[Tuple[str, str]] = {
            (_normalize(e["value"]), e["type"].strip().lower())
            for e in sample.get("expected_iocs", [])
        }
        extracted_set: Set[Tuple[str, str]] = {
            (_normalize(e["value"]), e["type"].strip().lower())
            for e in sample.get("extracted_iocs", [])
        }
        tp = len(expected_set & extracted_set)
        fp = len(extracted_set - expected_set)
        fn = len(expected_set - extracted_set)
        sample_scores.append((tp, fp, fn))

    # Point estimates
    point_p, point_r, point_f = _compute_prf(sample_scores)

    # Bootstrap resampling
    boot_precisions = []
    boot_recalls = []
    boot_f1s = []

    n = len(sample_scores)
    for _ in range(n_iterations):
        # Resample with replacement
        bootstrap_sample = [rng.choice(sample_scores) for _ in range(n)]
        p, r, f = _compute_prf(bootstrap_sample)
        boot_precisions.append(p)
        boot_recalls.append(r)
        boot_f1s.append(f)

    # Compute percentile-based CIs
    alpha = (1 - confidence_level) / 2
    lower_idx = int(alpha * n_iterations)
    upper_idx = int((1 - alpha) * n_iterations)

    boot_precisions.sort()
    boot_recalls.sort()
    boot_f1s.sort()

    result = BootstrapResult(
        n_samples=n,
        n_iterations=n_iterations,
        precision_ci=ConfidenceInterval(
            metric_name="Precision",
            point_estimate=point_p,
            ci_lower=boot_precisions[lower_idx],
            ci_upper=boot_precisions[upper_idx],
            n_iterations=n_iterations,
        ),
        recall_ci=ConfidenceInterval(
            metric_name="Recall",
            point_estimate=point_r,
            ci_lower=boot_recalls[lower_idx],
            ci_upper=boot_recalls[upper_idx],
            n_iterations=n_iterations,
        ),
        f1_ci=ConfidenceInterval(
            metric_name="F1 Score",
            point_estimate=point_f,
            ci_lower=boot_f1s[lower_idx],
            ci_upper=boot_f1s[upper_idx],
            n_iterations=n_iterations,
        ),
    )

    logger.info(
        f"Bootstrap CI ({n_iterations} iterations): "
        f"F1 = {point_f:.4f} [{boot_f1s[lower_idx]:.4f}, {boot_f1s[upper_idx]:.4f}]"
    )

    return result


def format_bootstrap_table(result: BootstrapResult) -> str:
    """Format bootstrap results as a readable table."""
    lines = []
    lines.append("=" * 68)
    lines.append(f"  BOOTSTRAP CONFIDENCE INTERVALS ({result.n_iterations} iterations, 95% CI)")
    lines.append("=" * 68)
    lines.append(f"  {'Metric':<12s} {'Point':>8s}   {'95% CI Lower':>12s}  {'95% CI Upper':>12s}  {'Width':>8s}")
    lines.append(f"  {'-'*12} {'-'*8}   {'-'*12}  {'-'*12}  {'-'*8}")

    for ci in [result.precision_ci, result.recall_ci, result.f1_ci]:
        if ci:
            lines.append(
                f"  {ci.metric_name:<12s} {ci.point_estimate:7.1%}   "
                f"{ci.ci_lower:11.1%}   {ci.ci_upper:11.1%}   {ci.ci_width:7.1%}"
            )

    lines.append("=" * 68)
    return "\n".join(lines)
