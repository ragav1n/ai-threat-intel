"""
Confidence Calibration Metrics for IOC Extraction.

A well-calibrated extractor's confidence score should match its empirical
accuracy: among IOCs assigned confidence ~0.8, about 80% should be genuine.
Mezzi et al. (ARES 2025) showed LLM confidence for CTI is severely
miscalibrated (ECE up to 0.91) — this module quantifies that for our pipeline
and supports the "calibrated confidence fusion" contribution (C2).

Metrics
-------
  Brier score : mean squared error between confidence and binary outcome.
                Lower is better; 0.0 = perfect, 0.25 = uninformative (p=0.5).
  ECE         : Expected Calibration Error — support-weighted mean gap between
                bin confidence and bin accuracy. Lower is better.
  MCE         : Maximum Calibration Error — worst-case bin gap.
  Reliability : per-bin (mean confidence, empirical accuracy, count) — the data
                behind a reliability diagram.

Inputs are (confidence, correct) pairs, where `correct` is True for a true
positive and False for a false positive. The module is source-agnostic: it can
score the fused pipeline confidence, the raw LLM confidence, or the regex-only
confidence — enabling direct calibration comparisons.
"""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# A single prediction: (confidence in [0,1], whether it was actually correct).
Prediction = Tuple[float, bool]


@dataclass
class CalibrationBin:
    """One bin of a reliability diagram."""
    lower: float
    upper: float
    count: int = 0
    mean_confidence: float = 0.0
    accuracy: float = 0.0

    @property
    def gap(self) -> float:
        """Absolute calibration gap |accuracy - confidence| for this bin."""
        return abs(self.accuracy - self.mean_confidence)

    def to_dict(self) -> Dict[str, float]:
        return {
            "range": f"[{self.lower:.1f},{self.upper:.1f})",
            "count": self.count,
            "mean_confidence": round(self.mean_confidence, 4),
            "accuracy": round(self.accuracy, 4),
            "gap": round(self.gap, 4),
        }


@dataclass
class CalibrationResult:
    """Calibration metrics for one set of (confidence, correct) predictions."""
    n_samples: int = 0
    brier_score: float = 0.0
    ece: float = 0.0
    mce: float = 0.0
    avg_confidence: float = 0.0
    accuracy: float = 0.0
    bins: List[CalibrationBin] = field(default_factory=list)

    @property
    def overconfidence(self) -> float:
        """Mean confidence minus empirical accuracy. Positive = overconfident."""
        return self.avg_confidence - self.accuracy

    def to_dict(self) -> Dict[str, object]:
        return {
            "n_samples": self.n_samples,
            "brier_score": round(self.brier_score, 4),
            "ece": round(self.ece, 4),
            "mce": round(self.mce, 4),
            "avg_confidence": round(self.avg_confidence, 4),
            "accuracy": round(self.accuracy, 4),
            "overconfidence": round(self.overconfidence, 4),
            "bins": [b.to_dict() for b in self.bins],
        }


@dataclass
class CalibrationCI:
    """A calibration metric with a percentile bootstrap confidence interval."""
    metric_name: str            # "ECE" | "Brier" | "MCE"
    point_estimate: float
    ci_lower: float
    ci_upper: float
    n_iterations: int = 0

    @property
    def ci_width(self) -> float:
        return self.ci_upper - self.ci_lower

    def to_dict(self) -> Dict[str, object]:
        return {
            "metric": self.metric_name,
            "point_estimate": round(self.point_estimate, 4),
            "ci_lower": round(self.ci_lower, 4),
            "ci_upper": round(self.ci_upper, 4),
            "ci_width": round(self.ci_width, 4),
            "n_iterations": self.n_iterations,
        }


@dataclass
class CalibrationBootstrapResult:
    """ECE / Brier / MCE with bootstrap CIs for one set of predictions."""
    n_samples: int = 0
    n_iterations: int = 0
    ece_ci: Optional[CalibrationCI] = None
    brier_ci: Optional[CalibrationCI] = None
    mce_ci: Optional[CalibrationCI] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "n_samples": self.n_samples,
            "n_iterations": self.n_iterations,
            "ece": self.ece_ci.to_dict() if self.ece_ci else None,
            "brier": self.brier_ci.to_dict() if self.brier_ci else None,
            "mce": self.mce_ci.to_dict() if self.mce_ci else None,
        }


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def compute_calibration(
    predictions: Sequence[Prediction],
    n_bins: int = 10,
) -> CalibrationResult:
    """
    Compute Brier score, ECE, MCE and reliability bins for a set of predictions.

    Args:
        predictions: sequence of (confidence, correct) pairs. `confidence` is
            clamped to [0,1]; `correct` is True for a true positive.
        n_bins: number of equal-width confidence bins (default 10).

    Returns:
        CalibrationResult. An empty input yields an all-zero result.
    """
    preds = [(_clamp01(c), bool(y)) for c, y in predictions]
    n = len(preds)
    result = CalibrationResult(n_samples=n)

    # Initialise equal-width bins over [0,1].
    edges = [i / n_bins for i in range(n_bins + 1)]
    bins = [CalibrationBin(lower=edges[i], upper=edges[i + 1]) for i in range(n_bins)]
    result.bins = bins
    if n == 0:
        return result

    # Brier score and global aggregates.
    result.brier_score = sum((c - (1.0 if y else 0.0)) ** 2 for c, y in preds) / n
    result.avg_confidence = sum(c for c, _ in preds) / n
    result.accuracy = sum(1 for _, y in preds if y) / n

    # Accumulate per-bin sums.
    bin_conf_sum = [0.0] * n_bins
    bin_correct = [0] * n_bins
    for c, y in preds:
        # p == 1.0 falls into the last bin.
        idx = min(n_bins - 1, int(c * n_bins))
        bins[idx].count += 1
        bin_conf_sum[idx] += c
        bin_correct[idx] += 1 if y else 0

    ece = 0.0
    mce = 0.0
    for i, b in enumerate(bins):
        if b.count == 0:
            continue
        b.mean_confidence = bin_conf_sum[i] / b.count
        b.accuracy = bin_correct[i] / b.count
        ece += (b.count / n) * b.gap
        mce = max(mce, b.gap)

    result.ece = ece
    result.mce = mce
    return result


def format_reliability_diagram(result: CalibrationResult, title: str = "") -> str:
    """Render a calibration result as an ASCII reliability diagram."""
    lines = []
    header = "  RELIABILITY DIAGRAM" + (f" — {title}" if title else "")
    lines.append("=" * 72)
    lines.append(header)
    lines.append("=" * 72)
    if result.n_samples == 0:
        lines.append("  (no predictions)")
        lines.append("=" * 72)
        return "\n".join(lines)

    lines.append(f"  {'Bin':<13s} {'Count':>7s} {'Conf':>8s} {'Acc':>8s} {'Gap':>8s}  Bar")
    lines.append(f"  {'-'*13} {'-'*7} {'-'*8} {'-'*8} {'-'*8}  {'-'*20}")
    for b in result.bins:
        if b.count == 0:
            lines.append(
                f"  [{b.lower:.1f},{b.upper:.1f}) {0:>7d} {'—':>8s} {'—':>8s} {'—':>8s}"
            )
            continue
        bar = "#" * int(round(b.accuracy * 20))
        lines.append(
            f"  [{b.lower:.1f},{b.upper:.1f}) {b.count:>7d} "
            f"{b.mean_confidence:>8.3f} {b.accuracy:>8.3f} {b.gap:>8.3f}  {bar}"
        )
    lines.append("")
    lines.append(
        f"  N={result.n_samples}  Brier={result.brier_score:.4f}  "
        f"ECE={result.ece:.4f}  MCE={result.mce:.4f}"
    )
    lines.append(
        f"  avg confidence={result.avg_confidence:.3f}  accuracy={result.accuracy:.3f}  "
        f"overconfidence={result.overconfidence:+.3f}"
    )
    lines.append("=" * 72)
    return "\n".join(lines)


def bootstrap_calibration_ci(
    predictions: Sequence[Prediction],
    n_bins: int = 10,
    n_iterations: int = 1000,
    confidence_level: float = 0.95,
    seed: int = 42,
) -> CalibrationBootstrapResult:
    """
    Percentile bootstrap confidence intervals for ECE / Brier / MCE.

    Resamples the (confidence, correct) pairs with replacement `n_iterations`
    times, recomputes calibration on each draw, and reports percentile CIs.
    Point estimates come from `compute_calibration` on the full sample (not the
    bootstrap mean), so they match the headline numbers exactly.

    Args:
        predictions: sequence of (confidence, correct) pairs.
        n_bins: confidence bins passed through to `compute_calibration`.
        n_iterations: number of bootstrap resamples (default 1000).
        confidence_level: CI mass (default 0.95).
        seed: RNG seed for reproducibility (default 42, matching bootstrap_ci).

    Returns:
        CalibrationBootstrapResult. An empty input yields a result with
        n_samples=0 and all CIs None.
    """
    preds = list(predictions)
    n = len(preds)
    result = CalibrationBootstrapResult(n_samples=n, n_iterations=n_iterations)
    if n == 0:
        return result

    base = compute_calibration(preds, n_bins)
    rng = random.Random(seed)

    eces: List[float] = []
    briers: List[float] = []
    mces: List[float] = []
    for _ in range(n_iterations):
        draw = [rng.choice(preds) for _ in range(n)]
        r = compute_calibration(draw, n_bins)
        eces.append(r.ece)
        briers.append(r.brier_score)
        mces.append(r.mce)

    alpha = (1.0 - confidence_level) / 2.0
    lo_idx = int(alpha * n_iterations)
    hi_idx = min(n_iterations - 1, int((1.0 - alpha) * n_iterations))

    def _ci(name: str, point: float, samples: List[float]) -> CalibrationCI:
        ordered = sorted(samples)
        return CalibrationCI(
            metric_name=name,
            point_estimate=point,
            ci_lower=ordered[lo_idx],
            ci_upper=ordered[hi_idx],
            n_iterations=n_iterations,
        )

    result.ece_ci = _ci("ECE", base.ece, eces)
    result.brier_ci = _ci("Brier", base.brier_score, briers)
    result.mce_ci = _ci("MCE", base.mce, mces)
    return result


def format_calibration_ci_table(named: Dict[str, CalibrationBootstrapResult]) -> str:
    """Render ECE / Brier point estimates with bootstrap CIs side by side.

    Intended for the C2 paper table: each confidence source's ECE and Brier
    with error bars.
    """
    lines = []
    lines.append("=" * 78)
    lines.append("  CALIBRATION METRICS WITH BOOTSTRAP CONFIDENCE INTERVALS")
    lines.append("=" * 78)
    lines.append(
        f"  {'Confidence source':<24s} {'N':>6s} "
        f"{'ECE [95% CI]':>23s} {'Brier [95% CI]':>23s}"
    )
    lines.append(f"  {'-'*24} {'-'*6} {'-'*23} {'-'*23}")
    for name, r in named.items():
        if r.ece_ci is None:
            lines.append(f"  {name:<24s} {r.n_samples:>6d}   (no predictions)")
            continue
        ece = (f"{r.ece_ci.point_estimate:.4f} "
               f"[{r.ece_ci.ci_lower:.4f},{r.ece_ci.ci_upper:.4f}]")
        brier = (f"{r.brier_ci.point_estimate:.4f} "
                 f"[{r.brier_ci.ci_lower:.4f},{r.brier_ci.ci_upper:.4f}]")
        lines.append(f"  {name:<24s} {r.n_samples:>6d} {ece:>23s} {brier:>23s}")
    lines.append("")
    lines.append("  Point estimate followed by [lower, upper] percentile bootstrap CI.")
    lines.append("=" * 78)
    return "\n".join(lines)


def format_calibration_comparison(named_results: Dict[str, CalibrationResult]) -> str:
    """
    Render a side-by-side calibration comparison of several confidence sources.

    Intended for the C2 contribution: compare raw LLM confidence vs. fused vs.
    calibrated confidence on the same extraction outcomes.
    """
    lines = []
    lines.append("=" * 78)
    lines.append("  CALIBRATION COMPARISON")
    lines.append("=" * 78)
    lines.append(
        f"  {'Confidence source':<26s} {'N':>6s} {'Brier':>8s} {'ECE':>8s} "
        f"{'MCE':>8s} {'Overconf':>9s}"
    )
    lines.append(f"  {'-'*26} {'-'*6} {'-'*8} {'-'*8} {'-'*8} {'-'*9}")
    for name, r in named_results.items():
        lines.append(
            f"  {name:<26s} {r.n_samples:>6d} {r.brier_score:>8.4f} "
            f"{r.ece:>8.4f} {r.mce:>8.4f} {r.overconfidence:>+9.3f}"
        )
    lines.append("")
    lines.append("  Lower Brier / ECE / MCE = better calibrated.")
    lines.append("  Overconfidence > 0 = confidence exceeds empirical accuracy.")
    lines.append("=" * 78)
    return "\n".join(lines)
