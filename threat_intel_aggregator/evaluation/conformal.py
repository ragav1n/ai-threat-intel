"""
Conformal risk control for IOC extraction (research-paper contribution C2+).

Post-hoc isotonic calibration (see `calibrators.py`) lowers ECE but offers no
guarantee: it says the score is *on average* close to the accuracy, not that an
auto-applied IOC is wrong at most X% of the time. For a blocklist that is the
quantity that matters — a wrong IOC firewalls a benign domain.

This module turns the confidence score into a triage rule with a *distribution-
free, finite-sample guarantee*: pick a confidence threshold so that the error
rate among the accepted (auto-applied) IOCs is at most ``alpha``, with
probability at least ``1 - delta`` over the calibration draw.

Method
------
Split-conformal selective classification by a calibrated threshold search:

  * candidate thresholds are a fixed grid over [0, 1] (data-independent, so the
    multiplicity of the search is known in advance);
  * at each grid threshold the accepted error rate is a Bernoulli parameter; a
    finite-sample upper confidence bound on it is computed with the
    Chernoff / KL bound (`_kl_upper`) at the Bonferroni-corrected level
    ``delta / grid_size``, so all grid bounds hold simultaneously with
    probability ``1 - delta``;
  * the fitted threshold is the lowest (highest-coverage) grid point whose
    corrected bound is at or below ``alpha``.

The guarantee is on the *population* error rate among accepted IOCs,
P(wrong | accepted) <= alpha — distribution-free, valid in finite samples, and
assuming only that calibration and deployment IOCs are exchangeable. That
exchangeability holds within one report source and not across sources, which is
exactly why the threshold must be re-fit per source (contrast: isotonic
transfer, `scripts/calibration_transfer.py`). The Bonferroni correction makes
the threshold mildly conservative — coverage is lower than an oracle's — which
is the honest price of a finite-sample guarantee.

`risk` here is the error rate among accepted IOCs (1 - precision) and `coverage`
the fraction auto-applied — the same definitions as `evaluation/selective.py`,
so the two modules' numbers are directly comparable.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from threat_intel_aggregator.evaluation.selective import operating_point

# (confidence in [0,1], was the IOC correct?) — same shape as calibration.Prediction
Prediction = Tuple[float, bool]

# "abstain on everything" — no grid threshold was safe at the requested alpha.
ABSTAIN_ALL = float("inf")

# Fixed, data-independent candidate thresholds (step 0.01 over [0, 1]).
THRESHOLD_GRID: List[float] = [i / 100.0 for i in range(101)]


def _kl(a: float, b: float) -> float:
    """Binary KL divergence kl(a||b) for Bernoulli means, in nats."""
    if b <= 0.0 or b >= 1.0:
        return float("inf")
    out = 0.0
    if a > 0.0:
        out += a * math.log(a / b)
    if a < 1.0:
        out += (1.0 - a) * math.log((1.0 - a) / (1.0 - b))
    return out


def _kl_upper(n_err: int, n_acc: int, delta: float) -> float:
    """Chernoff/KL upper confidence bound on a Bernoulli error rate.

    Returns the largest ``p`` such that ``n_acc * kl(p_hat || p) <= ln(1/delta)``,
    a valid finite-sample (1 - delta) upper bound on the true error rate given
    ``n_err`` errors in ``n_acc`` accepted items. With no accepted items there is
    no information, so the bound is 1.0.
    """
    if n_acc <= 0:
        return 1.0
    p_hat = n_err / n_acc
    if p_hat >= 1.0:
        return 1.0
    budget = math.log(1.0 / delta) / n_acc
    # The bound lies in [p_hat, 1]; kl(p_hat||p) is increasing in p there.
    lo, hi = p_hat, 1.0
    for _ in range(60):
        mid = (lo + hi) / 2.0
        if _kl(p_hat, mid) > budget:
            hi = mid
        else:
            lo = mid
    return hi


@dataclass
class RiskControlResult:
    """Outcome of fitting and testing one conformal threshold."""
    alpha: float                 # target error rate among accepted IOCs
    delta: float                 # guarantee fails with probability <= delta
    threshold: float             # min accepted confidence (inf = abstain on all)
    n_calib: int
    n_test: int
    empirical_risk: float        # error rate among accepted on the test split
    coverage: float              # fraction auto-applied on the test split
    risk_bound: float            # corrected KL upper bound at the fitted threshold
    guarantee_holds: bool        # did the test accepted error rate stay <= alpha?

    def to_dict(self) -> dict:
        thr = None if math.isinf(self.threshold) else round(self.threshold, 6)
        return {
            "alpha": self.alpha,
            "delta": self.delta,
            "threshold": thr,
            "n_calib": self.n_calib,
            "n_test": self.n_test,
            "empirical_risk": round(self.empirical_risk, 6),
            "coverage": round(self.coverage, 6),
            "risk_bound": round(self.risk_bound, 6),
            "guarantee_holds": self.guarantee_holds,
        }


@dataclass
class ConformalCI:
    """A conformal metric with a percentile interval over calibration splits."""
    mean: float
    ci_lower: float
    ci_upper: float

    def to_dict(self) -> dict:
        return {
            "mean": round(self.mean, 6),
            "ci_lower": round(self.ci_lower, 6),
            "ci_upper": round(self.ci_upper, 6),
        }


@dataclass
class ConformalBootstrapResult:
    """Conformal threshold behaviour aggregated over many calibration splits."""
    alpha: float
    delta: float
    n_total: int
    n_trials: int
    calib_frac: float
    risk: Optional[ConformalCI] = None         # test error rate among accepted
    coverage: Optional[ConformalCI] = None     # test fraction auto-applied
    threshold: Optional[ConformalCI] = None    # fitted threshold
    guarantee_coverage: float = 0.0            # trials with test risk <= alpha
    abstain_rate: float = 0.0                  # trials where no threshold was safe

    def to_dict(self) -> dict:
        return {
            "alpha": self.alpha,
            "delta": self.delta,
            "n_total": self.n_total,
            "n_trials": self.n_trials,
            "calib_frac": self.calib_frac,
            "risk": self.risk.to_dict() if self.risk else None,
            "coverage": self.coverage.to_dict() if self.coverage else None,
            "threshold": self.threshold.to_dict() if self.threshold else None,
            "guarantee_coverage": round(self.guarantee_coverage, 4),
            "abstain_rate": round(self.abstain_rate, 4),
        }


def _accepted_counts(predictions: Sequence[Prediction], threshold: float) -> Tuple[int, int]:
    """(n_accepted, n_errors) for IOCs with confidence >= threshold."""
    n_acc = 0
    n_err = 0
    for c, y in predictions:
        if c >= threshold:
            n_acc += 1
            if not y:
                n_err += 1
    return n_acc, n_err


def conformal_threshold(
    cal_predictions: Sequence[Prediction],
    alpha: float,
    delta: float = 0.1,
    loss: str = "fdr",
) -> float:
    """Lowest confidence threshold whose accepted error rate is provably <= alpha.

    Searches the fixed `THRESHOLD_GRID` and, at each grid point, bounds the
    accepted error rate with the Bonferroni-corrected KL bound described in the
    module docstring. Returns the lowest (highest-coverage) grid threshold whose
    bound is at or below ``alpha``, or ``ABSTAIN_ALL`` if none qualifies.

    Args:
        cal_predictions: calibration (confidence, correct) pairs.
        alpha: target error rate among accepted IOCs.
        delta: the guarantee may fail with probability at most this (default 0.1).
        loss: only "fdr" (error rate among accepted) is supported.

    Returns:
        The fitted confidence threshold, or ``ABSTAIN_ALL``.
    """
    if loss != "fdr":
        raise ValueError(f"unsupported loss {loss!r}; only 'fdr' is implemented")
    preds = list(cal_predictions)
    if not preds:
        return ABSTAIN_ALL

    corrected = delta / len(THRESHOLD_GRID)
    for threshold in THRESHOLD_GRID:                 # ascending: lowest first
        n_acc, n_err = _accepted_counts(preds, threshold)
        if n_acc == 0:
            continue
        if _kl_upper(n_err, n_acc, corrected) <= alpha:
            return threshold
    return ABSTAIN_ALL


def fit_and_test(
    cal_predictions: Sequence[Prediction],
    test_predictions: Sequence[Prediction],
    alpha: float,
    delta: float = 0.1,
) -> RiskControlResult:
    """Fit a conformal threshold on one split and measure it on another."""
    cal = list(cal_predictions)
    threshold = conformal_threshold(cal, alpha, delta)

    # The bound the calibration set certifies at the fitted threshold.
    if math.isinf(threshold):
        risk_bound = 1.0
    else:
        n_acc, n_err = _accepted_counts(cal, threshold)
        risk_bound = _kl_upper(n_err, n_acc, delta / len(THRESHOLD_GRID))

    op = operating_point(test_predictions, threshold)
    # An empty accepted set satisfies the bound vacuously.
    holds = op.n_accepted == 0 or op.risk <= alpha
    return RiskControlResult(
        alpha=alpha,
        delta=delta,
        threshold=threshold,
        n_calib=len(cal),
        n_test=len(list(test_predictions)),
        empirical_risk=op.risk,
        coverage=op.coverage,
        risk_bound=risk_bound,
        guarantee_holds=holds,
    )


def _percentile_ci(samples: List[float], level: float = 0.95) -> ConformalCI:
    """Mean and percentile interval of a list of trial statistics."""
    ordered = sorted(samples)
    n = len(ordered)
    mean = sum(ordered) / n
    tail = (1.0 - level) / 2.0
    lo = ordered[int(tail * n)]
    hi = ordered[min(n - 1, int((1.0 - tail) * n))]
    return ConformalCI(mean=mean, ci_lower=lo, ci_upper=hi)


def evaluate_conformal(
    predictions: Sequence[Prediction],
    alpha: float,
    delta: float = 0.1,
    n_trials: int = 100,
    calib_frac: float = 0.5,
    seed: int = 42,
) -> ConformalBootstrapResult:
    """Repeatedly split, fit a conformal threshold, and measure it out of sample.

    Each trial shuffles the predictions, fits the threshold on a ``calib_frac``
    slice and measures the error rate / coverage on the rest. Reports percentile
    intervals over trials and ``guarantee_coverage`` — the fraction of trials
    whose held-out accepted error rate stayed at or below ``alpha``. For a valid
    procedure that fraction should comfortably exceed ``1 - delta`` once test
    splits are large enough that their empirical error rate tracks the
    population rate.

    Args:
        predictions: (confidence, correct) pairs.
        alpha: target error rate among accepted IOCs.
        delta: per-fit failure probability budget (default 0.1).
        n_trials: number of random calibration/test splits (default 100).
        calib_frac: fraction of data used to fit the threshold (default 0.5).
        seed: RNG seed for reproducible splits (default 42).

    Returns:
        ConformalBootstrapResult. Empty input yields an all-None result.
    """
    preds = list(predictions)
    n = len(preds)
    result = ConformalBootstrapResult(
        alpha=alpha, delta=delta, n_total=n, n_trials=n_trials,
        calib_frac=calib_frac,
    )
    if n < 2:
        return result

    rng = random.Random(seed)
    n_calib = max(1, min(n - 1, int(round(calib_frac * n))))

    risks: List[float] = []
    coverages: List[float] = []
    thresholds: List[float] = []
    n_held = 0
    n_abstain = 0
    for _ in range(n_trials):
        idx = list(range(n))
        rng.shuffle(idx)
        cal = [preds[i] for i in idx[:n_calib]]
        test = [preds[i] for i in idx[n_calib:]]
        r = fit_and_test(cal, test, alpha, delta)
        risks.append(r.empirical_risk)
        coverages.append(r.coverage)
        if r.guarantee_holds:
            n_held += 1
        if math.isinf(r.threshold):
            n_abstain += 1
        else:
            thresholds.append(r.threshold)

    result.risk = _percentile_ci(risks)
    result.coverage = _percentile_ci(coverages)
    result.threshold = _percentile_ci(thresholds) if thresholds else None
    result.guarantee_coverage = n_held / n_trials
    result.abstain_rate = n_abstain / n_trials
    return result


def fdr_coverage_curve(
    predictions: Sequence[Prediction],
    alphas: Sequence[float],
    delta: float = 0.1,
    n_trials: int = 100,
    calib_frac: float = 0.5,
    seed: int = 42,
) -> Dict[float, ConformalBootstrapResult]:
    """Conformal behaviour across a grid of target error rates ``alpha``.

    For each alpha, runs `evaluate_conformal` and returns the aggregate. As alpha
    rises the threshold drops and coverage rises — the conformal analogue of a
    risk-coverage curve, but every point carries the finite-sample guarantee.
    """
    return {
        alpha: evaluate_conformal(predictions, alpha, delta, n_trials,
                                  calib_frac, seed)
        for alpha in alphas
    }


def format_conformal_table(
    curve: Dict[float, ConformalBootstrapResult],
    title: str = "",
) -> str:
    """Render an FDR-vs-coverage table from `fdr_coverage_curve` output."""
    lines = []
    header = "  CONFORMAL RISK CONTROL" + (f" — {title}" if title else "")
    lines.append("=" * 78)
    lines.append(header)
    lines.append("=" * 78)
    lines.append(
        f"  {'alpha':>7s} {'threshold':>10s} {'coverage':>20s} "
        f"{'test risk':>20s} {'guar.':>7s}"
    )
    lines.append(f"  {'-'*7} {'-'*10} {'-'*20} {'-'*20} {'-'*7}")
    for alpha in sorted(curve):
        r = curve[alpha]
        if r.risk is None:
            lines.append(f"  {alpha:>7.2f}   (too few predictions)")
            continue
        thr = "abstain" if r.threshold is None else f"{r.threshold.mean:.4f}"
        cov = (f"{r.coverage.mean:.1%} "
               f"[{r.coverage.ci_lower:.1%},{r.coverage.ci_upper:.1%}]")
        rsk = (f"{r.risk.mean:.1%} "
               f"[{r.risk.ci_lower:.1%},{r.risk.ci_upper:.1%}]")
        lines.append(
            f"  {alpha:>7.2f} {thr:>10s} {cov:>20s} {rsk:>20s} "
            f"{r.guarantee_coverage:>6.0%}"
        )
    lines.append("")
    lines.append("  threshold/coverage/test-risk: mean [95% CI] over calibration "
                 "splits.")
    lines.append("  guar. = fraction of splits whose held-out error rate stayed "
                 "<= alpha")
    if curve:
        delta = next(iter(curve.values())).delta
        lines.append(f"  (a valid procedure keeps this comfortably above "
                     f"1 - delta = {1.0 - delta:.0%}).")
    lines.append("=" * 78)
    return "\n".join(lines)
