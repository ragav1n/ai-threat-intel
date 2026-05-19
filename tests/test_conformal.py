"""Tests for conformal risk control (evaluation.conformal)."""
import math
import random

from threat_intel_aggregator.evaluation.conformal import (
    ABSTAIN_ALL,
    conformal_threshold,
    evaluate_conformal,
    fdr_coverage_curve,
    fit_and_test,
    _kl_upper,
)


def _well_calibrated(n, seed=0):
    """Predictions whose confidence equals P(correct) — perfectly calibrated."""
    rng = random.Random(seed)
    preds = []
    for _ in range(n):
        conf = rng.random()
        preds.append((conf, rng.random() < conf))
    return preds


# ── _kl_upper ──────────────────────────────────────────────

def test_kl_upper_bounds_the_estimate():
    # The upper bound is always at or above the point estimate.
    assert _kl_upper(10, 100, 0.1) >= 0.10
    assert _kl_upper(0, 100, 0.1) >= 0.0
    assert _kl_upper(50, 100, 0.1) >= 0.50


def test_kl_upper_tightens_with_more_data():
    # More accepted items at the same error rate -> tighter (lower) bound.
    wide = _kl_upper(5, 50, 0.1)
    tight = _kl_upper(50, 500, 0.1)
    assert tight < wide


def test_kl_upper_no_data_is_uninformative():
    assert _kl_upper(0, 0, 0.1) == 1.0


# ── conformal_threshold ────────────────────────────────────

def test_threshold_controls_calibration_risk():
    # On the calibration set itself, the accepted error rate must be <= alpha.
    preds = _well_calibrated(3000, seed=1)
    alpha = 0.15
    t = conformal_threshold(preds, alpha, delta=0.1)
    assert not math.isinf(t)
    accepted = [(c, y) for c, y in preds if c >= t]
    risk = sum(1 for _, y in accepted if not y) / len(accepted)
    assert risk <= alpha


def test_threshold_monotone_in_alpha():
    # A stricter alpha must not yield a more permissive (lower) threshold.
    preds = _well_calibrated(3000, seed=2)
    t_strict = conformal_threshold(preds, 0.10, delta=0.1)
    t_loose = conformal_threshold(preds, 0.20, delta=0.1)
    assert t_strict >= t_loose


def test_threshold_abstains_when_nothing_is_safe():
    # Every IOC is wrong -> no threshold can hit a 1% error rate.
    preds = [(0.9, False)] * 200
    assert conformal_threshold(preds, 0.01, delta=0.1) == ABSTAIN_ALL


def test_threshold_empty_input_abstains():
    assert conformal_threshold([], 0.1) == ABSTAIN_ALL


def test_threshold_rejects_unknown_loss():
    try:
        conformal_threshold([(0.9, True)], 0.1, loss="coverage")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_threshold_is_deterministic():
    preds = _well_calibrated(500, seed=3)
    assert conformal_threshold(preds, 0.1) == conformal_threshold(preds, 0.1)


# ── fit_and_test ───────────────────────────────────────────

def test_fit_and_test_reports_both_splits():
    preds = _well_calibrated(4000, seed=4)
    r = fit_and_test(preds[:2000], preds[2000:], alpha=0.20, delta=0.1)
    assert r.n_calib == 2000 and r.n_test == 2000
    assert not math.isinf(r.threshold)
    assert r.risk_bound <= 0.20 + 1e-9          # calibration bound respects alpha
    assert 0.0 <= r.coverage <= 1.0


# ── evaluate_conformal ─────────────────────────────────────

def test_evaluate_conformal_guarantee_holds_when_well_specified():
    # On a well-calibrated source the held-out error rate should stay <= alpha
    # in at least (1 - delta) of trials, allowing slack for test-split noise.
    preds = _well_calibrated(6000, seed=5)
    res = evaluate_conformal(preds, alpha=0.20, delta=0.1, n_trials=100)
    assert res.guarantee_coverage >= 0.80
    assert res.risk.mean <= 0.20 + 0.05


def test_evaluate_conformal_empty_input():
    res = evaluate_conformal([], alpha=0.1)
    assert res.risk is None and res.guarantee_coverage == 0.0


def test_evaluate_conformal_is_deterministic():
    preds = _well_calibrated(800, seed=6)
    a = evaluate_conformal(preds, 0.1, n_trials=30)
    b = evaluate_conformal(preds, 0.1, n_trials=30)
    assert a.risk.mean == b.risk.mean and a.coverage.mean == b.coverage.mean


# ── fdr_coverage_curve ─────────────────────────────────────

def test_fdr_coverage_curve_coverage_rises_with_alpha():
    preds = _well_calibrated(6000, seed=7)
    curve = fdr_coverage_curve(preds, [0.10, 0.15, 0.20], delta=0.1, n_trials=60)
    cov = [curve[a].coverage.mean for a in (0.10, 0.15, 0.20)]
    assert cov[0] <= cov[1] <= cov[2]
