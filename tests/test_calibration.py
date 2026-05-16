"""
Tests for the confidence calibration module (research-paper contribution C2).
"""
import json
import math

from threat_intel_aggregator.evaluation.calibration import (
    CalibrationResult,
    bootstrap_calibration_ci,
    compute_calibration,
    format_calibration_ci_table,
    format_reliability_diagram,
    format_calibration_comparison,
)
from threat_intel_aggregator.evaluation.metrics_engine import MetricsEngine


# ── compute_calibration ────────────────────────────────────

def test_empty_predictions_yield_zero_result():
    r = compute_calibration([])
    assert r.n_samples == 0
    assert r.brier_score == 0.0
    assert r.ece == 0.0
    assert r.mce == 0.0
    assert len(r.bins) == 10  # bins still initialised


def test_bin_count_is_configurable():
    r = compute_calibration([(0.5, True)], n_bins=5)
    assert len(r.bins) == 5


def test_confidence_one_falls_in_last_bin():
    r = compute_calibration([(1.0, True)])
    assert r.bins[-1].count == 1
    assert sum(b.count for b in r.bins) == 1


def test_perfect_calibration_has_zero_error():
    # Confidence exactly matches outcomes: ECE and Brier collapse to 0.
    preds = [(1.0, True)] * 50 + [(0.0, False)] * 50
    r = compute_calibration(preds)
    assert r.brier_score == 0.0
    assert r.ece == 0.0
    assert r.mce == 0.0
    assert math.isclose(r.accuracy, 0.5)


def test_overconfident_predictions_flagged():
    # Confidence 0.9 but always wrong → large gap, positive overconfidence.
    r = compute_calibration([(0.9, False)] * 20)
    assert math.isclose(r.ece, 0.9, abs_tol=1e-9)
    assert math.isclose(r.mce, 0.9, abs_tol=1e-9)
    assert math.isclose(r.overconfidence, 0.9, abs_tol=1e-9)
    assert math.isclose(r.brier_score, 0.81, abs_tol=1e-9)


def test_underconfident_predictions_have_negative_overconfidence():
    r = compute_calibration([(0.2, True)] * 20)
    assert r.overconfidence < 0


def test_brier_score_known_value():
    # ((0.8-1)^2 + (0.8-0)^2) / 2 = (0.04 + 0.64) / 2 = 0.34
    r = compute_calibration([(0.8, True), (0.8, False)])
    assert math.isclose(r.brier_score, 0.34, abs_tol=1e-9)


def test_confidence_is_clamped_to_unit_interval():
    r = compute_calibration([(1.5, True), (-0.3, False)])
    assert 0.0 <= r.avg_confidence <= 1.0
    assert r.bins[-1].count == 1   # 1.5 clamped to 1.0
    assert r.bins[0].count == 1    # -0.3 clamped to 0.0


def test_ece_is_support_weighted():
    # 90 well-calibrated (bin [0.9,1.0)) + 10 badly-calibrated (bin [0.8,0.9)).
    preds = [(1.0, True)] * 90 + [(0.85, False)] * 10
    r = compute_calibration(preds)
    # ECE = (90/100)*0 + (10/100)*0.85 = 0.085  → pulled toward 0 by support.
    assert math.isclose(r.ece, 0.085, abs_tol=1e-9)
    assert math.isclose(r.mce, 0.85, abs_tol=1e-9)  # worst bin still 0.85


def test_to_dict_is_serialisable():
    r = compute_calibration([(0.7, True), (0.3, False)])
    d = r.to_dict()
    assert set(d) >= {"n_samples", "brier_score", "ece", "mce", "bins"}
    assert isinstance(d["bins"], list)


# ── formatting ─────────────────────────────────────────────

def test_reliability_diagram_renders():
    r = compute_calibration([(0.7, True), (0.9, True), (0.4, False)])
    out = format_reliability_diagram(r, title="Test")
    assert "RELIABILITY DIAGRAM" in out
    assert "Brier=" in out and "ECE=" in out


def test_reliability_diagram_handles_empty():
    out = format_reliability_diagram(compute_calibration([]))
    assert "no predictions" in out


def test_calibration_comparison_renders():
    a = compute_calibration([(0.9, True)] * 10)
    b = compute_calibration([(0.9, False)] * 10)
    out = format_calibration_comparison({"good": a, "bad": b})
    assert "CALIBRATION COMPARISON" in out
    assert "good" in out and "bad" in out


# ── integration with MetricsEngine ─────────────────────────

def test_metrics_engine_populates_calibration():
    samples = [
        {
            "expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
            "extracted_iocs": [{"value": "1.2.3.4", "type": "ip", "confidence": 0.9}],
            "category": "true_positive",
        },
        {
            "expected_iocs": [],
            "extracted_iocs": [{"value": "8.8.8.8", "type": "ip", "confidence": 0.6}],
            "category": "true_negative",
        },
    ]
    result = MetricsEngine().evaluate(samples)
    assert result.calibration is not None
    # one TP + one FP → two calibration predictions
    assert result.calibration.n_samples == 2
    assert result.to_dict()["calibration"]["n_samples"] == 2


def test_metrics_engine_calibration_empty_when_no_extractions():
    samples = [{"expected_iocs": [], "extracted_iocs": [], "category": "true_negative"}]
    result = MetricsEngine().evaluate(samples)
    assert result.calibration is not None
    assert result.calibration.n_samples == 0


# ── bootstrap_calibration_ci ───────────────────────────────

def _mixed_preds():
    """A miscalibrated mix (overconfident in both bins)."""
    return (
        [(0.9, True)] * 30 + [(0.9, False)] * 20
        + [(0.6, True)] * 25 + [(0.6, False)] * 25
    )


def test_bootstrap_ci_returns_populated_result():
    r = bootstrap_calibration_ci(_mixed_preds(), n_iterations=200)
    assert r.n_samples == 100
    assert r.n_iterations == 200
    assert r.ece_ci is not None and r.brier_ci is not None and r.mce_ci is not None


def test_bootstrap_ci_bounds_contain_point():
    r = bootstrap_calibration_ci(_mixed_preds(), n_iterations=300)
    for ci in (r.ece_ci, r.brier_ci, r.mce_ci):
        assert ci.ci_lower <= ci.point_estimate <= ci.ci_upper
        assert ci.ci_width >= 0.0


def test_bootstrap_ci_reproducible_with_seed():
    a = bootstrap_calibration_ci(_mixed_preds(), n_iterations=200, seed=7)
    b = bootstrap_calibration_ci(_mixed_preds(), n_iterations=200, seed=7)
    assert a.ece_ci.ci_lower == b.ece_ci.ci_lower
    assert a.ece_ci.ci_upper == b.ece_ci.ci_upper


def test_bootstrap_ci_point_matches_compute_calibration():
    preds = _mixed_preds()
    r = bootstrap_calibration_ci(preds, n_iterations=100)
    base = compute_calibration(preds)
    assert r.ece_ci.point_estimate == base.ece
    assert r.brier_ci.point_estimate == base.brier_score


def test_bootstrap_ci_perfect_data_tight():
    # perfectly calibrated -> ECE ~0 in every resample, so the CI collapses.
    preds = [(1.0, True)] * 50 + [(0.0, False)] * 50
    r = bootstrap_calibration_ci(preds, n_iterations=200)
    assert r.ece_ci.ci_width < 0.05
    assert r.ece_ci.ci_upper < 0.05


def test_bootstrap_ci_empty_input():
    r = bootstrap_calibration_ci([], n_iterations=100)
    assert r.n_samples == 0
    assert r.ece_ci is None and r.brier_ci is None and r.mce_ci is None


def test_bootstrap_ci_to_dict_serialisable():
    r = bootstrap_calibration_ci(_mixed_preds(), n_iterations=50)
    json.dumps(r.to_dict())  # must not raise
    assert r.to_dict()["ece"]["metric"] == "ECE"


def test_format_calibration_ci_table_renders():
    table = format_calibration_ci_table({
        "Fused": bootstrap_calibration_ci(_mixed_preds(), n_iterations=50),
        "Empty": bootstrap_calibration_ci([]),
    })
    assert "ECE" in table and "Fused" in table
    assert "no predictions" in table
