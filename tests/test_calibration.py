"""
Tests for the confidence calibration module (research-paper contribution C2).
"""
import math

from threat_intel_aggregator.evaluation.calibration import (
    CalibrationResult,
    compute_calibration,
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
