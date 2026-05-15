"""
Tests for post-hoc confidence calibrators (research-paper contribution C2).
"""
import random

from threat_intel_aggregator.evaluation.calibration import compute_calibration
from threat_intel_aggregator.evaluation.calibrators import (
    CALIBRATORS,
    IdentityCalibrator,
    IsotonicCalibrator,
    TemperatureScaler,
    _pava,
    kfold_calibration_eval,
)


def _miscalibrated(n=800, gap=0.25, seed=1):
    """Synthetic overconfident data: empirical accuracy = confidence - gap."""
    rng = random.Random(seed)
    levels = [0.3, 0.5, 0.7, 0.9]
    preds = []
    for _ in range(n):
        c = rng.choice(levels)
        preds.append((c, rng.random() < max(0.0, c - gap)))
    return preds


# ── registry ───────────────────────────────────────────────

def test_calibrator_registry():
    assert set(CALIBRATORS) == {"identity", "temperature", "isotonic"}
    for factory in CALIBRATORS.values():
        assert hasattr(factory(), "fit") and hasattr(factory(), "transform")


# ── identity ────────────────────────────────────────────────

def test_identity_is_passthrough_and_clamps():
    cal = IdentityCalibrator().fit([(0.5, True)])
    assert cal.transform([0.4, 1.7, -0.2]) == [0.4, 1.0, 0.0]


# ── _pava ───────────────────────────────────────────────────

def test_pava_output_is_non_decreasing():
    out = _pava([3.0, 1.0, 2.0, 0.0, 5.0])
    assert out == sorted(out)
    assert len(out) == 5


def test_pava_preserves_already_sorted():
    assert _pava([0.0, 0.0, 1.0, 1.0]) == [0.0, 0.0, 1.0, 1.0]


# ── temperature scaling ─────────────────────────────────────

def test_temperature_empty_predictions_defaults_to_one():
    assert TemperatureScaler().fit([]).temperature == 1.0


def test_temperature_softens_overconfident_scores():
    ts = TemperatureScaler().fit(_miscalibrated())
    # Overconfident input → temperature > 1 → calibrated score pulled down.
    assert ts.temperature > 1.0
    assert ts.transform([0.9])[0] < 0.9


def test_temperature_reduces_ece_on_training_data():
    preds = _miscalibrated()
    ts = TemperatureScaler().fit(preds)
    before = compute_calibration(preds).ece
    after = compute_calibration(
        [(ts.transform([c])[0], y) for c, y in preds]
    ).ece
    assert after < before


def test_temperature_transform_clamps_to_unit_interval():
    ts = TemperatureScaler().fit(_miscalibrated())
    for v in ts.transform([0.0, 1.0, 0.5]):
        assert 0.0 <= v <= 1.0


# ── isotonic regression ─────────────────────────────────────

def test_isotonic_empty_is_identity():
    cal = IsotonicCalibrator().fit([])
    assert cal.transform([0.3, 0.7]) == [0.3, 0.7]


def test_isotonic_output_is_monotone_in_input():
    cal = IsotonicCalibrator().fit(_miscalibrated())
    xs = [i / 50 for i in range(51)]
    ys = cal.transform(xs)
    assert ys == sorted(ys)  # non-decreasing


def test_isotonic_reduces_ece_on_training_data():
    preds = _miscalibrated()
    cal = IsotonicCalibrator().fit(preds)
    before = compute_calibration(preds).ece
    after = compute_calibration(
        [(cal.transform([c])[0], y) for c, y in preds]
    ).ece
    assert after < before


# ── k-fold cross-validated evaluation ───────────────────────

def test_kfold_returns_all_predictions_out_of_fold():
    preds = _miscalibrated(n=200)
    result = kfold_calibration_eval(preds, TemperatureScaler, k=5)
    assert result.n_samples == len(preds)


def test_kfold_empty_predictions():
    assert kfold_calibration_eval([], TemperatureScaler).n_samples == 0


def test_kfold_is_deterministic():
    preds = _miscalibrated(n=300)
    a = kfold_calibration_eval(preds, IsotonicCalibrator, seed=7)
    b = kfold_calibration_eval(preds, IsotonicCalibrator, seed=7)
    assert a.ece == b.ece


def test_kfold_calibration_beats_uncalibrated():
    preds = _miscalibrated(n=800)
    uncalibrated = compute_calibration(preds).ece
    temp = kfold_calibration_eval(preds, TemperatureScaler).ece
    iso = kfold_calibration_eval(preds, IsotonicCalibrator).ece
    # Honest out-of-fold calibration should still beat the uncalibrated score.
    assert temp < uncalibrated
    assert iso < uncalibrated
