"""
Tests for post-hoc calibration wired into confidence fusion (research C2,
production integration).
"""
from threat_intel_aggregator.feed_collection import confidence_fusion as cf
from threat_intel_aggregator.feed_collection.confidence_fusion import (
    calibrate_confidence,
    fuse_confidence,
    fuse_with_penalty,
)


def test_apply_calibration_false_matches_raw_fusion():
    raw = fuse_with_penalty(0.8, 0.9, llm_is_valid=True, apply_calibration=False)
    assert raw == fuse_confidence(0.8, 0.9)


def test_regex_only_path_is_never_calibrated():
    # No LLM confidence → regex-only fallback; calibrator must not touch it.
    assert (
        fuse_with_penalty(0.7, None, apply_calibration=True)
        == fuse_with_penalty(0.7, None, apply_calibration=False)
    )


def test_calibration_output_stays_in_unit_interval():
    for regex_c, llm_c, valid in [(0.8, 0.9, False), (0.9, 0.95, True), (0.3, 0.2, True)]:
        out = fuse_with_penalty(regex_c, llm_c, llm_is_valid=valid, apply_calibration=True)
        assert 0.0 <= out <= 1.0


def test_calibration_applied_when_fitted_calibrator_present():
    # The repo ships data/evaluation/fitted_calibrator.json; with it loaded the
    # calibrated score for a rejected-but-genuine IOC differs from the raw fusion.
    cf._calibrator = None
    cf._calibrator_loaded = False
    raw = fuse_with_penalty(0.8, 0.9, llm_is_valid=False, apply_calibration=False)
    cal = fuse_with_penalty(0.8, 0.9, llm_is_valid=False, apply_calibration=True)
    if cf._get_calibrator() is not None:        # calibrator file is present
        assert cal != raw
    else:                                       # graceful fallback
        assert cal == raw


def test_calibrate_confidence_graceful_without_calibrator(monkeypatch):
    # Point at a non-existent calibrator and reset the lazy singleton.
    monkeypatch.setattr(cf, "_CALIBRATOR_PATH", "/nonexistent/calibrator.json")
    monkeypatch.setattr(cf, "_calibrator", None)
    monkeypatch.setattr(cf, "_calibrator_loaded", False)
    assert calibrate_confidence(0.42) == 0.42
    assert calibrate_confidence(0.0) == 0.0
    assert calibrate_confidence(1.0) == 1.0


def test_calibrator_is_loaded_only_once(monkeypatch):
    calls = []
    real_exists = cf.os.path.exists

    def counting_exists(path):
        calls.append(path)
        return real_exists(path)

    monkeypatch.setattr(cf.os.path, "exists", counting_exists)
    monkeypatch.setattr(cf, "_calibrator", None)
    monkeypatch.setattr(cf, "_calibrator_loaded", False)
    cf._get_calibrator()
    cf._get_calibrator()
    cf._get_calibrator()
    # The file existence check runs once despite three calls (lazy singleton).
    assert calls.count(cf._CALIBRATOR_PATH) == 1
