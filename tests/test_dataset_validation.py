"""Tests for dataset_builder.validation — text-grounding checks."""
import pytest

from threat_intel_aggregator.evaluation.dataset_builder.validation import (
    MIN_DATASET_COVERAGE,
    format_grounding_report,
    grounding_report,
)


def _sample(sid, text, iocs):
    return {
        "id": sid,
        "text": text,
        "expected_iocs": [{"value": v, "type": t} for v, t in iocs],
    }


def test_fully_grounded_dataset_passes():
    samples = [
        _sample("a", "contact evil.com and 1.2.3.4 today",
                [("evil.com", "domain"), ("1.2.3.4", "ip")]),
    ]
    report = grounding_report(samples)
    assert report["coverage"] == 1.0
    assert report["ok"] is True
    assert report["ungrounded_samples"] == []


def test_scraped_labels_fail():
    """Labels absent from the text — the benchmark_dataset.json defect."""
    samples = [
        _sample("a", "A short prose summary with no indicators.",
                [("evil.com", "domain"), ("bad.net", "domain"), ("9.9.9.9", "ip")]),
    ]
    report = grounding_report(samples)
    assert report["coverage"] == 0.0
    assert report["ok"] is False
    assert report["ungrounded_samples"][0]["id"] == "a"


def test_defanged_text_still_matches_refanged_label():
    """A refanged label must match a defanged occurrence (deobfuscation-aware)."""
    samples = [
        _sample("a", "beacon to hxxp://evil[.]com observed",
                [("http://evil.com", "url")]),
    ]
    report = grounding_report(samples)
    assert report["coverage"] == 1.0
    assert report["ok"] is True


def test_partial_grounding_threshold():
    # 1 of 3 grounded = 33% -> below MIN_DATASET_COVERAGE, sample flagged.
    samples = [
        _sample("a", "only evil.com is here",
                [("evil.com", "domain"), ("gone.net", "domain"), ("8.8.8.8", "ip")]),
    ]
    report = grounding_report(samples)
    assert report["coverage"] < MIN_DATASET_COVERAGE
    assert report["ok"] is False
    assert report["ungrounded_samples"][0]["grounded"] == 1
    assert report["ungrounded_samples"][0]["total"] == 3


def test_empty_dataset_is_vacuously_ok():
    report = grounding_report([])
    assert report["coverage"] == 1.0
    assert report["ok"] is True
    assert report["n_iocs"] == 0


def test_format_report_renders_verdict():
    report = grounding_report([_sample("a", "evil.com", [("evil.com", "domain")])])
    text = format_grounding_report(report)
    assert "PASS" in text
    assert "text-grounding ratio" in text
