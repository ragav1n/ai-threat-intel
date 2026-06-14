"""
Tests for the baseline-vs-obfuscation comparison (research-paper
contribution C1, support for `run_obfuscation_baselines.py`).

Uses a tiny synthetic sample set and the offline-fast baselines
(`regex_only`, `our_pipeline`) so the suite stays fast and doesn't require
`iocextract`/`ioc-finder` to be installed.
"""
from threat_intel_aggregator.evaluation.ablation_study import (
    format_obfuscation_baselines_table,
    run_obfuscation_baseline_comparison,
)
from threat_intel_aggregator.evaluation.obfuscation_generator import ADVERSARIAL_TIERS

_BASELINES = ["regex_only", "our_pipeline"]

_SAMPLES = [
    {
        "text": "Malware connects to 185.220.101.34 and hxxp://evil-c2[.]ru/payload.exe",
        "expected_iocs": [
            {"value": "185.220.101.34", "type": "ip"},
            {"value": "http://evil-c2.ru/payload.exe", "type": "url"},
        ],
        "category": "report",
    },
    {
        "text": "No indicators in this paragraph at all.",
        "expected_iocs": [],
        "category": "report",
    },
]


def test_run_obfuscation_baseline_comparison_shape():
    results = run_obfuscation_baseline_comparison(
        samples=_SAMPLES,
        tiers=["T0_clean", "T1_defang"],
        baselines=_BASELINES,
        n_iterations=20,
    )

    assert set(results) == {"T0_clean", "T1_defang"}
    for tier_results in results.values():
        assert set(tier_results) == set(_BASELINES)
        for entry in tier_results.values():
            for key in ("precision", "recall", "f1", "true_positives",
                         "false_positives", "false_negatives", "per_type", "bootstrap"):
                assert key in entry
            assert "f1" in entry["bootstrap"]
            assert "point_estimate" in entry["bootstrap"]["f1"]


def test_format_obfuscation_baselines_table_marks_adversarial_tier():
    tiers = ["T0_clean", "T5_adversarial"]
    results = run_obfuscation_baseline_comparison(
        samples=_SAMPLES, tiers=tiers, baselines=_BASELINES, n_iterations=10)

    table = format_obfuscation_baselines_table(results, _BASELINES)

    assert "T0_clean" in table
    assert "T5_adversarial" in table
    assert "*" in table
    assert "T5_adversarial" in ADVERSARIAL_TIERS
