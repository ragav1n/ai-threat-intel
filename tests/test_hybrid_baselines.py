"""
Tests for the pipeline/ioc-finder hybrid compositions (research-paper
contribution C1, extension — support for `scripts/run_hybrid_study.py`).

The candidate-filter tests run offline. The composition tests need
`ioc-finder` installed and skip cleanly when it is not.
"""
import pytest

from threat_intel_aggregator.evaluation.baseline_comparison import (
    BASELINES, _apply_pipeline_filters,
)
from threat_intel_aggregator.evaluation.bootstrap_ci import (
    compute_paired_bootstrap_delta,
)
from threat_intel_aggregator.evaluation.obfuscation_generator import (
    build_obfuscated_samples,
)

_SAMPLES = [
    {
        "text": ("Beacon resolves evil-c2.ru and fetches "
                 "http://evil-c2.ru/payload.exe from 185.220.101.34."),
        "expected_iocs": [
            {"value": "evil-c2.ru", "type": "domain"},
            {"value": "http://evil-c2.ru/payload.exe", "type": "url"},
            {"value": "185.220.101.34", "type": "ip"},
        ],
        "category": "report",
    },
    {
        "text": "No indicators in this paragraph at all.",
        "expected_iocs": [],
        "category": "report",
    },
]


# ── Candidate filters ──────────────────────────────────────

def test_filters_drop_private_ip_and_keep_public():
    kept = _apply_pipeline_filters({("192.168.1.10", "ip"), ("185.220.101.34", "ip")})
    assert kept == {("185.220.101.34", "ip")}


def test_filters_drop_invalid_ip():
    assert _apply_pipeline_filters({("999.1.1.1", "ip")}) == set()


def test_filters_drop_file_extension_masquerading_as_domain():
    kept = _apply_pipeline_filters({("payload.exe", "domain"), ("evil-c2.ru", "domain")})
    assert kept == {("evil-c2.ru", "domain")}


def test_filters_leave_hashes_and_cves_untouched():
    candidates = {("a" * 64, "sha256"), ("cve-2023-1234", "cve")}
    assert _apply_pipeline_filters(candidates) == candidates


def test_url_domain_dedup_is_optional():
    candidates = {("evil-c2.ru", "domain"), ("http://evil-c2.ru/payload.exe", "url")}

    deduped = _apply_pipeline_filters(candidates, dedup_url_domains=True)
    assert ("evil-c2.ru", "domain") not in deduped

    kept = _apply_pipeline_filters(candidates, dedup_url_domains=False)
    assert ("evil-c2.ru", "domain") in kept


# ── Compositions ───────────────────────────────────────────

@pytest.fixture
def ioc_finder_available():
    pytest.importorskip("ioc_finder", reason="ioc-finder not installed")


def test_deobfuscation_makes_ioc_finder_tier_invariant(ioc_finder_available):
    """The T3 unicode tier is what collapses raw ioc-finder; deobfuscation
    should hand it the same text it would have seen on clean input."""
    raw = BASELINES["ioc_finder"][1]
    deobf = BASELINES["ioc_finder_deobf"][1]

    clean = build_obfuscated_samples(_SAMPLES, "T0_clean")[0]["text"]
    obfuscated = build_obfuscated_samples(_SAMPLES, "T3_unicode")[0]["text"]
    assert obfuscated != clean

    assert raw(obfuscated) != raw(clean)
    assert deobf(obfuscated) == deobf(clean)


def test_union_and_intersection_bracket_their_components(ioc_finder_available):
    text = _SAMPLES[0]["text"]
    ours = BASELINES["our_pipeline"][1](text)
    theirs = BASELINES["ioc_finder_deobf"][1](text)

    union = BASELINES["hybrid_union"][1](text)
    intersect = BASELINES["hybrid_intersect"][1](text)

    assert ours <= union and theirs <= union
    assert intersect <= ours and intersect <= theirs


def test_filtered_hybrid_is_a_subset_of_the_union(ioc_finder_available):
    text = _SAMPLES[0]["text"]
    assert BASELINES["hybrid_filtered"][1](text) <= BASELINES["hybrid_union"][1](text)


# ── Paired bootstrap ───────────────────────────────────────

def _samples(hit: bool):
    return [
        {"expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
         "extracted_iocs": [{"value": "1.2.3.4", "type": "ip"}] if hit else []}
        for _ in range(12)
    ]


def test_paired_delta_is_zero_against_itself():
    same = _samples(hit=True)
    delta = compute_paired_bootstrap_delta(same, same, n_iterations=100)["f1"]
    assert delta.delta == 0.0
    assert not delta.significant
    assert delta.p_value == 1.0


def test_paired_delta_detects_total_dominance():
    delta = compute_paired_bootstrap_delta(
        _samples(hit=False), _samples(hit=True), n_iterations=100)["f1"]
    assert delta.delta == pytest.approx(1.0)
    assert delta.significant
    assert delta.p_value == 0.0


def test_paired_delta_reports_all_three_metrics():
    out = compute_paired_bootstrap_delta(
        _samples(hit=False), _samples(hit=True), n_iterations=50)
    assert set(out) == {"precision", "recall", "f1"}
    assert out["f1"].n_iterations == 50
    assert out["f1"].n_samples == 12


def test_paired_delta_rejects_misaligned_samples():
    with pytest.raises(ValueError, match="aligned"):
        compute_paired_bootstrap_delta(_samples(True)[:3], _samples(True), n_iterations=10)


def test_paired_delta_is_deterministic():
    a, b = _samples(hit=False), _samples(hit=True)
    first = compute_paired_bootstrap_delta(a, b, n_iterations=100)["f1"].to_dict()
    second = compute_paired_bootstrap_delta(a, b, n_iterations=100)["f1"].to_dict()
    assert first == second
