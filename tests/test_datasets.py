"""
Tests for the evaluation dataset registry / loader.
"""
import pytest

from threat_intel_aggregator.evaluation.datasets import (
    DATASET_PATHS,
    available_datasets,
    load_samples,
    _canonical_type,
    _normalize_sample,
)

_SAMPLE_KEYS = {"id", "text", "expected_iocs", "category"}


# ── registry ────────────────────────────────────────────────

def test_available_datasets_includes_synthetic_and_registered():
    avail = available_datasets()
    assert avail[0] == "synthetic"
    assert set(DATASET_PATHS).issubset(set(avail))


# ── type canonicalisation ───────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("hash_sha256", "sha256"),
    ("HASH_SHA1", "sha1"),
    ("FileHash-MD5", "md5"),
    ("ipv4", "ip"),
    ("ip-src", "ip"),
    ("hostname", "domain"),
    ("domain", "domain"),     # already canonical
    ("cve", "cve"),
    ("weird_type", "weird_type"),  # unknown passes through
])
def test_canonical_type(raw, expected):
    assert _canonical_type(raw) == expected


# ── schema normalisation ────────────────────────────────────

def test_normalize_standard_schema():
    raw = {
        "id": "x1", "text": "evil.com seen",
        "expected_iocs": [{"value": "evil.com", "type": "domain"}],
        "category": "true_positive",
    }
    out = _normalize_sample(raw)
    assert set(out) == _SAMPLE_KEYS
    assert out["expected_iocs"] == [{"value": "evil.com", "type": "domain"}]


def test_normalize_otx_schema_maps_rawtext_and_groundtruth():
    raw = {
        "id": "otx1",
        "raw_text": "hash abc seen",
        "ground_truth": [{"value": "abc", "type": "hash_sha256"}],
    }
    out = _normalize_sample(raw)
    assert out["text"] == "hash abc seen"
    assert out["expected_iocs"] == [{"value": "abc", "type": "sha256"}]
    assert out["category"] == "true_positive"  # default when absent


def test_normalize_drops_incomplete_iocs():
    raw = {
        "text": "t",
        "expected_iocs": [
            {"value": "evil.com", "type": "domain"},
            {"value": "", "type": "domain"},      # no value
            {"type": "ip"},                        # no value key
            "not-a-dict",                          # wrong shape
        ],
    }
    out = _normalize_sample(raw)
    assert out["expected_iocs"] == [{"value": "evil.com", "type": "domain"}]


# ── end-to-end loading of real files ────────────────────────

def test_load_synthetic_dataset():
    samples = load_samples("synthetic")
    assert len(samples) == 122
    for s in samples:
        assert set(s) == _SAMPLE_KEYS


def test_load_real_world_v2_dataset():
    samples = load_samples("real_world_v2")
    assert len(samples) > 100
    assert sum(len(s["expected_iocs"]) for s in samples) > 400
    for s in samples[:20]:
        assert set(s) == _SAMPLE_KEYS
        assert isinstance(s["text"], str)


def test_load_otx_dataset_is_type_canonicalised():
    samples = load_samples("otx")
    assert len(samples) > 0
    types = {e["type"] for s in samples for e in s["expected_iocs"]}
    # The OTX file labels hashes "hash_sha256"; loader must canonicalise it.
    assert "hash_sha256" not in types
    assert types  # non-empty


def test_load_accepts_direct_path():
    samples = load_samples(DATASET_PATHS["real_world_v2"])
    assert len(samples) > 100
