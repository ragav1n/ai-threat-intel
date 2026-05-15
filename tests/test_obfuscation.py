"""
Tests for the obfuscation-severity generator and obfuscation ablation
(research-paper contribution C1).

Two core properties are verified:
  * tiers T1–T4 are reversible by `deobfuscate_text()` *by construction*
    (so the OFF-vs-ON gap isolates the deobfuscation layer's contribution);
  * tier T5_adversarial is *held out* — `deobfuscate_text()` must NOT recover it
    (so the recovery measured on T1–T4 is demonstrably not circular).
"""
import pytest

from threat_intel_aggregator.evaluation.obfuscation_generator import (
    SEVERITY_TIERS,
    IN_RULESET_TIERS,
    ADVERSARIAL_TIERS,
    obfuscate_value,
    obfuscate_sample,
    build_obfuscated_samples,
)
from threat_intel_aggregator.feed_collection.ioc_deobfuscator import deobfuscate_text


# Representative IOCs spanning the types the generator handles.
_IOCS = [
    ("185.220.101.34", "ip"),
    ("evil-c2.ru", "domain"),
    ("http://malware-dist.ru/payload.exe", "url"),
    ("attacker@evil-phishing.xyz", "email"),
    ("CVE-2024-21762", "cve"),
    ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
]


# ── tier registry ──────────────────────────────────────────

def test_six_severity_tiers_in_order():
    assert SEVERITY_TIERS == [
        "T0_clean", "T1_defang", "T2_encode",
        "T3_unicode", "T4_combined", "T5_adversarial",
    ]


def test_ruleset_and_adversarial_tiers_partition():
    assert ADVERSARIAL_TIERS == ["T5_adversarial"]
    assert set(IN_RULESET_TIERS).isdisjoint(ADVERSARIAL_TIERS)
    assert set(IN_RULESET_TIERS) | {"T0_clean"} | set(ADVERSARIAL_TIERS) == set(SEVERITY_TIERS)


# ── T0 control ─────────────────────────────────────────────

@pytest.mark.parametrize("value,ioc_type", _IOCS)
def test_t0_clean_is_identity(value, ioc_type):
    assert obfuscate_value(value, ioc_type, "T0_clean") == value


# ── T1–T4: reversible by construction ──────────────────────

@pytest.mark.parametrize("tier", IN_RULESET_TIERS)
@pytest.mark.parametrize("value,ioc_type", _IOCS)
def test_in_ruleset_tiers_are_reversible(tier, value, ioc_type):
    """deobfuscate_text() must recover the canonical value for T1–T4."""
    obf = obfuscate_value(value, ioc_type, tier)
    recovered, _ = deobfuscate_text(obf)
    assert value in recovered, (
        f"{tier} {ioc_type}: {value!r} not recovered from {obf!r} -> {recovered!r}"
    )


@pytest.mark.parametrize("tier", ["T1_defang", "T2_encode"])
def test_in_ruleset_tiers_actually_change_text(tier):
    # Non-hash IOCs must genuinely be altered (otherwise the tier is a no-op).
    assert obfuscate_value("evil-c2.ru", "domain", tier) != "evil-c2.ru"
    assert obfuscate_value("185.220.101.34", "ip", tier) != "185.220.101.34"


# ── T5: held-out adversarial, must NOT be reversible ───────

@pytest.mark.parametrize("value,ioc_type", _IOCS)
def test_adversarial_tier_changes_every_ioc(value, ioc_type):
    assert obfuscate_value(value, ioc_type, "T5_adversarial") != value


@pytest.mark.parametrize("value,ioc_type", _IOCS)
def test_adversarial_tier_is_not_reversible(value, ioc_type):
    """The whole point of T5: the deobfuscator cannot recover it."""
    obf = obfuscate_value(value, ioc_type, "T5_adversarial")
    recovered, _ = deobfuscate_text(obf)
    assert value not in recovered


def test_adversarial_domain_becomes_non_ascii():
    obf = obfuscate_value("evil-c2.ru", "domain", "T5_adversarial")
    assert not obf.isascii()


def test_adversarial_ip_and_hash_use_spacing_not_homoglyphs():
    assert " " in obfuscate_value("185.220.101.34", "ip", "T5_adversarial")
    assert " " in obfuscate_value("d41d8cd98f00b204e9800998ecf8427e", "md5", "T5_adversarial")


# ── sample-level helpers ───────────────────────────────────

def test_benign_sample_with_no_iocs_is_unchanged():
    text = "The meeting is scheduled for 10:30 AM in conference room 3."
    for tier in SEVERITY_TIERS:
        assert obfuscate_sample(text, [], tier) == text


def test_obfuscate_sample_replaces_ioc_occurrence():
    text = "C2 server at evil-c2.ru was seen."
    out = obfuscate_sample(text, [{"value": "evil-c2.ru", "type": "domain"}], "T1_defang")
    assert "evil-c2.ru" not in out
    assert "evil-c2[.]ru" in out


def test_build_obfuscated_samples_preserves_expected_iocs():
    samples = [{
        "text": "C2 at evil-c2.ru today.",
        "expected_iocs": [{"value": "evil-c2.ru", "type": "domain"}],
        "category": "true_positive",
    }]
    out = build_obfuscated_samples(samples, "T3_unicode")
    assert out[0]["expected_iocs"] == samples[0]["expected_iocs"]  # canonical, untouched
    assert out[0]["text"] != samples[0]["text"]                    # text obfuscated


def test_longest_ioc_replaced_first_avoids_double_obfuscation():
    # The URL contains the domain as a substring; URL must be replaced as a unit.
    text = "See http://evil-c2.ru/x and evil-c2.ru."
    iocs = [
        {"value": "http://evil-c2.ru/x", "type": "url"},
        {"value": "evil-c2.ru", "type": "domain"},
    ]
    out = obfuscate_sample(text, iocs, "T1_defang")
    assert "hxxp://evil-c2[.]ru/x" in out
