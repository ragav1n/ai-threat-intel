"""
Obfuscation-Severity Generator for the IOC-extraction evaluation harness.

Programmatically applies obfuscation transformations to the IOC occurrences
inside ground-truth samples, at graded severity tiers. The *expected* IOCs are
left in canonical (clean) form — a correct deobfuscation + extraction pipeline
must recover them regardless of tier.

Severity tiers
--------------
  T0_clean      — no change (control)
  T1_defang     — analyst-style defanging: hxxp, [.], (dot), [at]
  T2_encode     — encoding: decimal/hex IPs, numeric HTML entities, CVE separators
  T3_unicode    — unicode evasion: homoglyphs, zero-width chars, fullwidth dots
  T4_combined   — defanging + unicode evasion stacked together
  T5_adversarial — transformations OUTSIDE the deobfuscator's rule set:
                   extended Unicode confusables (Greek/Armenian/extended-Cyrillic
                   homoglyphs absent from the deobfuscator's 9-entry map), digit
                   spacing, and hash chunking. This is the *held-out adversarial*
                   tier — deliberately NOT reversible by `deobfuscate_text()`.

Tiers T1–T4 are reversible by `deobfuscate_text()` by construction, so the gap
between deobfuscation OFF vs ON on those tiers isolates the symbolic layer's
contribution. Tier T5 is held out: it measures where rule-based deobfuscation
*breaks*, keeping the study honest (the recovery is not circular) and motivating
learned deobfuscation / the complementary role of an LLM.

Note on hashes: MD5/SHA1/SHA256 are hex strings with no dots/scheme, so they
cannot be meaningfully defanged or numerically encoded — they are only altered
by the unicode tiers (T3/T4). This asymmetry is a finding worth reporting.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List

logger = logging.getLogger(__name__)

# Ordered severity tiers (T0 first = control, T5 = held-out adversarial).
SEVERITY_TIERS: List[str] = [
    "T0_clean",
    "T1_defang",
    "T2_encode",
    "T3_unicode",
    "T4_combined",
    "T5_adversarial",
]

# Tiers reversible by `deobfuscate_text()` by construction (used for the
# "force multiplier" claim) vs. the held-out adversarial tier.
IN_RULESET_TIERS: List[str] = ["T1_defang", "T2_encode", "T3_unicode", "T4_combined"]
ADVERSARIAL_TIERS: List[str] = ["T5_adversarial"]

# Zero-width space inserted between characters (stripped by the deobfuscator).
_ZWSP = "​"

# Latin -> Cyrillic homoglyph map — exactly the inverse of the deobfuscator's
# 9-entry homoglyph table, so tiers T3/T4 stay reversible.
_HOMOGLYPHS: Dict[str, str] = {
    "a": "а", "c": "с", "e": "е", "o": "о",
    "p": "р", "x": "х", "y": "у", "i": "і", "j": "ј",
}

# ADVERSARIAL homoglyph map — Greek / Armenian / extended-Cyrillic confusables
# that are visually near-identical to ASCII letters but are NOT in the
# deobfuscator's 9-entry table and are NOT folded to Latin by NFKC. An IDN
# "homograph attack". Recoverable in principle via a full Unicode TR39
# confusables table — which the deobfuscator does not implement.
_ADV_HOMOGLYPHS: Dict[str, str] = {
    "a": "α",  # U+03B1 Greek small alpha
    "c": "ϲ",  # U+03F2 Greek lunate sigma
    "d": "ԁ",  # U+0501 Cyrillic small komi de
    "e": "ҽ",  # U+04BD Cyrillic small abkhasian che
    "h": "һ",  # U+04BB Cyrillic small shha
    "i": "ι",  # U+03B9 Greek small iota
    "j": "ϳ",  # U+03F3 Greek letter yot
    "l": "ӏ",  # U+04CF Cyrillic small palochka
    "n": "ո",  # U+0578 Armenian small vo
    "o": "ο",  # U+03BF Greek small omicron
    "p": "ρ",  # U+03C1 Greek small rho
    "s": "ѕ",  # U+0455 Cyrillic small dze
    "x": "χ",  # U+03C7 Greek small chi
    "y": "ү",  # U+04AF Cyrillic small straight u
}


def _zero_width(text: str) -> str:
    """Insert a zero-width space between every character."""
    return _ZWSP.join(text)


def _homoglyph(text: str) -> str:
    """Replace Latin characters with confusable Cyrillic homoglyphs (reversible)."""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def _adv_homoglyph(text: str) -> str:
    """Replace Latin characters with extended confusables outside the ruleset."""
    return "".join(_ADV_HOMOGLYPHS.get(ch.lower(), ch) for ch in text)


def _space_digits(text: str) -> str:
    """Insert a space between every pair of consecutive digits."""
    out: List[str] = []
    for i, ch in enumerate(text):
        out.append(ch)
        if ch.isdigit() and i + 1 < len(text) and text[i + 1].isdigit():
            out.append(" ")
    return "".join(out)


def _chunk(text: str, size: int = 8) -> str:
    """Split a string into fixed-size chunks joined by spaces."""
    return " ".join(text[i:i + size] for i in range(0, len(text), size))


def _ip_to_decimal(ip: str) -> str:
    """Convert a dotted IPv4 string to its 32-bit decimal integer form."""
    try:
        o = [int(p) for p in ip.split(".")]
        if len(o) != 4 or any(not 0 <= x <= 255 for x in o):
            return ip
        return str((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3])
    except (ValueError, IndexError):
        return ip


def _html_entities(text: str, chars: str = ".@-/") -> str:
    """Replace each character in `chars` with its numeric HTML entity."""
    return "".join(f"&#{ord(ch)};" if ch in chars else ch for ch in text)


# --- Per-type obfuscation -------------------------------------------------

def _obfuscate_ip(value: str, tier: str) -> str:
    if tier == "T1_defang":
        return value.replace(".", "[.]")
    if tier == "T2_encode":
        return _ip_to_decimal(value)
    if tier == "T3_unicode":
        return _zero_width(value.replace(".", "．"))  # fullwidth dot + ZWSP
    if tier == "T4_combined":
        return _zero_width(value.replace(".", "[．]"))
    return value


def _obfuscate_domain(value: str, tier: str) -> str:
    if tier == "T1_defang":
        return value.replace(".", "[.]")
    if tier == "T2_encode":
        return _html_entities(value, chars=".-")
    if tier == "T3_unicode":
        return _zero_width(_homoglyph(value))
    if tier == "T4_combined":
        return _zero_width(_homoglyph(value).replace(".", "[.]"))
    return value


def _obfuscate_url(value: str, tier: str) -> str:
    if tier == "T1_defang":
        v = value
        if v.lower().startswith("http"):
            v = v.replace("http", "hxxp", 1)
        elif v.lower().startswith("ftp"):
            v = v.replace("ftp", "fxp", 1)
        return v.replace(".", "[.]")
    if tier == "T2_encode":
        return _html_entities(value, chars=".-")
    if tier == "T3_unicode":
        return _zero_width(_homoglyph(value))
    if tier == "T4_combined":
        v = value
        if v.lower().startswith("http"):
            v = v.replace("http", "hxxp", 1)
        return _zero_width(_homoglyph(v).replace(".", "[.]"))
    return value


def _obfuscate_email(value: str, tier: str) -> str:
    if tier == "T1_defang":
        return value.replace("@", "[at]").replace(".", "[.]")
    if tier == "T2_encode":
        return _html_entities(value, chars=".@-")
    if tier == "T3_unicode":
        return _zero_width(_homoglyph(value))
    if tier == "T4_combined":
        return _zero_width(_homoglyph(value).replace("@", "[at]").replace(".", "[.]"))
    return value


def _obfuscate_cve(value: str, tier: str) -> str:
    if tier == "T1_defang":
        return value.replace("-", "_")
    if tier == "T2_encode":
        return _html_entities(value, chars="-")
    if tier == "T3_unicode":
        return _zero_width(value)
    if tier == "T4_combined":
        return _zero_width(value.replace("-", "_"))
    return value


def _obfuscate_hash(value: str, tier: str) -> str:
    # Hashes are bare hex — only unicode-evasion tiers can touch them.
    if tier in ("T3_unicode", "T4_combined"):
        return _zero_width(_homoglyph(value))
    return value


def _obfuscate_adversarial(value: str, ioc_type: str) -> str:
    """
    Held-out adversarial obfuscation — by design NOT reversible by the
    deobfuscator's rule set. Recoverable in principle, just not by this ruleset.
    """
    if ioc_type in ("md5", "sha1", "sha256"):
        return _chunk(value, 8)            # break the fixed-length hash regex
    if ioc_type in ("ip", "cve"):
        return _space_digits(value)        # break contiguous-digit matching
    # domain / url / email / ipv6: extended-confusable homograph attack
    return _adv_homoglyph(value)


_DISPATCH = {
    "ip": _obfuscate_ip,
    "ipv6": _obfuscate_domain,   # colon-separated; ZWSP/homoglyph still apply
    "domain": _obfuscate_domain,
    "url": _obfuscate_url,
    "email": _obfuscate_email,
    "cve": _obfuscate_cve,
    "md5": _obfuscate_hash,
    "sha1": _obfuscate_hash,
    "sha256": _obfuscate_hash,
}


def obfuscate_value(value: str, ioc_type: str, tier: str) -> str:
    """Obfuscate a single IOC value at the given severity tier."""
    if tier == "T0_clean":
        return value
    norm_type = ioc_type.strip().lower()
    if tier == "T5_adversarial":
        return _obfuscate_adversarial(value, norm_type)
    fn = _DISPATCH.get(norm_type)
    return fn(value, tier) if fn else value


def obfuscate_sample(text: str, expected_iocs: List[dict], tier: str) -> str:
    """
    Obfuscate every expected-IOC occurrence inside a sample's text.

    Args:
        text:          The original sample text.
        expected_iocs: List of {"value", "type"} dicts (canonical/clean values).
        tier:          One of SEVERITY_TIERS.

    Returns:
        Text with IOC occurrences replaced by their obfuscated form. Benign text
        with no expected IOCs is returned unchanged (so false-positive behaviour
        on negatives stays controlled across tiers).
    """
    if tier == "T0_clean" or not expected_iocs:
        return text

    new_text = text
    # Replace longest values first so URLs are obfuscated before any domain/IP
    # substrings they contain (prevents double transformation). Matching is
    # case-insensitive because real reports often differ in case from the
    # canonical ground-truth value (e.g. CVE-2023-1234 vs cve-2023-1234).
    for e in sorted(expected_iocs, key=lambda x: len(x["value"]), reverse=True):
        value = e["value"]
        obf = obfuscate_value(value, e["type"], tier)
        if obf == value:
            continue
        pattern = re.compile(re.escape(value), re.IGNORECASE)
        new_text = pattern.sub(lambda m, _o=obf: _o, new_text)
    return new_text


def build_obfuscated_samples(samples: List[dict], tier: str) -> List[dict]:
    """
    Produce a tier-obfuscated copy of a list of ground-truth samples.

    Input/output samples are dicts with keys: text, expected_iocs, category.
    `expected_iocs` are preserved verbatim (canonical) — only `text` changes.
    """
    out: List[dict] = []
    for s in samples:
        out.append({
            "text": obfuscate_sample(s["text"], s.get("expected_iocs", []), tier),
            "expected_iocs": s.get("expected_iocs", []),
            "category": s.get("category", ""),
        })
    return out
