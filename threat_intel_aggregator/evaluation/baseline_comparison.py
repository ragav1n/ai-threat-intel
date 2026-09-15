"""
Baseline Comparison: compare our pipeline against multiple external tools.

Supported baselines:
  1. iocextract        (InQuest)         — popular regex-based IOC extraction
  2. ioc-finder        (Floyd Hightower) — grammar-based extraction with defanging
  3. spacy_ner         (spaCy en_core_web_sm) — generic NER (shows domain-gap)
  4. Regex Only        — our own regex patterns with no filtering/deobfuscation
  5. our_pipeline      — regex + deobfuscation + confidence filtering
  6. our_pipeline_llm  — full pipeline with LLM verification

Runs all extractors on the same ground-truth dataset and produces
a side-by-side P/R/F1 comparison table, per IOC type.
"""

import re
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List, Dict, Any, Set, Tuple, Union

logger = logging.getLogger(__name__)


@dataclass
class BaselineResult:
    """Metrics for a single extractor."""
    name: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    per_type: Dict[str, Dict[str, int]] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        d = self.true_positives + self.false_positives
        return self.true_positives / d if d > 0 else 0.0

    @property
    def recall(self) -> float:
        d = self.true_positives + self.false_negatives
        return self.true_positives / d if d > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def per_type_metrics(self) -> Dict[str, Dict[str, float]]:
        result = {}
        for t, counts in self.per_type.items():
            tp = counts.get("tp", 0)
            fp = counts.get("fp", 0)
            fn = counts.get("fn", 0)
            p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
            result[t] = {"precision": p, "recall": r, "f1": f, "tp": tp, "fp": fp, "fn": fn}
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "per_type": {
                t: {k: round(v, 4) if isinstance(v, float) else v for k, v in m.items()}
                for t, m in self.per_type_metrics().items()
            },
        }


def _normalize(v: str) -> str:
    return v.strip().lower()


# ── Extractor: iocextract (InQuest) ─────────────────────────

def _extract_with_iocextract(text: str) -> Set[Tuple[str, str]]:
    """Extract IOCs using iocextract (InQuest) library."""
    try:
        import iocextract
    except ImportError:
        logger.warning("iocextract not installed — skipping baseline")
        return set()

    results: Set[Tuple[str, str]] = set()

    for ip in iocextract.extract_ipv4s(text, refang=True):
        results.add((_normalize(ip), "ip"))

    for url in iocextract.extract_urls(text, refang=True):
        results.add((_normalize(url), "url"))

    for h in iocextract.extract_hashes(text):
        h_clean = _normalize(h)
        if len(h_clean) == 32:
            results.add((h_clean, "md5"))
        elif len(h_clean) == 40:
            results.add((h_clean, "sha1"))
        elif len(h_clean) == 64:
            results.add((h_clean, "sha256"))

    for email in iocextract.extract_emails(text, refang=True):
        results.add((_normalize(email), "email"))

    for m in re.finditer(r"\bCVE-\d{4}-\d{4,}\b", text):
        results.add((_normalize(m.group()), "cve"))

    return results


# ── Extractor: ioc-finder (Floyd Hightower) ─────────────────

def _extract_with_ioc_finder(text: str) -> Set[Tuple[str, str]]:
    """Extract IOCs using ioc-finder library."""
    try:
        from ioc_finder import find_iocs
    except ImportError:
        logger.warning("ioc-finder not installed — skipping baseline")
        return set()

    results: Set[Tuple[str, str]] = set()

    try:
        iocs = find_iocs(text)
    except Exception as e:
        logger.warning(f"ioc-finder error: {e}")
        return results

    for ip in iocs.get("ipv4s", []):
        results.add((_normalize(ip), "ip"))

    for ip in iocs.get("ipv6s", []):
        results.add((_normalize(ip), "ipv6"))

    for domain in iocs.get("domains", []):
        results.add((_normalize(domain), "domain"))

    for url in iocs.get("urls", []):
        results.add((_normalize(url), "url"))

    for h in iocs.get("md5s", []):
        results.add((_normalize(h), "md5"))

    for h in iocs.get("sha1s", []):
        results.add((_normalize(h), "sha1"))

    for h in iocs.get("sha256s", []):
        results.add((_normalize(h), "sha256"))

    for email in iocs.get("email_addresses", []):
        results.add((_normalize(email), "email"))

    for cve in iocs.get("cves", []):
        results.add((_normalize(cve), "cve"))

    return results


# ── Extractor: Regex Only (no filtering) ────────────────────

def _extract_regex_only(text: str) -> Set[Tuple[str, str]]:
    """Extract IOCs using raw regex patterns — no deobfuscation, no filtering."""
    from threat_intel_aggregator.enums import IOCType
    from threat_intel_aggregator.feed_collection.ioc_extractor import IOC_PATTERNS, is_valid_ip

    results: Set[Tuple[str, str]] = set()

    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in re.finditer(pattern, text):
            item = match.group()
            if ioc_type == IOCType.IP and not is_valid_ip(item):
                continue
            results.add((_normalize(item), str(ioc_type)))

    return results


# ── Extractor: Our Pipeline ────────────────────────────────

def _extract_with_our_pipeline(text: str) -> Set[Tuple[str, str]]:
    """Extract IOCs using our full pipeline."""
    from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence

    matches = extract_iocs_with_confidence(text, include_private_ips=False, min_confidence=0.0)
    return {(_normalize(m.value), str(m.ioc_type)) for m in matches}


def _extract_with_llm_pipeline(text: str) -> Set[Tuple[str, str]]:
    """Extract IOCs using full pipeline: regex + LLM verification + confidence fusion."""
    from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
    from threat_intel_aggregator.feed_collection.llm_ioc_verifier import get_llm_verifier
    from threat_intel_aggregator.feed_collection.confidence_fusion import fuse_with_penalty

    matches = extract_iocs_with_confidence(text, include_private_ips=False, min_confidence=0.0)
    if not matches:
        return set()

    verifier = get_llm_verifier()
    if not verifier.is_available():
        # Graceful fallback: return regex-only results
        return {(_normalize(m.value), str(m.ioc_type)) for m in matches}

    results = set()
    verified = verifier.batch_verify(matches, max_iocs=50)
    for v in verified:
        fused = fuse_with_penalty(
            v["regex_confidence"], v.get("llm_confidence"), v.get("is_valid_ioc")
        )
        if fused >= 0.3:  # Apply a reasonable threshold derived from tests
            results.add((_normalize(v["ioc"]), v["type"]))
    return results


# ── Extractor: deobfuscation + ioc-finder, and pipeline/ioc-finder hybrids ──
#
# C1 asks whether our deobfuscation layer is a *force multiplier*: ioc-finder
# beats our regex extractor on clean prose but collapses at T3+ (unicode), so
# the interesting configurations are the ones that give ioc-finder our
# deobfuscated text, and the ones that pool both candidate sets. Extraction is
# deterministic, so results are memoised per text -- the hybrids call the same
# two extractors repeatedly and ioc-finder is the slow step (~1 min per tier).

@lru_cache(maxsize=512)
def _cached_ioc_finder(text: str) -> frozenset:
    return frozenset(_extract_with_ioc_finder(text))


@lru_cache(maxsize=512)
def _cached_our_pipeline(text: str) -> frozenset:
    return frozenset(_extract_with_our_pipeline(text))


@lru_cache(maxsize=512)
def _cached_deobfuscate(text: str) -> str:
    from threat_intel_aggregator.feed_collection.ioc_deobfuscator import deobfuscate_text

    return deobfuscate_text(text)[0]


def _domain_is_blocked(domain: str, allow_code_hosting: bool = False) -> bool:
    """Blocklist test for a domain, matching `extract_iocs_with_confidence`.

    Checks the domain and every base suffix of it (so `www.cisa.gov` is caught
    by a `cisa.gov` entry), with the same code-hosting exemption the pipeline
    applies to URLs.
    """
    from threat_intel_aggregator.feed_collection.ioc_extractor import (
        CODE_HOSTING_DOMAINS, DOMAIN_BLACKLIST,
    )

    if allow_code_hosting and domain in CODE_HOSTING_DOMAINS:
        return False
    parts = domain.split(".")
    for i in range(max(1, len(parts) - 1)):
        base = ".".join(parts[i:])
        if base in DOMAIN_BLACKLIST and not (allow_code_hosting and base in CODE_HOSTING_DOMAINS):
            return True
    return domain in DOMAIN_BLACKLIST


def _apply_pipeline_filters(
    candidates: Set[Tuple[str, str]],
    include_private_ips: bool = False,
    dedup_url_domains: bool = True,
) -> Set[Tuple[str, str]]:
    """Apply our pipeline's validity/blocklist filters to any extractor's output.

    `extract_iocs_with_confidence` interleaves these checks with regex matching,
    so they cannot be reused directly on a third-party candidate set. This is
    the same ladder, lifted to operate on ``(value, type)`` pairs: IP validity
    and private/reserved-range rejection, domain and URL-domain blocklisting,
    URL-domain deduplication, and the file-extension guard that stops
    `payload.exe` being scored as a domain.

    The filters are keyed on IOC type only -- no gold label is consulted -- so
    this is a fair, non-leaking precision layer.
    """
    from threat_intel_aggregator.feed_collection.ioc_extractor import (
        FILE_EXTENSION_BLACKLIST, get_domain_from_url, is_private_ip, is_valid_ip,
        is_valid_ipv6,
    )

    urls = {v for v, t in candidates if t == "url"}
    kept: Set[Tuple[str, str]] = set()

    for value, ioc_type in candidates:
        if ioc_type == "ip":
            if not is_valid_ip(value):
                continue
            if not include_private_ips and is_private_ip(value):
                continue
            if _domain_is_blocked(value) or value in ("1.1.1.1", "8.8.8.8", "8.8.4.4"):
                continue

        elif ioc_type == "ipv6":
            if not is_valid_ipv6(value):
                continue

        elif ioc_type == "url":
            if _domain_is_blocked(get_domain_from_url(value), allow_code_hosting=True):
                continue

        elif ioc_type == "domain":
            if _domain_is_blocked(value):
                continue
            # Drop a bare domain that is already covered by an extracted URL.
            # PRISM scores such a domain as an indicator in its own right, so
            # this rule is a schema mismatch there rather than a precision
            # gain; `dedup_url_domains=False` measures its cost separately.
            if dedup_url_domains and any(value in url for url in urls):
                continue
            last_dot = value.rfind(".")
            if last_dot >= 0 and value[last_dot:] in FILE_EXTENSION_BLACKLIST:
                continue

        kept.add((value, ioc_type))

    return kept


def _extract_with_ioc_finder_deobf(text: str) -> Set[Tuple[str, str]]:
    """ioc-finder run on text our deobfuscation layer has already normalised."""
    return set(_cached_ioc_finder(_cached_deobfuscate(text)))


def _extract_hybrid_union(text: str) -> Set[Tuple[str, str]]:
    """Pooled candidates: our pipeline OR deobfuscation-fed ioc-finder."""
    return set(_cached_our_pipeline(text)) | _extract_with_ioc_finder_deobf(text)


def _extract_hybrid_intersection(text: str) -> Set[Tuple[str, str]]:
    """Agreement only: candidates both extractors return (precision-first)."""
    return set(_cached_our_pipeline(text)) & _extract_with_ioc_finder_deobf(text)


def _extract_hybrid_filtered(text: str) -> Set[Tuple[str, str]]:
    """The pooled candidate set, then our pipeline's precision filters."""
    return _apply_pipeline_filters(_extract_hybrid_union(text))


def _extract_ioc_finder_deobf_filtered(text: str) -> Set[Tuple[str, str]]:
    """ioc-finder on deobfuscated text, then our precision filters.

    Isolates the two things our pipeline contributes -- text normalisation and
    candidate filtering -- from its own regex candidate generation.
    """
    return _apply_pipeline_filters(_extract_with_ioc_finder_deobf(text))


def _extract_ioc_finder_deobf_filtered_nodedup(text: str) -> Set[Tuple[str, str]]:
    """As above, minus the rule that drops a domain appearing inside a URL."""
    return _apply_pipeline_filters(
        _extract_with_ioc_finder_deobf(text), dedup_url_domains=False)


# ── Extractor: spaCy NER (Generic NLP baseline) ─────────────

# Mapping from spaCy entity labels to IOC types we evaluate.
# spaCy's generic model wasn't trained on cybersecurity data, so this
# intentionally shows the 'domain gap' — our system should outperform it.
_SPACY_LABEL_TO_IOC_TYPE = {
    "ORG":      None,         # Often picks up company names — not useful for IOCs
    "GPE":      None,         # Geopolitical entities — not IOCs
    "PRODUCT":  None,         # Product names — not IOCs
    "EVENT":    None,         # Events — not IOCs
    # Only map entities that could be IOC-adjacent
    "CARDINAL": None,         # Numbers — no
    "PERSON":   None,         # People — no
}


def _extract_with_spacy_ner(text: str) -> Set[Tuple[str, str]]:
    """
    Extract IOC-like entities using spaCy's generic NER (en_core_web_sm).

    This is a 'generic NLP' baseline showing that domain-specific IOC
    extraction is necessary — spaCy NER alone misses most cybersecurity IOCs.

    Requires: pip install spacy && python -m spacy download en_core_web_sm
    """
    try:
        import spacy
    except ImportError:
        logger.warning("spaCy not installed — skipping spacy_ner baseline. Run: pip install spacy")
        return set()

    try:
        nlp = spacy.load("en_core_web_sm")
    except OSError:
        logger.warning(
            "spaCy model 'en_core_web_sm' not found — skipping. Run: "
            "python -m spacy download en_core_web_sm"
        )
        return set()

    results: Set[Tuple[str, str]] = set()
    doc = nlp(text[:100_000])  # spaCy has a token limit; cap to 100k chars

    # Use spaCy NER for what it CAN detect, then supplement with
    # pattern matching for what it CANNOT (IPs, hashes, CVEs)
    # This is fair — spaCy alone can't detect IOC types at all.
    import re as _re

    # IPs — spaCy doesn't label these, use simple regex
    for m in _re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text):
        results.add((_normalize(m.group()), "ip"))

    # CVEs — structured and easy to find
    for m in _re.finditer(r"\bCVE-\d{4}-\d{4,}\b", text, _re.IGNORECASE):
        results.add((_normalize(m.group()), "cve"))

    # URLs — spaCy sometimes captures these as ORG or misses them
    for m in _re.finditer(r"(?:https?|ftp)://[^\s\"'<>]+", text):
        results.add((_normalize(m.group()), "url"))

    # Named entities that spaCy flags — map to IOC types where possible
    for ent in doc.ents:
        # Domains: spaCy may label bare domains/hostnames as ORG/PRODUCT
        if ent.label_ in ("ORG", "PRODUCT") and "." in ent.text:
            token = _normalize(ent.text.strip())
            # Very rough domain heuristic
            if _re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", token):
                results.add((token, "domain"))

    return results


# ── Evaluation engine ──────────────────────────────────────

def _evaluate_extractor(
    name: str,
    extract_fn,
    samples: list,
    collect_per_sample: bool = False,
) -> Tuple[BaselineResult, List[dict]]:
    """Evaluate an extractor against ground-truth samples.

    Returns (BaselineResult, per_sample). `per_sample` is [] unless
    `collect_per_sample` is True, in which case it is a list aligned with
    `samples`, each entry ``{"expected_iocs": [...], "extracted_iocs": [...]}``
    with IOCs as ``{"value", "type"}`` dicts — the schema `compute_bootstrap_ci`
    expects. Values are already normalised, so bootstrap point estimates equal
    the aggregate `BaselineResult` metrics exactly.
    """
    result = BaselineResult(name=name)
    per_sample: List[dict] = []

    for sample in samples:
        expected_set: Set[Tuple[str, str]] = {
            (_normalize(e["value"]), e["type"].strip().lower())
            for e in sample.get("expected_iocs", [])
        }
        extracted_set = extract_fn(sample["text"])

        tp = expected_set & extracted_set
        fp = extracted_set - expected_set
        fn = expected_set - extracted_set

        result.true_positives += len(tp)
        result.false_positives += len(fp)
        result.false_negatives += len(fn)

        # sorted() keeps per_type insertion order deterministic across runs
        # (set iteration order varies with hash randomisation).
        all_types = {k[1] for k in expected_set | extracted_set}
        for t in sorted(all_types):
            if t not in result.per_type:
                result.per_type[t] = {"tp": 0, "fp": 0, "fn": 0}
            t_exp = {k for k in expected_set if k[1] == t}
            t_ext = {k for k in extracted_set if k[1] == t}
            result.per_type[t]["tp"] += len(t_exp & t_ext)
            result.per_type[t]["fp"] += len(t_ext - t_exp)
            result.per_type[t]["fn"] += len(t_exp - t_ext)

        if collect_per_sample:
            per_sample.append({
                "expected_iocs": [{"value": v, "type": t} for v, t in expected_set],
                "extracted_iocs": [{"value": v, "type": t} for v, t in extracted_set],
            })

    return result, per_sample


# ── Public API ─────────────────────────────────────────────

# Registry of available baselines
BASELINES = {
    "our_pipeline":     ("Our Pipeline (Regex)",       _extract_with_our_pipeline),
    "our_pipeline_llm": ("Our Pipeline + LLM",          _extract_with_llm_pipeline),
    "iocextract":       ("iocextract (InQuest)",        _extract_with_iocextract),
    "ioc_finder":       ("ioc-finder (Hightower)",      _extract_with_ioc_finder),
    "spacy_ner":        ("spaCy NER (Generic NLP)",     _extract_with_spacy_ner),
    "regex_only":       ("Regex Only (no filter)",      _extract_regex_only),
    # Deobfuscation-fed and pooled configurations (see C1 hybrid study).
    "ioc_finder_deobf":     ("ioc-finder + our deobf",      _extract_with_ioc_finder_deobf),
    "ioc_finder_deobf_flt": ("ioc-finder + deobf + filters", _extract_ioc_finder_deobf_filtered),
    "ioc_finder_deobf_flt_nd": ("ioc-finder + deobf + filters, no URL-domain dedup",
                                _extract_ioc_finder_deobf_filtered_nodedup),
    "hybrid_union":         ("Hybrid (union)",              _extract_hybrid_union),
    "hybrid_filtered":      ("Hybrid (union + filters)",    _extract_hybrid_filtered),
    "hybrid_intersect":     ("Hybrid (intersection)",       _extract_hybrid_intersection),
}


def run_baseline_comparison(
    samples: list = None,
    baselines: list = None,
    collect_per_sample: bool = False,
) -> Union[Dict[str, BaselineResult],
           Tuple[Dict[str, BaselineResult], Dict[str, List[dict]]]]:
    """
    Run comparison between our pipeline and selected baselines.

    Args:
        samples: Ground-truth sample dicts. Loads default if None.
        baselines: List of baseline keys (e.g. ["iocextract", "ioc_finder"]).
                   If None, runs all available baselines.
        collect_per_sample: when True, also return per-sample extractions for
                   bootstrap CIs (see `_evaluate_extractor`).

    Returns:
        When `collect_per_sample` is False (default): a dict mapping baseline
        key to BaselineResult. When True: a tuple
        ``(results, per_sample_by_baseline)``.
    """
    if samples is None:
        from threat_intel_aggregator.evaluation.ground_truth import GroundTruthDataset
        dataset = GroundTruthDataset()
        samples = [
            {
                "text": s.text,
                "expected_iocs": [e.to_dict() for e in s.expected_iocs],
                "category": s.category,
            }
            for s in dataset.samples
        ]

    baselines_to_run = baselines or list(BASELINES.keys())
    results: Dict[str, BaselineResult] = {}
    per_sample_by_baseline: Dict[str, List[dict]] = {}

    for key in baselines_to_run:
        if key not in BASELINES:
            logger.warning(f"Unknown baseline: {key}")
            continue
        name, fn = BASELINES[key]
        logger.info(f"Evaluating: {name}")
        result, per_sample = _evaluate_extractor(name, fn, samples, collect_per_sample)
        results[key] = result
        if collect_per_sample:
            per_sample_by_baseline[key] = per_sample

    if collect_per_sample:
        return results, per_sample_by_baseline
    return results


def format_comparison_table(results: Dict[str, BaselineResult]) -> str:
    """Format comparison results as a readable table."""
    lines = []
    lines.append("=" * 80)
    lines.append("  BASELINE COMPARISON")
    lines.append("=" * 80)
    lines.append(f"  {'Extractor':<30s} {'Prec':>7s} {'Recall':>7s} {'F1':>7s}  {'TP':>4s} {'FP':>4s} {'FN':>4s}")
    lines.append(f"  {'-'*30} {'-'*7} {'-'*7} {'-'*7}  {'-'*4} {'-'*4} {'-'*4}")

    for name, r in results.items():
        lines.append(
            f"  {r.name:<30s} {r.precision:6.1%} {r.recall:6.1%} {r.f1:6.1%}  "
            f"{r.true_positives:4d} {r.false_positives:4d} {r.false_negatives:4d}"
        )

    # Per-type comparison
    all_types = sorted(set().union(*(r.per_type.keys() for r in results.values())))
    lines.append("")
    lines.append("  Per-Type F1 Comparison:")

    # Build header with truncated names
    truncated_names = {key: r.name[:15] for key, r in results.items()}
    header = f"  {'Type':<10s}"
    for key in results:
        header += f" {truncated_names[key]:>15s}"
    lines.append(header)
    lines.append(f"  {'-'*10}" + f" {'-'*15}" * len(results))

    for t in all_types:
        row = f"  {t:<10s}"
        for r in results.values():
            pt = r.per_type_metrics()
            f1 = pt.get(t, {}).get("f1", 0.0)
            row += f" {f1:14.1%}"
        lines.append(row)

    lines.append("=" * 80)
    return "\n".join(lines)
