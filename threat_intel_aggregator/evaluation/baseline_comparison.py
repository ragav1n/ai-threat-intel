"""
Baseline Comparison: compare our pipeline against multiple external tools.

Supported baselines:
  1. iocextract  (InQuest)  — popular regex-based IOC extraction
  2. ioc-finder  (Floyd Hightower) — grammar-based extraction with defanging
  3. Regex Only  — our own regex patterns with no filtering/deobfuscation

Runs all extractors on the same ground-truth dataset and produces
a side-by-side P/R/F1 comparison table, per IOC type.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Tuple

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


# ── Evaluation engine ──────────────────────────────────────

def _evaluate_extractor(
    name: str,
    extract_fn,
    samples: list,
) -> BaselineResult:
    """Evaluate an extractor against ground-truth samples."""
    result = BaselineResult(name=name)

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

        all_types = {k[1] for k in expected_set | extracted_set}
        for t in all_types:
            if t not in result.per_type:
                result.per_type[t] = {"tp": 0, "fp": 0, "fn": 0}
            t_exp = {k for k in expected_set if k[1] == t}
            t_ext = {k for k in extracted_set if k[1] == t}
            result.per_type[t]["tp"] += len(t_exp & t_ext)
            result.per_type[t]["fp"] += len(t_ext - t_exp)
            result.per_type[t]["fn"] += len(t_exp - t_ext)

    return result


# ── Public API ─────────────────────────────────────────────

# Registry of available baselines
BASELINES = {
    "our_pipeline": ("Our Pipeline", _extract_with_our_pipeline),
    "iocextract": ("iocextract (InQuest)", _extract_with_iocextract),
    "ioc_finder": ("ioc-finder (Hightower)", _extract_with_ioc_finder),
    "regex_only": ("Regex Only (no filter)", _extract_regex_only),
}


def run_baseline_comparison(
    samples: list = None,
    baselines: list = None,
) -> Dict[str, BaselineResult]:
    """
    Run comparison between our pipeline and selected baselines.

    Args:
        samples: Ground-truth sample dicts. Loads default if None.
        baselines: List of baseline keys (e.g. ["iocextract", "ioc_finder"]).
                   If None, runs all available baselines.

    Returns:
        Dict mapping baseline key to BaselineResult.
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
    results = {}

    for key in baselines_to_run:
        if key not in BASELINES:
            logger.warning(f"Unknown baseline: {key}")
            continue
        name, fn = BASELINES[key]
        logger.info(f"Evaluating: {name}")
        results[key] = _evaluate_extractor(name, fn, samples)

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
