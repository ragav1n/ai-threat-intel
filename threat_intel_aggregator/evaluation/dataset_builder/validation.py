"""
Text-grounding validation for IOC-extraction datasets.

A dataset is only valid for *extraction* evaluation if its labelled IOCs
actually occur in the report text. Labels harvested from a separate indicator
feed — the bug that left ``benchmark_dataset.json`` 0.1%-grounded — produce an
unwinnable evaluation: the extractor cannot recover an IOC that was never in
the text. This module measures text-grounding so a broken dataset is caught at
build time rather than silently depressing recall.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from threat_intel_aggregator.feed_collection.ioc_deobfuscator import deobfuscate_text

logger = logging.getLogger(__name__)

# Overall coverage below this is a hard failure: the labels almost certainly
# did not come from the text.
MIN_DATASET_COVERAGE = 0.80
# A single sample below this is reported individually.
MIN_SAMPLE_COVERAGE = 0.50


def _haystack(text: str) -> str:
    """Refang/deobfuscate the text, then lower-case it.

    This mirrors what the extractor sees before matching, so a label written in
    refanged form (``http://evil.com``) still matches a defanged occurrence
    (``hxxp://evil[.]com``) in the source text.
    """
    clean, _ = deobfuscate_text(text or "")
    return clean.lower()


def grounding_report(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute how many labelled IOCs appear in their own report text.

    Args:
        samples: uniform sample dicts —
            ``{"id", "text", "expected_iocs": [{"value", "type"}, ...]}``.

    Returns:
        A report dict with overall ``coverage``, an ``ok`` verdict, and the
        list of ``ungrounded_samples`` whose labels are mostly missing.
    """
    n_iocs = n_grounded = 0
    ungrounded: List[Dict[str, Any]] = []

    for s in samples:
        hay = _haystack(s.get("text", ""))
        iocs = s.get("expected_iocs", []) or []
        hit = sum(1 for e in iocs if str(e.get("value", "")).lower() in hay)
        n_iocs += len(iocs)
        n_grounded += hit
        if iocs and hit / len(iocs) < MIN_SAMPLE_COVERAGE:
            ungrounded.append({
                "id": s.get("id", "?"),
                "grounded": hit,
                "total": len(iocs),
                "coverage": round(hit / len(iocs), 3),
            })

    coverage = n_grounded / n_iocs if n_iocs else 1.0
    return {
        "n_samples": len(samples),
        "n_iocs": n_iocs,
        "n_grounded": n_grounded,
        "coverage": round(coverage, 4),
        "ok": coverage >= MIN_DATASET_COVERAGE,
        "ungrounded_samples": ungrounded,
    }


def format_grounding_report(report: Dict[str, Any]) -> str:
    """Render a grounding report as a human-readable block."""
    lines = [
        "Grounding validation",
        "-" * 56,
        f"  samples              : {report['n_samples']}",
        f"  expected IOCs        : {report['n_iocs']}",
        f"  IOCs found in text   : {report['n_grounded']}",
        f"  text-grounding ratio : {report['coverage']:.1%}",
    ]
    bad = report["ungrounded_samples"]
    if bad:
        lines.append(
            f"  low-grounding samples: {len(bad)} "
            f"(<{int(MIN_SAMPLE_COVERAGE * 100)}% of labels in text)"
        )
        for b in bad[:10]:
            lines.append(
                f"    - {b['id']}: {b['grounded']}/{b['total']} ({b['coverage']:.0%})"
            )
        if len(bad) > 10:
            lines.append(f"    ... and {len(bad) - 10} more")
    if report["ok"]:
        verdict = "PASS"
    else:
        verdict = (
            f"FAIL — grounding below {int(MIN_DATASET_COVERAGE * 100)}%; "
            "labels are not text-grounded and the dataset is unusable for "
            "extraction evaluation"
        )
    lines.append(f"  verdict              : {verdict}")
    return "\n".join(lines)
