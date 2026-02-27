"""
Error Analysis: categorize remaining false positives and false negatives.

Produces a structured report showing *why* each error occurs,
grouped by failure category for academic reporting.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ErrorInstance:
    """A single extraction error."""
    sample_id: str
    value: str
    ioc_type: str
    error_type: str  # "false_positive" or "false_negative"
    category: str    # failure category (e.g., "email_domain_leak", "ftp_unsupported")
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "value": self.value,
            "ioc_type": self.ioc_type,
            "error_type": self.error_type,
            "category": self.category,
            "explanation": self.explanation,
        }


@dataclass
class ErrorAnalysisResult:
    """Structured error analysis report."""
    total_fp: int = 0
    total_fn: int = 0
    errors: List[ErrorInstance] = field(default_factory=list)
    fp_categories: Dict[str, int] = field(default_factory=dict)
    fn_categories: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_fp": self.total_fp,
            "total_fn": self.total_fn,
            "fp_categories": self.fp_categories,
            "fn_categories": self.fn_categories,
            "errors": [e.to_dict() for e in self.errors],
        }


# Known benign/legitimate domains used as email providers or services
_EMAIL_PROVIDER_TLDS = {".xyz", ".top", ".tk", ".pw", ".cc", ".ws", ".ru", ".cn"}


def _classify_fp(value: str, ioc_type: str, sample_text: str, sample_category: str) -> Tuple[str, str]:
    """Classify a false positive into a failure category."""

    # Domain extracted from an email address
    if ioc_type == "domain":
        # Check if domain appears as part of an email in the text
        if re.search(rf"[A-Za-z0-9._%+-]+@{re.escape(value)}", sample_text, re.IGNORECASE):
            return "email_domain_leak", f"Domain '{value}' extracted from an email address in text"

        # Domain from true-negative text (benign context)
        if sample_category == "true_negative":
            return "benign_context_domain", f"Domain '{value}' extracted from benign/non-threat text"

        # Misc domain FP
        return "over_matching_domain", f"Domain '{value}' matched by regex but not a real threat IOC"

    # IP false positives
    if ioc_type == "ip":
        if sample_category == "true_negative":
            return "benign_context_ip", f"IP '{value}' extracted from benign text"
        # Check if it looks like a version number
        parts = value.split(".")
        if all(int(p) < 20 for p in parts if p.isdigit()):
            return "version_string_ip", f"IP-like pattern '{value}' is likely a version number"
        return "over_matching_ip", f"IP '{value}' matched but not labeled as expected IOC"

    # Hash false positives (rare)
    if ioc_type in ("md5", "sha1", "sha256"):
        if all(c == "0" for c in value):
            return "null_hash", f"Null/placeholder hash '{value[:16]}...' incorrectly extracted"
        return "over_matching_hash", f"Hash '{value[:16]}...' not in expected set"

    # Email false positives
    if ioc_type == "email":
        if sample_category == "true_negative":
            return "benign_context_email", f"Email '{value}' from benign text"
        return "over_matching_email", f"Email '{value}' not labeled as expected"

    # URL false positives
    if ioc_type == "url":
        if sample_category == "true_negative":
            return "benign_context_url", f"URL '{value}' from benign text"
        return "over_matching_url", f"URL '{value}' not in expected set"

    return "unknown", f"Unclassified FP: {ioc_type} '{value}'"


def _classify_fn(value: str, ioc_type: str, sample_text: str, sample_category: str) -> Tuple[str, str]:
    """Classify a false negative into a failure category."""

    # Check if the value is even present in the text (post-deobfuscation)
    if value.lower() not in sample_text.lower():
        # Might be an obfuscated value that deobfuscation missed
        return "deobfuscation_failure", f"Expected '{value}' not found in text — deobfuscation may have failed"

    # Domain missed
    if ioc_type == "domain":
        return "domain_filtered", f"Domain '{value}' was present but filtered (blacklist/dedup/file-ext)"

    # IP missed
    if ioc_type == "ip":
        return "ip_filtered", f"IP '{value}' was present but filtered (private/reserved)"

    # URL missed
    if ioc_type == "url":
        if value.startswith("ftp://"):
            return "unsupported_scheme", f"URL '{value}' uses unsupported scheme"
        return "url_regex_miss", f"URL '{value}' not matched by URL regex"

    # Hash missed
    if ioc_type in ("md5", "sha1", "sha256"):
        return "hash_regex_miss", f"Hash '{value[:16]}...' not matched by regex"

    return "unknown", f"Unclassified FN: {ioc_type} '{value}'"


def run_error_analysis(samples: list = None) -> ErrorAnalysisResult:
    """
    Analyze all extraction errors (FPs and FNs) and categorize them.

    Args:
        samples: Ground-truth sample dicts with 'text', 'expected_iocs',
                 'extracted_iocs', 'category', and 'id' fields.
                 If None, runs extraction on default dataset.

    Returns:
        ErrorAnalysisResult with categorized errors.
    """
    if samples is None:
        from threat_intel_aggregator.evaluation.ground_truth import GroundTruthDataset
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence

        dataset = GroundTruthDataset()
        samples = []
        for s in dataset.samples:
            matches = extract_iocs_with_confidence(s.text, include_private_ips=False, min_confidence=0.0)
            samples.append({
                "id": s.id,
                "text": s.text,
                "expected_iocs": [e.to_dict() for e in s.expected_iocs],
                "extracted_iocs": [
                    {"value": m.value, "type": str(m.ioc_type), "confidence": m.confidence}
                    for m in matches
                ],
                "category": s.category,
            })

    result = ErrorAnalysisResult()

    for sample in samples:
        sid = sample.get("id", "unknown")
        text = sample.get("text", "")
        cat = sample.get("category", "unknown")

        expected_set = {
            (e["value"].strip().lower(), e["type"].strip().lower())
            for e in sample.get("expected_iocs", [])
        }
        extracted_set = {
            (e["value"].strip().lower(), e["type"].strip().lower())
            for e in sample.get("extracted_iocs", [])
        }

        # False positives
        for val, typ in (extracted_set - expected_set):
            result.total_fp += 1
            category, explanation = _classify_fp(val, typ, text, cat)
            result.fp_categories[category] = result.fp_categories.get(category, 0) + 1
            result.errors.append(ErrorInstance(
                sample_id=sid, value=val, ioc_type=typ,
                error_type="false_positive", category=category, explanation=explanation,
            ))

        # False negatives
        for val, typ in (expected_set - extracted_set):
            result.total_fn += 1
            category, explanation = _classify_fn(val, typ, text, cat)
            result.fn_categories[category] = result.fn_categories.get(category, 0) + 1
            result.errors.append(ErrorInstance(
                sample_id=sid, value=val, ioc_type=typ,
                error_type="false_negative", category=category, explanation=explanation,
            ))

    logger.info(f"Error analysis: {result.total_fp} FPs, {result.total_fn} FNs")
    return result


def format_error_analysis(result: ErrorAnalysisResult) -> str:
    """Format error analysis as a readable report."""
    lines = []
    lines.append("=" * 72)
    lines.append("  ERROR ANALYSIS")
    lines.append("=" * 72)
    lines.append(f"  Total False Positives: {result.total_fp}")
    lines.append(f"  Total False Negatives: {result.total_fn}")
    lines.append("")

    if result.fp_categories:
        lines.append("  FP Failure Categories:")
        for cat, count in sorted(result.fp_categories.items(), key=lambda x: -x[1]):
            pct = count / result.total_fp * 100 if result.total_fp > 0 else 0
            lines.append(f"    {cat:<30s} {count:3d}  ({pct:5.1f}%)")
        lines.append("")

    if result.fn_categories:
        lines.append("  FN Failure Categories:")
        for cat, count in sorted(result.fn_categories.items(), key=lambda x: -x[1]):
            pct = count / result.total_fn * 100 if result.total_fn > 0 else 0
            lines.append(f"    {cat:<30s} {count:3d}  ({pct:5.1f}%)")
        lines.append("")

    # Show individual errors
    lines.append("  Detailed Errors:")
    for err in result.errors:
        marker = "FP" if err.error_type == "false_positive" else "FN"
        lines.append(f"    [{marker}] {err.sample_id:15s} {err.ioc_type:8s} {err.value[:40]:40s} → {err.category}")

    lines.append("=" * 72)
    return "\n".join(lines)
