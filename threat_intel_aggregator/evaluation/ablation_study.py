"""
Ablation Study: measure the contribution of each pipeline component.

Runs the extraction pipeline in multiple configurations to quantify
the impact of deobfuscation, confidence scoring, and filtering.

Configurations:
  A. Regex Only         — raw regex, no deobfuscation, no filtering
  B. Regex + Deobfusc.  — regex after deobfuscation, no filtering
  C. Full Pipeline      — regex + deobfuscation + confidence + all filters
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class AblationConfig:
    """Describes a single ablation configuration."""
    name: str
    description: str
    use_deobfuscation: bool = False
    use_confidence_filter: bool = False
    use_domain_filter: bool = False
    use_file_ext_filter: bool = False
    use_url_domain_dedup: bool = False
    min_confidence: float = 0.0


@dataclass
class AblationResult:
    """Result for a single ablation configuration."""
    config: AblationConfig
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "config": self.config.name,
            "description": self.config.description,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
        }


# Standard ablation configurations
ABLATION_CONFIGS = [
    AblationConfig(
        name="A. Regex Only",
        description="Raw regex extraction, no deobfuscation, no filtering",
        use_deobfuscation=False,
        use_confidence_filter=False,
        use_domain_filter=False,
        use_file_ext_filter=False,
        use_url_domain_dedup=False,
    ),
    AblationConfig(
        name="B. Regex + Deobfuscation",
        description="Regex after deobfuscating defanged IOCs",
        use_deobfuscation=True,
        use_confidence_filter=False,
        use_domain_filter=False,
        use_file_ext_filter=False,
        use_url_domain_dedup=False,
    ),
    AblationConfig(
        name="C. Regex + Deobfusc. + Domain Filter",
        description="Add domain blacklist and file-extension filtering",
        use_deobfuscation=True,
        use_confidence_filter=False,
        use_domain_filter=True,
        use_file_ext_filter=True,
        use_url_domain_dedup=False,
    ),
    AblationConfig(
        name="D. Full Pipeline",
        description="All components: deobfuscation + domain filter + file-ext filter + URL-domain dedup + confidence",
        use_deobfuscation=True,
        use_confidence_filter=True,
        use_domain_filter=True,
        use_file_ext_filter=True,
        use_url_domain_dedup=True,
    ),
]


def _normalize(v: str) -> str:
    return v.strip().lower()


def _extract_with_config(text: str, config: AblationConfig) -> Set[Tuple[str, str]]:
    """Extract IOCs using a specific ablation configuration."""
    import ipaddress
    from threat_intel_aggregator.enums import IOCType
    from threat_intel_aggregator.feed_collection.ioc_extractor import (
        IOC_PATTERNS, DOMAIN_BLACKLIST, FILE_EXTENSION_BLACKLIST,
        is_valid_ip, is_private_ip,
    )

    # Step 1: Optionally deobfuscate
    if config.use_deobfuscation:
        from threat_intel_aggregator.feed_collection.ioc_deobfuscator import deobfuscate_text
        text, _ = deobfuscate_text(text)

    results: Set[Tuple[str, str]] = set()

    # Pre-extract URLs for dedup
    extracted_urls: Set[str] = set()
    if config.use_url_domain_dedup:
        for m in re.finditer(IOC_PATTERNS[IOCType.URL], text):
            extracted_urls.add(m.group().lower())

    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in re.finditer(pattern, text):
            item = match.group()
            item_lower = item.lower()
            type_str = str(ioc_type)

            # IP validation
            if ioc_type == IOCType.IP:
                if not is_valid_ip(item):
                    continue
                if is_private_ip(item):
                    continue

            # Domain filtering
            if ioc_type == IOCType.DOMAIN:
                if config.use_domain_filter and item_lower in DOMAIN_BLACKLIST:
                    continue
                if config.use_file_ext_filter:
                    last_dot = item_lower.rfind(".")
                    if last_dot >= 0 and item_lower[last_dot:] in FILE_EXTENSION_BLACKLIST:
                        continue
                if config.use_url_domain_dedup:
                    if any(item_lower in url for url in extracted_urls):
                        continue

            results.add((_normalize(item), type_str))

    return results


def run_ablation_study(
    samples: list = None,
    configs: list = None,
) -> List[AblationResult]:
    """
    Run ablation study across multiple pipeline configurations.

    Args:
        samples: Ground-truth sample dicts. Loads default if None.
        configs: List of AblationConfig. Uses ABLATION_CONFIGS if None.

    Returns:
        List of AblationResult, one per config.
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

    configs = configs or ABLATION_CONFIGS
    results = []

    for config in configs:
        logger.info(f"Ablation: {config.name}")
        result = AblationResult(config=config)

        for sample in samples:
            expected_set: Set[Tuple[str, str]] = {
                (_normalize(e["value"]), e["type"].strip().lower())
                for e in sample.get("expected_iocs", [])
            }
            extracted_set = _extract_with_config(sample["text"], config)

            tp = expected_set & extracted_set
            fp = extracted_set - expected_set
            fn = expected_set - extracted_set

            result.true_positives += len(tp)
            result.false_positives += len(fp)
            result.false_negatives += len(fn)

            # Per-type
            all_types = {k[1] for k in expected_set | extracted_set}
            for t in all_types:
                if t not in result.per_type:
                    result.per_type[t] = {"tp": 0, "fp": 0, "fn": 0}
                t_exp = {k for k in expected_set if k[1] == t}
                t_ext = {k for k in extracted_set if k[1] == t}
                result.per_type[t]["tp"] += len(t_exp & t_ext)
                result.per_type[t]["fp"] += len(t_ext - t_exp)
                result.per_type[t]["fn"] += len(t_exp - t_ext)

        results.append(result)

    return results


def format_ablation_table(results: List[AblationResult]) -> str:
    """Format ablation results as a readable table."""
    lines = []
    lines.append("=" * 80)
    lines.append("  ABLATION STUDY")
    lines.append("=" * 80)
    lines.append(f"  {'Config':<42s} {'Prec':>7s} {'Recall':>7s} {'F1':>7s}  {'TP':>4s} {'FP':>4s} {'FN':>4s}")
    lines.append(f"  {'-'*42} {'-'*7} {'-'*7} {'-'*7}  {'-'*4} {'-'*4} {'-'*4}")

    for r in results:
        lines.append(
            f"  {r.config.name:<42s} {r.precision:6.1%} {r.recall:6.1%} {r.f1:6.1%}  "
            f"{r.true_positives:4d} {r.false_positives:4d} {r.false_negatives:4d}"
        )

    # Show delta from baseline (Config A)
    if len(results) >= 2:
        baseline = results[0]
        lines.append("")
        lines.append("  Component Contribution (delta from Regex Only):")
        lines.append(f"  {'Component':<42s} {'dP':>7s} {'dR':>7s} {'dF1':>7s}  {'dFP':>5s} {'dFN':>5s}")
        lines.append(f"  {'-'*42} {'-'*7} {'-'*7} {'-'*7}  {'-'*5} {'-'*5}")
        for r in results[1:]:
            dp = r.precision - baseline.precision
            dr = r.recall - baseline.recall
            df = r.f1 - baseline.f1
            dfp = r.false_positives - baseline.false_positives
            dfn = r.false_negatives - baseline.false_negatives
            lines.append(
                f"  {r.config.name:<42s} {dp:+6.1%} {dr:+6.1%} {df:+6.1%}  {dfp:+5d} {dfn:+5d}"
            )

    lines.append("=" * 80)
    return "\n".join(lines)
