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


def _evaluate_config_on_samples(config: AblationConfig, samples: list) -> AblationResult:
    """Run a single ablation configuration over a sample list and tally metrics."""
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
        results.append(_evaluate_config_on_samples(config, samples))
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


# ── Obfuscation-Severity Ablation ──────────────────────────
#
# Measures the contribution of the symbolic deobfuscation layer as obfuscation
# severity increases. For each severity tier, the same ground-truth samples are
# obfuscated and extracted twice — with deobfuscation OFF vs ON — so the F1 gap
# quantifies "deobfuscation as a force multiplier" (research paper contribution C1).

# Two configs identical except for the deobfuscation stage.
_OBF_NO_DEOBF = AblationConfig(
    name="Deobfuscation OFF",
    description="All filters enabled, symbolic deobfuscation disabled",
    use_deobfuscation=False,
    use_domain_filter=True,
    use_file_ext_filter=True,
    use_url_domain_dedup=True,
)
_OBF_WITH_DEOBF = AblationConfig(
    name="Deobfuscation ON",
    description="All filters enabled, symbolic deobfuscation enabled",
    use_deobfuscation=True,
    use_domain_filter=True,
    use_file_ext_filter=True,
    use_url_domain_dedup=True,
)


def run_obfuscation_ablation(
    samples: list = None,
    tiers: list = None,
    dataset: str = "synthetic",
) -> Dict[str, Dict[str, AblationResult]]:
    """
    Run the obfuscation-severity ablation.

    For each severity tier, obfuscates the dataset samples and evaluates
    extraction with deobfuscation OFF and ON.

    Args:
        samples: Pre-loaded sample dicts (text, expected_iocs, category).
                 If None, loads `dataset` via the dataset registry.
        tiers:   Severity tiers to run. Uses all SEVERITY_TIERS if None.
        dataset: Registered dataset name when `samples` is None
                 (e.g. "synthetic", "real_world_v2", "benchmark").

    Returns:
        Dict mapping tier -> {"no_deobf": AblationResult, "with_deobf": AblationResult}.
    """
    from threat_intel_aggregator.evaluation.obfuscation_generator import (
        SEVERITY_TIERS, build_obfuscated_samples,
    )

    if samples is None:
        from threat_intel_aggregator.evaluation.datasets import load_samples
        samples = load_samples(dataset)

    tiers = tiers or SEVERITY_TIERS
    results: Dict[str, Dict[str, AblationResult]] = {}

    for tier in tiers:
        logger.info(f"Obfuscation ablation: tier {tier}")
        obf_samples = build_obfuscated_samples(samples, tier)
        results[tier] = {
            "no_deobf": _evaluate_config_on_samples(_OBF_NO_DEOBF, obf_samples),
            "with_deobf": _evaluate_config_on_samples(_OBF_WITH_DEOBF, obf_samples),
        }

    return results


def format_obfuscation_table(results: Dict[str, Dict[str, AblationResult]]) -> str:
    """Format obfuscation-severity ablation results as a readable table."""
    lines = []
    lines.append("=" * 80)
    lines.append("  OBFUSCATION-SEVERITY ABLATION  (deobfuscation as a force multiplier)")
    lines.append("=" * 80)
    lines.append(
        f"  {'Tier':<14s} "
        f"{'OFF P':>7s} {'OFF R':>7s} {'OFF F1':>7s}   "
        f"{'ON P':>7s} {'ON R':>7s} {'ON F1':>7s}   {'dF1':>7s}"
    )
    lines.append(f"  {'-'*14} {'-'*7} {'-'*7} {'-'*7}   {'-'*7} {'-'*7} {'-'*7}   {'-'*7}")

    from threat_intel_aggregator.evaluation.obfuscation_generator import ADVERSARIAL_TIERS

    for tier, pair in results.items():
        off = pair["no_deobf"]
        on = pair["with_deobf"]
        d_f1 = on.f1 - off.f1
        marker = " *" if tier in ADVERSARIAL_TIERS else "  "
        lines.append(
            f"  {tier:<12s}{marker} "
            f"{off.precision:6.1%} {off.recall:6.1%} {off.f1:6.1%}   "
            f"{on.precision:6.1%} {on.recall:6.1%} {on.f1:6.1%}   {d_f1:+6.1%}"
        )

    lines.append("")
    lines.append("  OFF = symbolic deobfuscation disabled,  ON = enabled")
    lines.append("  dF1 = F1 recovered by the deobfuscation layer at that severity tier")
    lines.append("  *   = held-out ADVERSARIAL tier (transformations outside the ruleset);")
    lines.append("        a small dF1 here is expected and shows the recovery is not circular.")
    lines.append("=" * 80)
    return "\n".join(lines)


# Offline-only baselines: no LLM, no extra optional deps (spaCy/Ollama).
DEFAULT_OBF_BASELINES = ["regex_only", "our_pipeline", "iocextract", "ioc_finder"]


def run_obfuscation_baseline_comparison(
    samples: list = None,
    tiers: list = None,
    baselines: list = None,
    dataset: str = "prism",
    n_iterations: int = 1000,
) -> Dict[str, Dict[str, dict]]:
    """
    Run off-the-shelf baseline extractors through the obfuscation-severity tiers.

    Companion to `run_obfuscation_ablation`: instead of comparing our pipeline
    with deobfuscation OFF vs ON, this compares *other tools* (ioc-finder,
    iocextract, regex_only) and our pipeline against each other at each tier,
    with bootstrap CIs. The question this answers: tools that are competitive
    on clean text (T0) -- do they stay competitive once the text is disguised
    (T2+), or do they collapse the way an unaided regex does?

    Args:
        samples: Pre-loaded sample dicts (text, expected_iocs, category).
                 If None, loads `dataset` via the dataset registry.
        tiers:   Severity tiers to run. Uses all SEVERITY_TIERS if None.
        baselines: Baseline keys from `baseline_comparison.BASELINES`.
                 Defaults to DEFAULT_OBF_BASELINES (fully offline).
        dataset: Registered dataset name when `samples` is None.
        n_iterations: Bootstrap resamples per tier per baseline.

    Returns:
        Dict mapping tier -> {baseline_key: {**BaselineResult.to_dict(),
        "bootstrap": BootstrapResult.to_dict()}}.
    """
    from threat_intel_aggregator.evaluation.baseline_comparison import run_baseline_comparison
    from threat_intel_aggregator.evaluation.bootstrap_ci import compute_bootstrap_ci
    from threat_intel_aggregator.evaluation.obfuscation_generator import (
        SEVERITY_TIERS, build_obfuscated_samples,
    )

    if samples is None:
        from threat_intel_aggregator.evaluation.datasets import load_samples
        samples = load_samples(dataset)

    tiers = tiers or SEVERITY_TIERS
    baselines = baselines or DEFAULT_OBF_BASELINES

    results: Dict[str, Dict[str, dict]] = {}
    for tier in tiers:
        logger.info(f"Obfuscation baseline comparison: tier {tier}")
        obf_samples = build_obfuscated_samples(samples, tier)
        tier_results, per_sample = run_baseline_comparison(
            obf_samples, baselines=baselines, collect_per_sample=True)
        results[tier] = {
            key: {
                **tier_results[key].to_dict(),
                "bootstrap": compute_bootstrap_ci(
                    per_sample[key], n_iterations=n_iterations).to_dict(),
            }
            for key in tier_results
        }

    return results


def format_obfuscation_baselines_table(results: Dict[str, Dict[str, dict]], baselines: list) -> str:
    """Format the tier x baseline F1 matrix from `run_obfuscation_baseline_comparison`."""
    from threat_intel_aggregator.evaluation.baseline_comparison import BASELINES
    from threat_intel_aggregator.evaluation.obfuscation_generator import ADVERSARIAL_TIERS

    lines = []
    lines.append("=" * 78)
    lines.append("  OBFUSCATION-SEVERITY BASELINE COMPARISON  (F1 per tier)")
    lines.append("=" * 78)

    names = {key: BASELINES[key][0] for key in baselines}
    header = f"  {'Tier':<14s}"
    for key in baselines:
        header += f" {names[key]:>22s}"
    lines.append(header)
    lines.append(f"  {'-'*14}" + f" {'-'*22}" * len(baselines))

    for tier, tier_results in results.items():
        marker = " *" if tier in ADVERSARIAL_TIERS else "  "
        row = f"  {tier:<12s}{marker}"
        for key in baselines:
            f1 = tier_results.get(key, {}).get("f1", 0.0)
            row += f" {f1:21.1%}"
        lines.append(row)

    lines.append("")
    lines.append("  *   = held-out ADVERSARIAL tier (transformations outside our deobfuscation ruleset)")
    lines.append("=" * 78)
    return "\n".join(lines)
