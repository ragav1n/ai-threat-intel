"""
Baseline-vs-obfuscation comparison (research-paper contribution C1, support).

Companion to `run_obfuscation_ablation.py`. That ablation only varies OUR
pipeline's deobfuscation layer (OFF vs ON) at each severity tier. This script
asks the question a reviewer will: off-the-shelf tools (ioc-finder, iocextract,
regex_only) are competitive -- or better -- than our pipeline on clean text
(T0_clean); do they stay competitive once the report text is disguised (T2+),
or do they collapse the way an unaided regex does?

    python scripts/run_obfuscation_baselines.py --dataset prism

Extraction is regex-level only (no LLM), but `ioc-finder` is slow on real
prose (~1 min/tier on PRISM's 50 reports), so the full T0-T5 run takes a few
minutes. Bootstrapping is negligible by comparison (~7ms per cell).

Note: the "our_pipeline" row here is `BASELINES["our_pipeline"]`
(regex + deobfuscation, no extra filters) -- a different, less-filtered
configuration than `run_obfuscation_ablation.py`'s "deobf_on"
(which also applies domain/file-extension filters and URL-domain dedup).
The two are not expected to match numerically; both should show the same
qualitative pattern: roughly flat F1 across T0-T4, a drop at the held-out
T5_adversarial tier.

Results are written to data/evaluation/obfuscation_baselines_<dataset>.json.
"""
import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.ablation_study import (
    DEFAULT_OBF_BASELINES, format_obfuscation_baselines_table,
    run_obfuscation_baseline_comparison,
)
from threat_intel_aggregator.evaluation.datasets import load_samples
from threat_intel_aggregator.evaluation.obfuscation_generator import ADVERSARIAL_TIERS


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Run baseline extractors through the obfuscation-severity tiers.")
    ap.add_argument("--dataset", default="prism", help="registered dataset name")
    ap.add_argument("--baselines", default="",
                    help="comma-separated baseline keys (default: offline-fast set)")
    ap.add_argument("--n-iterations", type=int, default=1000, help="bootstrap resamples")
    ap.add_argument("--output", default=None, help="output JSON path")
    args = ap.parse_args()

    baselines = [b.strip() for b in args.baselines.split(",") if b.strip()] \
        or DEFAULT_OBF_BASELINES
    out_path = args.output or f"data/evaluation/obfuscation_baselines_{args.dataset}.json"

    samples = load_samples(args.dataset)
    print(f"=== Obfuscation baselines — dataset: {args.dataset} ===")
    print(f"  samples: {len(samples)}   baselines: {', '.join(baselines)}")

    results = run_obfuscation_baseline_comparison(
        samples=samples, baselines=baselines, n_iterations=args.n_iterations)

    print()
    print(format_obfuscation_baselines_table(results, baselines))

    summary = {
        "dataset": args.dataset,
        "n_samples": len(samples),
        "n_iterations": args.n_iterations,
        "baselines": baselines,
        "tiers": {
            tier: {
                "adversarial": tier in ADVERSARIAL_TIERS,
                "baselines": tier_results,
            }
            for tier, tier_results in results.items()
        },
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n💾 Saved to {out_path}")


if __name__ == "__main__":
    main()
