"""
Unified gold-benchmark evaluation — baselines vs our pipeline, with CIs.

Runs every extractor (our pipeline, iocextract, ioc-finder, spaCy NER, regex
only) over a gold dataset — by default PRISM, the external analyst-validated
benchmark — and attaches a 95% bootstrap confidence interval to each P/R/F1.
This is the headline comparison table for the paper: on external gold, with
error bars.

    python scripts/run_gold_benchmark.py                       # PRISM, fast set
    python scripts/run_gold_benchmark.py --dataset prism \
        --baselines our_pipeline,iocextract,ioc_finder,regex_only,spacy_ner

`our_pipeline_llm` (needs Ollama) and `spacy_ner` (needs the spaCy model) are
opt-in via --baselines so the default run is fully offline. Results are written
to data/evaluation/gold_benchmark_<dataset>.json.
"""
import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.baseline_comparison import (
    format_comparison_table, run_baseline_comparison,
)
from threat_intel_aggregator.evaluation.bootstrap_ci import compute_bootstrap_ci
from threat_intel_aggregator.evaluation.datasets import load_samples

# Offline-fast set — no Ollama, no optional deps.
DEFAULT_BASELINES = ["regex_only", "our_pipeline", "iocextract", "ioc_finder"]


def _gold_count(samples: list) -> int:
    """Micro count of gold IOC instances (per-sample, strip+lower normalised)."""
    return sum(
        len({(e["value"].strip().lower(), e["type"].strip().lower())
             for e in s["expected_iocs"]})
        for s in samples
    )


def _format_ci_table(results: dict, boot: dict) -> str:
    """Per-baseline F1/P/R each with its 95% bootstrap CI."""
    lines = ["=" * 78,
             "  BASELINE METRICS WITH 95% BOOTSTRAP CONFIDENCE INTERVALS",
             "=" * 78,
             f"  {'Extractor':<24s} {'F1 [95% CI]':>23s} "
             f"{'P [95% CI]':>23s}"]
    lines.append(f"  {'-'*24} {'-'*23} {'-'*23}")
    for key, r in results.items():
        b = boot[key]
        f1 = (f"{b.f1_ci.point_estimate:.3f} "
              f"[{b.f1_ci.ci_lower:.3f},{b.f1_ci.ci_upper:.3f}]")
        p = (f"{b.precision_ci.point_estimate:.3f} "
             f"[{b.precision_ci.ci_lower:.3f},{b.precision_ci.ci_upper:.3f}]")
        lines.append(f"  {r.name:<24s} {f1:>23s} {p:>23s}")
    lines.append("")
    lines.append("  Point estimate followed by [lower, upper] percentile bootstrap CI.")
    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Gold-benchmark baseline comparison with CIs.")
    ap.add_argument("--dataset", default="prism", help="registered dataset name")
    ap.add_argument("--n-iterations", type=int, default=1000, help="bootstrap resamples")
    ap.add_argument("--baselines", default="",
                    help="comma-separated baseline keys (default: offline-fast set)")
    args = ap.parse_args()

    baselines = [b.strip() for b in args.baselines.split(",") if b.strip()] \
        or DEFAULT_BASELINES

    samples = load_samples(args.dataset)
    n_gold = _gold_count(samples)
    print(f"=== Gold-benchmark evaluation — dataset: {args.dataset} ===")
    print(f"  samples: {len(samples)}   gold IOC instances: {n_gold}")
    print(f"  baselines: {', '.join(baselines)}")

    results, per_sample = run_baseline_comparison(
        samples, baselines=baselines, collect_per_sample=True)
    boot = {key: compute_bootstrap_ci(per_sample[key], n_iterations=args.n_iterations)
            for key in results}

    print()
    print(format_comparison_table(results))
    print()
    print(_format_ci_table(results, boot))

    out = {
        "dataset": args.dataset,
        "n_samples": len(samples),
        "n_gold_iocs": n_gold,
        "n_iterations": args.n_iterations,
        "baselines": {
            key: {**results[key].to_dict(), "bootstrap": boot[key].to_dict()}
            for key in results
        },
    }
    out_path = f"data/evaluation/gold_benchmark_{args.dataset}.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n💾 Saved to {out_path}")


if __name__ == "__main__":
    main()
