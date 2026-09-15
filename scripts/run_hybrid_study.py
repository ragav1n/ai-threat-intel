"""
Pipeline/ioc-finder hybrid study (research-paper contribution C1, extension).

`run_obfuscation_baselines.py` establishes the C1 gap: off-the-shelf
`ioc-finder` beats our regex extractor on clean prose (F1 0.833 vs 0.745) but
loses 34 points at T3+ once indicators are disguised, while our pipeline stays
flat. The obvious reviewer question is what happens if you use both. This
script answers it by scoring five compositions against the two of them:

    ioc_finder_deobf      ioc-finder on text our deobfuscation layer normalised
    ioc_finder_deobf_flt  the above, then our validity/blocklist filters
    ioc_finder_deobf_flt_nd  the above without the URL-domain dedup rule
    hybrid_union          our candidates OR deobfuscation-fed ioc-finder's
    hybrid_filtered       that union, then our filters
    hybrid_intersect      only candidates both extractors return

Marginal bootstrap intervals are reported per cell, and because two marginal
intervals can overlap even when one extractor wins on every report, each
composition also gets a *paired* bootstrap delta against both references
(`our_pipeline` and `ioc_finder`) at every tier.

    python scripts/run_hybrid_study.py --dataset prism

Extraction is regex-level only (no LLM, no network), but ioc-finder is slow on
real prose, so a full T0-T5 run takes several minutes. Results are written to
data/evaluation/hybrid_study_<dataset>.json.
"""
import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.baseline_comparison import (
    BASELINES, run_baseline_comparison,
)
from threat_intel_aggregator.evaluation.bootstrap_ci import (
    compute_bootstrap_ci, compute_paired_bootstrap_delta,
)
from threat_intel_aggregator.evaluation.datasets import load_samples
from threat_intel_aggregator.evaluation.obfuscation_generator import (
    ADVERSARIAL_TIERS, SEVERITY_TIERS, build_obfuscated_samples,
)

# The two extractors every composition is measured against.
REFERENCES = ["our_pipeline", "ioc_finder"]

# Compositions under test, in increasing order of how much of our pipeline
# they borrow.
COMPOSITIONS = [
    "ioc_finder_deobf",
    "ioc_finder_deobf_flt",
    "ioc_finder_deobf_flt_nd",
    "hybrid_union",
    "hybrid_filtered",
    "hybrid_intersect",
]


def run_study(samples: list, tiers: list, n_iterations: int) -> dict:
    """Score references and compositions at each tier, with paired deltas."""
    keys = REFERENCES + COMPOSITIONS
    tiers_out = {}

    for tier in tiers:
        print(f"  tier {tier} ...", flush=True)
        obf = build_obfuscated_samples(samples, tier)
        results, per_sample = run_baseline_comparison(
            obf, baselines=keys, collect_per_sample=True)

        cells = {}
        for key in keys:
            cells[key] = {
                **results[key].to_dict(),
                "bootstrap": compute_bootstrap_ci(
                    per_sample[key], n_iterations=n_iterations).to_dict(),
                "paired_vs": {
                    ref: {
                        metric: delta.to_dict() for metric, delta in
                        compute_paired_bootstrap_delta(
                            per_sample[ref], per_sample[key],
                            n_iterations=n_iterations).items()
                    }
                    for ref in REFERENCES if ref != key
                },
            }

        tiers_out[tier] = {
            "adversarial": tier in ADVERSARIAL_TIERS,
            "baselines": cells,
        }

    return tiers_out


def format_f1_table(tiers_out: dict, keys: list) -> str:
    """Tier x extractor F1 matrix."""
    lines = ["=" * 78,
             "  PIPELINE / IOC-FINDER HYBRID STUDY  (F1 per tier)",
             "=" * 78]
    header = f"  {'Tier':<16s}" + "".join(f" {BASELINES[k][0][:20]:>20s}" for k in keys)
    lines.append(header)
    lines.append(f"  {'-'*16}" + f" {'-'*20}" * len(keys))
    for tier, tier_out in tiers_out.items():
        marker = " *" if tier_out["adversarial"] else "  "
        row = f"  {tier:<14s}{marker}"
        for k in keys:
            row += f" {tier_out['baselines'][k]['f1']:19.1%}"
        lines.append(row)
    lines.append("")
    lines.append("  *   = held-out ADVERSARIAL tier (outside our deobfuscation ruleset)")
    lines.append("=" * 78)
    return "\n".join(lines)


def format_paired_table(tiers_out: dict, reference: str) -> str:
    """Paired F1 deltas for every composition against one reference."""
    lines = ["=" * 78,
             f"  PAIRED BOOTSTRAP: F1 delta vs {BASELINES[reference][0]}",
             "=" * 78,
             f"  {'Tier':<16s}{'Composition':<24s}{'delta F1':>10s}"
             f"{'95% CI':>20s}{'p':>8s}"]
    lines.append(f"  {'-'*16}{'-'*24}{'-'*10}{'-'*20}{'-'*8}")
    for tier, tier_out in tiers_out.items():
        for key in COMPOSITIONS:
            d = tier_out["baselines"][key]["paired_vs"][reference]["f1"]
            flag = "" if d["significant"] else "  (ns)"
            lines.append(
                f"  {tier:<16s}{key:<24s}{d['delta']:>+10.4f}"
                f"   [{d['ci_lower']:>+.4f}, {d['ci_upper']:>+.4f}]"
                f"{d['p_value']:>8.3f}{flag}")
        lines.append("")
    lines.append("  (ns) = 95% interval for the difference includes zero")
    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Score pipeline/ioc-finder hybrid compositions per obfuscation tier.")
    ap.add_argument("--dataset", default="prism", help="registered dataset name")
    ap.add_argument("--tiers", default="", help="comma-separated tiers (default: all)")
    ap.add_argument("--n-iterations", type=int, default=1000, help="bootstrap resamples")
    ap.add_argument("--output", default=None, help="output JSON path")
    args = ap.parse_args()

    tiers = [t.strip() for t in args.tiers.split(",") if t.strip()] or SEVERITY_TIERS
    out_path = args.output or f"data/evaluation/hybrid_study_{args.dataset}.json"

    samples = load_samples(args.dataset)
    keys = REFERENCES + COMPOSITIONS
    print(f"=== Hybrid study — dataset: {args.dataset} ===")
    print(f"  samples: {len(samples)}   extractors: {', '.join(keys)}")

    tiers_out = run_study(samples, tiers, args.n_iterations)

    print()
    print(format_f1_table(tiers_out, keys))
    for ref in REFERENCES:
        print()
        print(format_paired_table(tiers_out, ref))

    summary = {
        "dataset": args.dataset,
        "n_samples": len(samples),
        "n_iterations": args.n_iterations,
        "references": REFERENCES,
        "compositions": COMPOSITIONS,
        "tiers": tiers_out,
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n💾 Saved to {out_path}")


if __name__ == "__main__":
    main()
