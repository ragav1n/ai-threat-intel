"""
Obfuscation-severity ablation (research-paper contribution C1).

For each severity tier the dataset is obfuscated and IOC extraction is run
twice — with the symbolic deobfuscation layer OFF vs ON. The F1 gap quantifies
"deobfuscation as a force multiplier": ON should stay tier-invariant across the
in-ruleset tiers while OFF collapses; on the held-out ADVERSARIAL tier the gap
shrinks, showing the recovery is not circular.

    python scripts/run_obfuscation_ablation.py                       # synthetic
    python scripts/run_obfuscation_ablation.py --dataset prism
    python scripts/run_obfuscation_ablation.py --dataset real_world_v2_gpt55

Extraction here is regex + deobfuscation + filters only (no LLM), so the run is
fast. Results are written to data/evaluation/obfuscation_ablation_<dataset>.json.
"""
import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.ablation_study import (
    format_obfuscation_table, run_obfuscation_ablation,
)
from threat_intel_aggregator.evaluation.obfuscation_generator import ADVERSARIAL_TIERS


def _result_dict(r) -> dict:
    return {
        "precision": round(r.precision, 6),
        "recall": round(r.recall, 6),
        "f1": round(r.f1, 6),
        "true_positives": r.true_positives,
        "false_positives": r.false_positives,
        "false_negatives": r.false_negatives,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the obfuscation-severity ablation.")
    ap.add_argument("--dataset", default="synthetic", help="registered dataset name")
    ap.add_argument("--output", default=None, help="output JSON path")
    args = ap.parse_args()

    out_path = args.output or f"data/evaluation/obfuscation_ablation_{args.dataset}.json"
    print(f"=== Obfuscation ablation — dataset: {args.dataset} ===")

    results = run_obfuscation_ablation(dataset=args.dataset)
    print()
    print(format_obfuscation_table(results))

    summary = {
        "dataset": args.dataset,
        "tiers": {
            tier: {
                "deobf_off": _result_dict(pair["no_deobf"]),
                "deobf_on": _result_dict(pair["with_deobf"]),
                "f1_recovered": round(pair["with_deobf"].f1 - pair["no_deobf"].f1, 6),
                "adversarial": tier in ADVERSARIAL_TIERS,
            }
            for tier, pair in results.items()
        },
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n💾 Ablation results saved to {out_path}")


if __name__ == "__main__":
    main()
