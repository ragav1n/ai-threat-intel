"""
Selective prediction for IOC extraction (research-paper contribution C2).

Turns the calibrated confidence score into a triage policy: auto-apply the
IOCs the pipeline is most sure of, route the rest to a human analyst. Reports

  * the risk-coverage curve and AURC  — how well confidence orders the IOCs;
  * a target-risk table               — accept every IOC the score rates at or
                                         above (1 - target). On a calibrated
                                         score the achieved error rate tracks
                                         the target, so an analyst can pick an
                                         error budget and the pipeline meets
                                         it. On the raw score it cannot.

    python scripts/selective_prediction.py --dataset prism \
        --calibrator data/evaluation/fitted_calibrator_no_prism.json

Reads the cached predictions, so it needs no LLM and no network. Output is
written to data/evaluation/selective_prediction_<dataset>.json.
"""
import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.calibrators import load_calibrator
from threat_intel_aggregator.evaluation.selective import (
    aurc, operating_point, risk_coverage_curve, target_risk_point,
)

CALIBRATOR_PATH = "data/evaluation/fitted_calibrator.json"
TARGET_RISKS = [0.01, 0.05, 0.10, 0.20]


def _curve_at_deciles(curve: list) -> list:
    """Pick the curve point nearest each 10% coverage step, for display."""
    picked = []
    for step in range(1, 11):
        target = step / 10
        nearest = min(curve, key=lambda p: abs(p.coverage - target))
        if nearest not in picked:
            picked.append(nearest)
    return picked


def main() -> None:
    ap = argparse.ArgumentParser(description="Selective-prediction triage for IOC extraction.")
    ap.add_argument("--dataset", default="prism")
    ap.add_argument("--calibrator", default=CALIBRATOR_PATH,
                    help="fitted calibrator JSON (use a dataset-excluded "
                         "calibrator for an out-of-sample result)")
    args = ap.parse_args()

    with open(f"data/evaluation/calibration_predictions_{args.dataset}.json") as f:
        rows = json.load(f)
    calibrator = load_calibrator(args.calibrator)

    raw = [(r["fused"], bool(r["correct"])) for r in rows]
    cal = [(calibrator.transform([r["fused"]])[0], bool(r["correct"])) for r in rows]
    n = len(raw)
    base_risk = sum(1 for _, y in raw if not y) / n if n else 0.0

    print(f"=== Selective prediction — dataset: {args.dataset} ===")
    print(f"  calibrator             : {args.calibrator}")
    print(f"  candidate IOCs         : {n}")
    print(f"  error rate if all auto-applied : {base_risk:.1%}")

    # Which confidence ranks IOCs best? AURC is rank-only, so it is computed on
    # the raw scores. The LLM's self-reported confidence tends to be coarse and
    # a weak ranker even though it improves extraction precision.
    print("\n  Ranking quality by confidence source (AURC, lower is better):")
    aurc_by_source = {}
    for src in ("regex", "llm", "fused"):
        sp = [(r[src], bool(r["correct"])) for r in rows if r.get(src) is not None]
        a = aurc(sp)
        distinct = len({round(c, 4) for c, _ in sp})
        aurc_by_source[src] = round(a, 6)
        print(f"    {src:<6s} AURC {a:.4f}   ({distinct} distinct values, n={len(sp)})")

    # The risk-coverage curve and triage below use the deployed score: the
    # calibrated fused confidence.
    curve = risk_coverage_curve(cal)
    print(f"\n  {'coverage':>9s} {'risk':>8s} {'n_accepted':>11s}")
    print(f"  {'-'*9} {'-'*8} {'-'*11}")
    for p in _curve_at_deciles(curve):
        print(f"  {p.coverage:>8.1%} {p.risk:>7.1%} {p.n_accepted:>11d}")

    print(f"\n  Target-risk triage (accept IOCs scored >= 1 - target):")
    print(f"  {'target':>7s}   {'calibrated: coverage / risk':>30s}   "
          f"{'raw fused: coverage / risk':>28s}")
    target_rows = []
    for t in TARGET_RISKS:
        c = target_risk_point(cal, t)
        r = operating_point(raw, 1.0 - t)
        print(f"  {t:>6.0%}    {c.coverage:>13.1%} / {c.risk:>11.1%}   "
              f"{r.coverage:>13.1%} / {r.risk:>11.1%}")
        target_rows.append({
            "target_risk": t,
            "calibrated": c.to_dict(),
            "uncalibrated": r.to_dict(),
        })

    out = {
        "dataset": args.dataset,
        "calibrator": args.calibrator,
        "n_candidates": n,
        "base_risk": round(base_risk, 6),
        "aurc_by_source": aurc_by_source,
        "deployed_score_aurc": round(aurc(cal), 6),
        "risk_coverage_curve": [p.to_dict() for p in curve],
        "target_risk": target_rows,
    }
    out_path = f"data/evaluation/selective_prediction_{args.dataset}.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n💾 Saved to {out_path}")


if __name__ == "__main__":
    main()
