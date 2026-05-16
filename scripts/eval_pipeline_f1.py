"""
End-to-end pipeline F1 — regex + deobfuscation + LLM verification + calibration.

The C1 obfuscation ablation measures the regex+deobfuscation layer alone. This
script reports the FULL pipeline: it reuses the per-IOC predictions cached by
the calibration study (extraction + LLM verification already done), applies the
fitted isotonic calibrator, and sweeps the keep-threshold to give precision /
recall / F1 against the dataset's gold labels.

    python scripts/eval_pipeline_f1.py --dataset prism

Because isotonic calibration is monotonic it does not change the precision-
recall ranking — the max-F1 ceiling is identical with or without it. What
calibration buys is a *meaningful* fixed threshold: on calibrated confidence,
0.5 means "≈50% likely to be a true IOC", so the operating point is principled
rather than arbitrary.
"""
import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.calibrators import load_calibrator
from threat_intel_aggregator.evaluation.datasets import load_samples

CALIBRATOR_PATH = "data/evaluation/fitted_calibrator.json"


def total_gold(dataset: str) -> int:
    """Micro count of gold IOC instances (per-sample, strip+lower normalised)."""
    g = 0
    for s in load_samples(dataset):
        g += len({
            (e["value"].strip().lower(), e["type"].strip().lower())
            for e in s["expected_iocs"]
        })
    return g


def prf(rows: list, key: str, tau: float, gold: int) -> dict:
    """Precision / recall / F1 keeping rows whose `key` score >= tau.

    FN = gold - TP, which correctly counts gold IOCs that were never extracted
    (they are absent from the prediction cache) as well as correct predictions
    dropped below the threshold.
    """
    tp = sum(1 for r in rows if r[key] >= tau and r["correct"])
    fp = sum(1 for r in rows if r[key] >= tau and not r["correct"])
    fn = gold - tp
    p = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / gold if gold else 0.0
    f1 = 2 * p * rec / (p + rec) if p + rec else 0.0
    return {"tau": round(tau, 2), "precision": p, "recall": rec, "f1": f1,
            "tp": tp, "fp": fp, "fn": fn}


def main() -> None:
    ap = argparse.ArgumentParser(description="End-to-end pipeline F1 from cached predictions.")
    ap.add_argument("--dataset", default="prism")
    args = ap.parse_args()

    pred_path = f"data/evaluation/calibration_predictions_{args.dataset}.json"
    with open(pred_path) as f:
        rows = json.load(f)
    calibrator = load_calibrator(CALIBRATOR_PATH)
    for r in rows:
        r["cal"] = calibrator.transform([r["fused"]])[0]

    gold = total_gold(args.dataset)
    extracted_correct = sum(1 for r in rows if r["correct"])
    print(f"=== End-to-end pipeline F1 — dataset: {args.dataset} ===")
    print(f"  gold IOC instances     : {gold}")
    print(f"  extracted predictions  : {len(rows)}")
    print(f"  of which match gold    : {extracted_correct}  "
          f"(extraction recall ceiling {extracted_correct / gold:.1%})")

    # Threshold sweep on the (monotonic) calibrated confidence.
    sweep = [prf(rows, "cal", t / 20, gold) for t in range(0, 20)]
    best = max(sweep, key=lambda d: d["f1"])

    print(f"\n  {'cal τ':>6s} {'Prec':>7s} {'Recall':>7s} {'F1':>7s}   {'TP':>5s} {'FP':>5s} {'FN':>5s}")
    print(f"  {'-'*6} {'-'*7} {'-'*7} {'-'*7}   {'-'*5} {'-'*5} {'-'*5}")
    for d in sweep:
        if round(d["tau"] * 20) % 2 == 0 or d is best:
            mark = "  <- max F1" if d is best else ""
            print(f"  {d['tau']:6.2f} {d['precision']:6.1%} {d['recall']:6.1%} "
                  f"{d['f1']:6.1%}   {d['tp']:5d} {d['fp']:5d} {d['fn']:5d}{mark}")

    op = prf(rows, "cal", 0.5, gold)
    raw = prf(rows, "fused", 0.5, gold)
    print(f"\n  Operating point — calibrated τ=0.5 : "
          f"P {op['precision']:.1%}  R {op['recall']:.1%}  F1 {op['f1']:.1%}")
    print(f"  (uncalibrated fused τ=0.5 for ref.) : "
          f"P {raw['precision']:.1%}  R {raw['recall']:.1%}  F1 {raw['f1']:.1%}")
    print(f"  Max F1 (pipeline ceiling)           : "
          f"F1 {best['f1']:.1%}  at calibrated τ={best['tau']}  "
          f"(P {best['precision']:.1%}  R {best['recall']:.1%})")

    out = {
        "dataset": args.dataset,
        "gold_ioc_instances": gold,
        "extracted_predictions": len(rows),
        "extraction_recall_ceiling": round(extracted_correct / gold, 4),
        "operating_point_calibrated_0.5": op,
        "max_f1": best,
        "sweep": sweep,
    }
    out_path = f"data/evaluation/pipeline_f1_{args.dataset}.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n💾 Saved to {out_path}")


if __name__ == "__main__":
    main()
