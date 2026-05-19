"""
Conformal risk-control study (research-paper contribution C2+).

Post-hoc isotonic calibration lowers ECE but gives no guarantee. This study
fits a conformal threshold (see `evaluation/conformal.py`) that auto-applies the
IOCs the pipeline is most sure of with a distribution-free, finite-sample
guarantee: the error rate among the auto-applied IOCs is at most `alpha`, with
probability at least `1 - delta`.

Per dataset it reports, for each confidence source (regex / LLM / fused):
  * an FDR-vs-coverage table — for each target error rate alpha, the fitted
    threshold, the achieved coverage and held-out error rate, all with CIs over
    calibration splits, plus the empirical guarantee coverage.
The coverage a guarantee can buy depends on how well the score *ranks* IOCs,
so the per-source split mirrors the AURC-by-source result in
`scripts/selective_prediction.py`.

It also reports a cross-source transfer matrix — fit the threshold on one report
source, apply it to another. The diagonal (per-source) holds the guarantee; the
off-diagonal need not, because conformal validity needs within-source
exchangeability. This is the conformal counterpart of the poor isotonic transfer
in `calibration_transfer.json`.

    python scripts/run_conformal_study.py                  # all cached datasets
    python scripts/run_conformal_study.py --dataset prism

Reads cached predictions only — no LLM, no network. Per-dataset output goes to
data/evaluation/conformal_study_<dataset>.json and the transfer matrix to
data/evaluation/conformal_transfer.json.
"""
import argparse
import glob
import json
import math
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.conformal import (
    conformal_threshold, evaluate_conformal, fdr_coverage_curve,
    format_conformal_table,
)
from threat_intel_aggregator.evaluation.selective import aurc, operating_point

PRED_GLOB = "data/evaluation/calibration_predictions_*.json"
PREFIX, SUFFIX = "calibration_predictions_", ".json"
# legacy qwen labels, superseded by real_world_v2_gpt55 (same predictions)
SUPERSEDED = {"real_world_v2"}

SOURCES = ["regex", "llm", "fused"]
ALPHAS = [0.01, 0.02, 0.05, 0.10, 0.20]
DELTA = 0.10
# the transfer matrix is built on the best-ranking score (see selective_prediction)
TRANSFER_SOURCE = "regex"
TRANSFER_ALPHA = 0.10


def _load_datasets() -> dict:
    """name -> raw cached prediction rows (each with regex/llm/fused/correct)."""
    datasets = {}
    for path in sorted(glob.glob(PRED_GLOB)):
        name = os.path.basename(path)[len(PREFIX):-len(SUFFIX)]
        if name in SUPERSEDED:
            continue
        with open(path) as f:
            datasets[name] = json.load(f)
    return datasets


def _source_preds(rows: list, source: str) -> list:
    """(confidence, correct) pairs for one confidence source; skips missing."""
    return [(r[source], bool(r["correct"]))
            for r in rows if r.get(source) is not None]


def _study_one(name: str, rows: list) -> dict:
    """FDR-vs-coverage tables for one dataset, one per confidence source."""
    print(f"=== Conformal risk control — dataset: {name} (N={len(rows)}) ===\n")
    summary = {"dataset": name, "n_predictions": len(rows), "delta": DELTA,
               "sources": {}}
    for source in SOURCES:
        preds = _source_preds(rows, source)
        if not preds:
            continue
        curve = fdr_coverage_curve(preds, ALPHAS, delta=DELTA)
        title = f"{name} — {source} confidence (AURC {aurc(preds):.3f})"
        print(format_conformal_table(curve, title=title))
        print()
        summary["sources"][source] = {
            "n": len(preds),
            "aurc": round(aurc(preds), 4),
            "alphas": {f"{a:.2f}": curve[a].to_dict() for a in ALPHAS},
        }
    out_path = f"data/evaluation/conformal_study_{name}.json"
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"💾 Saved to {out_path}\n")
    return summary


def _transfer_matrix(datasets: dict) -> dict:
    """Fit the conformal threshold on one source, realise its risk on another."""
    names = list(datasets)
    preds = {n: _source_preds(datasets[n], TRANSFER_SOURCE) for n in names}
    print(f"=== Conformal transfer across sources "
          f"({TRANSFER_SOURCE} confidence, alpha={TRANSFER_ALPHA}, "
          f"delta={DELTA}) ===\n")

    matrix = {}  # train -> {test -> {threshold, risk, coverage}}
    for train in names:
        matrix[train] = {}
        for test in names:
            if train == test:
                # honest in-domain estimate over calibration splits
                res = evaluate_conformal(preds[test], TRANSFER_ALPHA, DELTA)
                thr = res.threshold.mean if res.threshold else float("inf")
                risk = res.risk.mean
                cov = res.coverage.mean
            else:
                thr = conformal_threshold(preds[train], TRANSFER_ALPHA, DELTA)
                op = operating_point(preds[test], thr)
                risk, cov = op.risk, op.coverage
            matrix[train][test] = {
                "threshold": None if math.isinf(thr) else round(thr, 4),
                "risk": round(risk, 4),
                "coverage": round(cov, 4),
            }

    label_w = 22
    header = f"  {'train \\ test':<{label_w}s}" + "".join(f"{n[:13]:>14s}" for n in names)
    print(header)
    print("  " + "-" * (label_w + 14 * len(names)))
    for train in names:
        row = f"  {train[:label_w]:<{label_w}s}"
        for test in names:
            mark = "*" if train == test else " "
            row += f"{matrix[train][test]['risk']:>13.4f}{mark}"
        print(row)
    print("  " + "-" * (label_w + 14 * len(names)))
    print(f"\n  Cell = realised error rate among accepted IOCs on the column")
    print(f"  dataset, using the threshold fitted on the row dataset. * = in-domain")
    print(f"  (calibration-split mean). A valid in-domain cell is <= alpha="
          f"{TRANSFER_ALPHA}; off-diagonal cells above alpha show the guarantee")
    print(f"  does not transfer across report sources.")

    out = {
        "source": TRANSFER_SOURCE,
        "alpha": TRANSFER_ALPHA,
        "delta": DELTA,
        "datasets": names,
        "transfer_matrix": matrix,
    }
    out_path = "data/evaluation/conformal_transfer.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n💾 Saved to {out_path}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Conformal risk-control study.")
    ap.add_argument("--dataset", default=None,
                    help="single dataset; default runs every cached dataset")
    args = ap.parse_args()

    datasets = _load_datasets()
    if not datasets:
        print("No cached prediction files found.")
        return

    if args.dataset:
        if args.dataset not in datasets:
            print(f"Unknown dataset {args.dataset!r}. "
                  f"Available: {', '.join(datasets)}")
            sys.exit(1)
        _study_one(args.dataset, datasets[args.dataset])
        return

    for name in datasets:
        _study_one(name, datasets[name])
    if len(datasets) >= 2:
        _transfer_matrix(datasets)


if __name__ == "__main__":
    main()
