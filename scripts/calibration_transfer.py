"""
Calibration transfer across report sources (research-paper contribution C2).

A confidence calibrator is fitted on labelled predictions from one dataset.
Does it still hold on a different one? If a calibrator generalises across
sources, a single calibrator can ship with the pipeline; if not, each source
needs its own. This builds the train-by-test ECE matrix:

  * diagonal (train == test): honest in-domain ECE via 5-fold cross-validation
  * off-diagonal: fit on the row dataset, measure ECE on the column dataset
  * the `uncalibrated` row: each dataset's ECE with no calibration, for reference

    python scripts/calibration_transfer.py

Reads cached predictions only, so it needs no LLM and no network. Output is
written to data/evaluation/calibration_transfer.json.
"""
import glob
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.calibration import compute_calibration
from threat_intel_aggregator.evaluation.calibrators import (
    IsotonicCalibrator, kfold_calibration_eval,
)

PRED_GLOB = "data/evaluation/calibration_predictions_*.json"
PREFIX, SUFFIX = "calibration_predictions_", ".json"
# legacy qwen labels, superseded by real_world_v2_gpt55 (same predictions)
SUPERSEDED = {"real_world_v2"}


def _load_datasets() -> dict:
    """name -> list of (fused confidence, correct) pairs, from cached files."""
    datasets = {}
    for path in sorted(glob.glob(PRED_GLOB)):
        name = os.path.basename(path)[len(PREFIX):-len(SUFFIX)]
        if name in SUPERSEDED:
            continue
        with open(path) as f:
            rows = json.load(f)
        datasets[name] = [(r["fused"], bool(r["correct"]))
                          for r in rows if r.get("fused") is not None]
    return datasets


def main() -> None:
    datasets = _load_datasets()
    names = list(datasets)
    if len(names) < 2:
        print("Need at least two prediction caches for a transfer matrix.")
        return
    print(f"=== Calibration transfer — datasets: {', '.join(names)} ===\n")

    uncalibrated = {n: compute_calibration(datasets[n]).ece for n in names}

    matrix = {}  # train -> {test -> ECE}
    for train in names:
        matrix[train] = {}
        fitted = IsotonicCalibrator().fit(datasets[train])
        for test in names:
            if train == test:
                ece = kfold_calibration_eval(datasets[test], IsotonicCalibrator).ece
            else:
                xs = [c for c, _ in datasets[test]]
                ys = [y for _, y in datasets[test]]
                ece = compute_calibration(list(zip(fitted.transform(xs), ys))).ece
            matrix[train][test] = round(ece, 4)

    label_w = 22
    header = f"  {'train \\ test':<{label_w}s}" + "".join(f"{n[:13]:>14s}" for n in names)
    print(header)
    print("  " + "-" * (label_w + 14 * len(names)))
    for train in names:
        row = f"  {train[:label_w]:<{label_w}s}"
        for test in names:
            mark = "*" if train == test else " "
            row += f"{matrix[train][test]:>13.4f}{mark}"
        print(row)
    print("  " + "-" * (label_w + 14 * len(names)))
    print(f"  {'(uncalibrated)':<{label_w}s}"
          + "".join(f"{uncalibrated[n]:>14.4f}" for n in names))
    print("\n  Cell = ECE on the column dataset after calibrating with the row")
    print("  dataset's calibrator. * = in-domain (5-fold CV). Lower is better.")
    print("  Off-diagonal near the diagonal = the calibrator transfers across")
    print("  sources; off-diagonal near (uncalibrated) = it does not.")

    out = {
        "datasets": names,
        "uncalibrated_ece": {n: round(uncalibrated[n], 4) for n in names},
        "transfer_matrix": matrix,
    }
    out_path = "data/evaluation/calibration_transfer.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n💾 Saved to {out_path}")


if __name__ == "__main__":
    main()
