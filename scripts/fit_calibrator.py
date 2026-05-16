"""
Fit and persist the production confidence calibrator.

The calibration study (run_calibration_study.py) showed that the regex+LLM
weighted fusion is miscalibrated and that isotonic regression corrects it.
This script fits an IsotonicCalibrator on the cached labelled predictions and
saves it so the live pipeline can apply it (see confidence_fusion.calibrate).

    python scripts/fit_calibrator.py                          # production fit
    python scripts/fit_calibrator.py --exclude-dataset prism \
        --out data/evaluation/fitted_calibrator_no_prism.json # leave-one-out

It pools every data/evaluation/calibration_predictions*.json file, fits the
calibrator on the FUSED (confidence, correct) pairs, reports the in-sample and
5-fold cross-validated calibration improvement, and writes the fitted model.

`--exclude-dataset` holds named datasets OUT of the fit (comma-separated) — use
it to produce a calibrator that is out-of-sample for a benchmark, so that
benchmark's calibrated operating point carries no in-sample optimism.
"""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel_aggregator.evaluation.calibration import compute_calibration
from threat_intel_aggregator.evaluation.calibrators import (
    IsotonicCalibrator, kfold_calibration_eval, save_calibrator,
)

PRED_GLOB = "data/evaluation/calibration_predictions*.json"
CALIBRATOR_PATH = "data/evaluation/fitted_calibrator.json"

# real_world_v2 (qwen2.5:7b labels) is superseded by real_world_v2_gpt55 — the
# SAME 651 extracted predictions re-judged against cleaner gpt-5.5 labels.
# Pooling both would double-count those points with conflicting `correct`
# values, so the legacy qwen cache is excluded from the production fit.
SUPERSEDED = {"data/evaluation/calibration_predictions_real_world_v2.json"}


def _dataset_name(path: str) -> str:
    """Extract the dataset name from a calibration_predictions_<name>.json path."""
    base = os.path.basename(path)
    prefix, suffix = "calibration_predictions_", ".json"
    if base.startswith(prefix) and base.endswith(suffix):
        return base[len(prefix):-len(suffix)]
    return ""


def load_fused_predictions(exclude: frozenset = frozenset()) -> list:
    """Pool fused (confidence, correct) pairs from every cached prediction file.

    `exclude` is a set of dataset names whose prediction cache is held out of
    the fit (in addition to the always-excluded SUPERSEDED files).
    """
    preds = []
    for path in sorted(glob.glob(PRED_GLOB)):
        if path in SUPERSEDED:
            print(f"  {path}: skipped (superseded)")
            continue
        name = _dataset_name(path)
        if name in exclude:
            print(f"  {path}: skipped (held out: {name})")
            continue
        with open(path) as f:
            rows = json.load(f)
        n = sum(1 for r in rows if r.get("fused") is not None)
        preds.extend(
            (r["fused"], bool(r["correct"]))
            for r in rows if r.get("fused") is not None
        )
        print(f"  {path}: {n} fused predictions")
    return preds


def main() -> None:
    ap = argparse.ArgumentParser(description="Fit the production confidence calibrator.")
    ap.add_argument("--exclude-dataset", default="",
                    help="comma-separated dataset names to hold OUT of the fit "
                         "(e.g. 'prism' for an out-of-sample operating point)")
    ap.add_argument("--out", default=CALIBRATOR_PATH,
                    help="output path for the fitted calibrator JSON")
    args = ap.parse_args()

    exclude = frozenset(d.strip() for d in args.exclude_dataset.split(",") if d.strip())
    preds = load_fused_predictions(exclude)
    if not preds:
        print("No cached predictions found — run scripts/run_calibration_study.py first.")
        return
    print(f"Pooled {len(preds)} fused predictions.\n")

    before = compute_calibration(preds)
    cv = kfold_calibration_eval(preds, IsotonicCalibrator)

    # Fit the deployed calibrator on ALL pooled data.
    calibrator = IsotonicCalibrator().fit(preds)
    after = compute_calibration(
        [(calibrator.transform([c])[0], y) for c, y in preds]
    )

    print(f"  Uncalibrated fused : Brier={before.brier_score:.4f}  ECE={before.ece:.4f}")
    print(f"  Isotonic (in-sample): Brier={after.brier_score:.4f}  ECE={after.ece:.4f}")
    print(f"  Isotonic (5-fold CV): Brier={cv.brier_score:.4f}  ECE={cv.ece:.4f}  "
          f"<- honest estimate of deployed quality")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    save_calibrator(calibrator, args.out)
    print(f"\n💾 Fitted calibrator saved to {args.out}")


if __name__ == "__main__":
    main()
