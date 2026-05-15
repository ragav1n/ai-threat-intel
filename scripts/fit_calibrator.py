"""
Fit and persist the production confidence calibrator.

The calibration study (run_calibration_study.py) showed that the regex+LLM
weighted fusion is miscalibrated and that isotonic regression corrects it.
This script fits an IsotonicCalibrator on the cached labelled predictions and
saves it so the live pipeline can apply it (see confidence_fusion.calibrate).

    python scripts/fit_calibrator.py

It pools every data/evaluation/calibration_predictions*.json file, fits the
calibrator on the FUSED (confidence, correct) pairs, reports the in-sample and
5-fold cross-validated calibration improvement, and writes the fitted model to
data/evaluation/fitted_calibrator.json.
"""
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


def load_fused_predictions() -> list:
    """Pool fused (confidence, correct) pairs from every cached prediction file."""
    preds = []
    files = sorted(glob.glob(PRED_GLOB))
    for path in files:
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
    preds = load_fused_predictions()
    if not preds:
        print("No cached predictions found — run scripts/run_calibration_study.py first.")
        return
    print(f"Pooled {len(preds)} fused predictions.\n")

    before = compute_calibration(preds)
    cv = kfold_calibration_eval(preds, IsotonicCalibrator)

    # Fit the deployed calibrator on ALL available data.
    calibrator = IsotonicCalibrator().fit(preds)
    after = compute_calibration(
        [(calibrator.transform([c])[0], y) for c, y in preds]
    )

    print(f"  Uncalibrated fused : Brier={before.brier_score:.4f}  ECE={before.ece:.4f}")
    print(f"  Isotonic (in-sample): Brier={after.brier_score:.4f}  ECE={after.ece:.4f}")
    print(f"  Isotonic (5-fold CV): Brier={cv.brier_score:.4f}  ECE={cv.ece:.4f}  "
          f"<- honest estimate of deployed quality")

    os.makedirs(os.path.dirname(CALIBRATOR_PATH), exist_ok=True)
    save_calibrator(calibrator, CALIBRATOR_PATH)
    print(f"\n💾 Fitted calibrator saved to {CALIBRATOR_PATH}")


if __name__ == "__main__":
    main()
