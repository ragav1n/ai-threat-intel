"""
Confidence Calibration Study (research-paper contribution C2).

Runs the full IOC-extraction pipeline over the ground-truth dataset and measures
how well-calibrated each confidence source is:

  * Regex only          — the regex extractor's multi-factor confidence
  * Raw LLM             — the Ollama verifier's self-reported confidence
  * Fused (0.4/0.6)     — confidence_fusion of regex + LLM
  * Fused + Temperature — fused score after post-hoc temperature scaling (k-fold CV)
  * Fused + Isotonic    — fused score after post-hoc isotonic regression (k-fold CV)

Calibration is quantified with Brier score, ECE and MCE. The hypothesis: fusion
improves calibration over the raw LLM, and a post-hoc calibrator improves it
further — addressing the miscalibration that Mezzi et al. (ARES 2025) report.

The raw (confidence, correct) observations are cached to JSON after the LLM
phase, so calibration can be re-analysed without re-querying the LLM:

    python scripts/run_calibration_study.py                       # synthetic set
    python scripts/run_calibration_study.py --dataset real_world_v2
    python scripts/run_calibration_study.py --dataset real_world_v2 --fresh

`--dataset` accepts any name from the dataset registry; `--fresh` forces the
LLM phase to re-run instead of using the cached predictions.
"""
import json
import logging
import os
import sys
import time

# Allow running directly from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel_aggregator.evaluation.datasets import load_samples
from threat_intel_aggregator.evaluation.calibration import (
    compute_calibration, format_calibration_comparison, format_reliability_diagram,
)
from threat_intel_aggregator.evaluation.calibrators import (
    TemperatureScaler, IsotonicCalibrator, kfold_calibration_eval,
)
from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
from threat_intel_aggregator.feed_collection.llm_ioc_verifier import get_llm_verifier
from threat_intel_aggregator.feed_collection.confidence_fusion import fuse_with_penalty

logging.basicConfig(level=logging.WARNING, format="%(message)s")

def _pred_path(dataset: str) -> str:
    return f"data/evaluation/calibration_predictions_{dataset}.json"


def _out_path(dataset: str) -> str:
    return f"data/evaluation/calibration_study_{dataset}.json"


def _norm(v: str) -> str:
    return v.strip().lower()


def collect_predictions(dataset: str) -> list:
    """Run extraction + LLM verification over a dataset; label each IOC."""
    samples = load_samples(dataset)
    verifier = get_llm_verifier()
    available = verifier.is_available()
    if available:
        print(f"LLM verifier available — model: {verifier.model}")
    else:
        print("⚠️  LLM verifier unavailable — LLM/fused columns will be regex-only.")

    rows: list = []
    start = time.time()

    for i, sample in enumerate(samples):
        matches = extract_iocs_with_confidence(sample["text"], min_confidence=0.0)
        if not matches:
            continue

        expected = {
            (_norm(e["value"]), _norm(e["type"])) for e in sample["expected_iocs"]
        }
        verified = verifier.batch_verify(matches, max_iocs=100)

        for v in verified:
            regex_c = v.get("regex_confidence", 0.0)
            llm_c = v.get("llm_confidence")  # None if LLM unavailable / skipped
            fused = fuse_with_penalty(regex_c, llm_c, v.get("is_valid_ioc"))
            correct = (_norm(v["ioc"]), _norm(v["type"])) in expected
            rows.append({
                "value": v["ioc"],
                "type": v["type"],
                "regex": round(float(regex_c), 6),
                "llm": None if llm_c is None else round(float(llm_c), 6),
                "fused": round(float(fused), 6),
                "correct": bool(correct),
            })

        if (i + 1) % 20 == 0 or i + 1 == len(samples):
            elapsed = time.time() - start
            print(f"  processed {i + 1}/{len(samples)} samples "
                  f"({len(rows)} IOCs, {elapsed:.0f}s)")

    pred_path = _pred_path(dataset)
    os.makedirs(os.path.dirname(pred_path), exist_ok=True)
    with open(pred_path, "w") as f:
        json.dump(rows, f, indent=1)
    print(f"💾 Cached {len(rows)} labelled predictions to {pred_path}")
    return rows


def analyze(rows: list) -> dict:
    """Compute calibration for every confidence source and calibrator."""
    regex_preds = [(r["regex"], r["correct"]) for r in rows]
    llm_preds = [(r["llm"], r["correct"]) for r in rows if r["llm"] is not None]
    fused_preds = [(r["fused"], r["correct"]) for r in rows]

    results = {
        "Regex only": compute_calibration(regex_preds),
        "Raw LLM": compute_calibration(llm_preds),
        "Fused (0.4/0.6)": compute_calibration(fused_preds),
        "Fused + Temperature*": kfold_calibration_eval(fused_preds, TemperatureScaler),
        "Fused + Isotonic*": kfold_calibration_eval(fused_preds, IsotonicCalibrator),
    }

    print()
    print(format_calibration_comparison(results))
    print("  * = post-hoc calibrator, evaluated with 5-fold cross-validation")
    print()
    print(format_reliability_diagram(results["Raw LLM"], "Raw LLM confidence"))
    print()
    print(format_reliability_diagram(results["Fused + Temperature*"],
                                     "Fused + Temperature (out-of-fold)"))

    # Temperature fit on the full dataset — reported for reproducibility.
    full_temp = TemperatureScaler().fit(fused_preds).temperature

    return {
        "n_predictions": len(rows),
        "n_llm_verified": len(llm_preds),
        "fused_temperature": round(full_temp, 4),
        "results": {name: r.to_dict() for name, r in results.items()},
    }


def _arg_value(flag: str, default: str) -> str:
    if flag in sys.argv:
        idx = sys.argv.index(flag)
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return default


def main() -> None:
    fresh = "--fresh" in sys.argv
    dataset = _arg_value("--dataset", "synthetic")
    pred_path, out_path = _pred_path(dataset), _out_path(dataset)
    print(f"=== Calibration study — dataset: {dataset} ===")

    if not fresh and os.path.exists(pred_path):
        with open(pred_path) as f:
            rows = json.load(f)
        print(f"Loaded {len(rows)} cached predictions from {pred_path} "
              f"(use --fresh to re-run the LLM).")
    else:
        rows = collect_predictions(dataset)

    if not rows:
        print("No predictions collected — aborting.")
        return

    summary = analyze(rows)
    summary["dataset"] = dataset
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n💾 Calibration study saved to {out_path}")


if __name__ == "__main__":
    main()
