"""
Multi-Model Benchmark Script

Runs the full IOC extraction evaluation across multiple LLM models
and prints a unified comparison table.

Usage:
    source venv/bin/activate
    python scripts/multi_model_benchmark.py

Models to benchmark (edit MODELS below to add/remove):
    - qwen3.5:4b   (fast, lightweight)
    - qwen3.5:9b   (balanced)
    - qwen2.5:32b  (maximum accuracy)
"""
import os
import sys
import logging
import json
from typing import Dict, List

# Ensure the project root is on the path when running this script directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

MODELS: List[Dict] = [
    {"name": "qwen3.5:4b",  "label": "Qwen3.5 4B  (Fast)"},
    {"name": "qwen3.5:9b",  "label": "Qwen3.5 9B  (Balanced)"},
    {"name": "qwen2.5:32b", "label": "Qwen2.5 32B (Best)"},
]

# These baselines run once (no LLM, model-independent)
STATIC_BASELINES = ["regex_only", "our_pipeline", "iocextract", "ioc_finder"]

# Optionally limit to a subset of dataset samples for speed
MAX_SAMPLES: int = None  # Set to e.g. 50 to run faster

# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_samples(max_samples: int = None):
    """Load evaluation samples from ground truth dataset."""
    from threat_intel_aggregator.evaluation.ground_truth import GroundTruthDataset
    dataset = GroundTruthDataset()
    samples = [
        {
            "text": s.text,
            "expected_iocs": [e.to_dict() for e in s.expected_iocs],
            "category": s.category,
        }
        for s in dataset.samples
    ]
    if max_samples:
        samples = samples[:max_samples]
    return samples


def _format_table(all_results: Dict[str, Dict]) -> str:
    """Format a combined results table."""
    col_w = 36
    num_w = 10
    header = f"{'Baseline / Model':<{col_w}} {'Precision':>{num_w}} {'Recall':>{num_w}} {'F1':>{num_w}}"
    sep = "─" * (col_w + num_w * 3 + 2)

    lines = [
        "",
        "═" * (col_w + num_w * 3 + 2),
        "  MULTI-MODEL BENCHMARK — IOC EXTRACTION",
        "═" * (col_w + num_w * 3 + 2),
        header,
        sep,
    ]

    for label, r in all_results.items():
        lines.append(
            f"{label:<{col_w}} {r['precision']:>{num_w}.3f} {r['recall']:>{num_w}.3f} {r['f1']:>{num_w}.3f}"
        )

    lines.append(sep)
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    from threat_intel_aggregator.evaluation.baseline_comparison import (
        run_baseline_comparison,
        BASELINES,
    )

    samples = _load_samples(MAX_SAMPLES)
    logger.info(f"Loaded {len(samples)} evaluation samples")

    all_results: Dict[str, Dict] = {}

    # Step 1: Run static baselines (regex, iocextract, ioc_finder) once
    logger.info("Running static baselines (no LLM)...")
    static_results = run_baseline_comparison(samples, baselines=[
        b for b in STATIC_BASELINES if b in BASELINES
    ])
    for key, r in static_results.items():
        label = BASELINES[key][0]
        all_results[label] = {"precision": r.precision, "recall": r.recall, "f1": r.f1}
        logger.info(f"  ✓ {label}: F1={r.f1:.3f}")

    # Step 2: Run LLM pipeline for each model
    for model_cfg in MODELS:
        model_name = model_cfg["name"]
        model_label = f"Our Pipeline + LLM  [{model_cfg['label']}]"
        logger.info(f"\nRunning LLM evaluation with model: {model_name}")

        # Set model via environment variable (picked up by get_llm_verifier)
        os.environ["IOC_VERIFIER_MODEL"] = model_name

        # Force re-instantiation of the verifier singleton with the new model
        try:
            from threat_intel_aggregator.feed_collection import llm_ioc_verifier as _v
            _v._verifier_instance = None  # Reset singleton
        except Exception:
            pass

        llm_results = run_baseline_comparison(samples, baselines=["our_pipeline_llm"])
        r = llm_results.get("our_pipeline_llm")
        if r:
            all_results[model_label] = {"precision": r.precision, "recall": r.recall, "f1": r.f1}
            logger.info(f"  ✓ {model_label}: F1={r.f1:.3f}")
        else:
            logger.warning(f"  ✗ No results for {model_name}")

    # Step 3: Print table
    print(_format_table(all_results))

    # Step 4: Save JSON for later use
    output_path = "data/evaluation/multi_model_benchmark.json"
    os.makedirs("data/evaluation", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)
    logger.info(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
