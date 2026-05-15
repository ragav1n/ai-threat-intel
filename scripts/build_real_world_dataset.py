"""
Build (or validate) a real-world ground-truth dataset for IOC extraction.

Build mode — label raw reports with the Teacher LLM:

    python scripts/build_real_world_dataset.py --input raw_reports.json \
        --output real_world_dataset.json

The input JSON is a list of reports (or a {"samples": [...]} wrapper):

    [{"id": "cisa_001", "text": "...", "tags": ["cisa"]}, ...]

Validate mode — check an existing dataset without calling the LLM:

    python scripts/build_real_world_dataset.py --validate data/evaluation/some_dataset.json

Validation measures *text-grounding*: the fraction of labelled IOCs that
actually occur in their report text. A dataset whose labels were scraped from a
separate indicator feed (the defect behind benchmark_dataset.json, only
0.1%-grounded) is unusable for extraction evaluation — this mode catches it.
Every build also runs validation automatically before saving.
"""

import argparse
import logging
import os
import sys

# Allow running directly from the repo root (python scripts/build_real_world_dataset.py).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel_aggregator.evaluation.dataset_builder.builder import build_from_file
from threat_intel_aggregator.evaluation.dataset_builder.validation import (
    format_grounding_report, grounding_report,
)
from threat_intel_aggregator.evaluation.datasets import load_samples

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def validate_only(path: str) -> int:
    """Validate the text-grounding of an existing dataset file. Returns an exit code."""
    print(f"Validating dataset: {path}")
    print("-" * 56)
    samples = load_samples(path)
    report = grounding_report(samples)
    print(format_grounding_report(report))
    return 0 if report["ok"] else 1


def main():
    parser = argparse.ArgumentParser(description="Build or validate a real-world CTI dataset.")
    parser.add_argument("--input", type=str, help="Path to raw reports JSON file")
    parser.add_argument("--output", type=str, help="Path to save the labeled dataset")
    parser.add_argument("--model", type=str, default="qwen2.5:7b", help="LLM model to use for labeling")
    parser.add_argument("--validate", type=str, metavar="DATASET.json",
                        help="Validate text-grounding of an existing dataset and exit (no LLM)")

    args = parser.parse_args()

    if args.validate:
        sys.exit(validate_only(args.validate))

    if not args.input or not args.output:
        parser.error("--input and --output are required for build mode "
                     "(or use --validate to check an existing dataset)")

    print(f"Starting dataset creation pipeline...")
    print(f"Input: {args.input}")
    print(f"Output: {args.output}")
    print(f"Model: {args.model}")
    print("-" * 40)

    try:
        report = build_from_file(args.input, args.output, model=args.model)
        print("-" * 40)
        print(format_grounding_report(report))
        print("-" * 40)
        print(f"Dataset creation complete! Saved to {args.output}")
        if not report["ok"]:
            print("⚠️  WARNING: the built dataset is poorly text-grounded — "
                  "review the labeller and input before using it for evaluation.")
    except Exception as e:
        print(f"Error during dataset creation: {e}")


if __name__ == "__main__":
    main()
