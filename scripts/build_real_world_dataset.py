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
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)


def _load_dotenv(path: str) -> None:
    """Minimal KEY=value .env loader (no python-dotenv dependency).

    Populates os.environ for keys not already set, so the teacher labeler can
    pick up OPENAI_API_KEY / ANTHROPIC_API_KEY from a repo-root .env file.
    Real environment variables always win over .env.
    """
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


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
    parser.add_argument(
        "--model", type=str, default="gpt-5.5",
        help="Teacher model for labeling. Provider is auto-detected: gpt-*/o1-* "
             "(needs OPENAI_API_KEY), claude-* (needs ANTHROPIC_API_KEY), or any "
             "other name = local Ollama. A frontier teacher is strongly "
             "recommended for publication-grade labels.")
    parser.add_argument("--validate", type=str, metavar="DATASET.json",
                        help="Validate text-grounding of an existing dataset and exit (no LLM)")

    args = parser.parse_args()

    _load_dotenv(os.path.join(REPO_ROOT, ".env"))

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
