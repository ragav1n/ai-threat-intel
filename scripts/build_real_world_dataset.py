"""
Script to build a real-world Ground-Truth dataset using the Teacher LLM.

Usage: python scripts/build_real_world_dataset.py --input raw_reports.json --output real_world_dataset.json

The input JSON should be a list of reports:
[
  {"id": "cisa_001", "text": "...", "tags": ["cisa"]},
  {"id": "mandiant_001", "text": "...", "tags": ["mandiant"]}
]
"""

import argparse
import logging
from threat_intel_aggregator.evaluation.dataset_builder.builder import build_from_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    parser = argparse.ArgumentParser(description="Build a real-world CTI dataset.")
    parser.add_argument("--input", type=str, required=True, help="Path to raw reports JSON file")
    parser.add_argument("--output", type=str, required=True, help="Path to save the labeled dataset")
    parser.add_argument("--model", type=str, default="qwen2.5:7b", help="LLM model to use for labeling")
    
    args = parser.parse_args()
    
    print(f"Starting dataset creation pipeline...")
    print(f"Input: {args.input}")
    print(f"Output: {args.output}")
    print(f"Model: {args.model}")
    print("-" * 40)
    
    try:
        build_from_file(args.input, args.output, model=args.model)
        print("-" * 40)
        print(f"Dataset creation complete! Saved to {args.output}")
    except Exception as e:
        print(f"Error during dataset creation: {e}")

if __name__ == "__main__":
    main()
