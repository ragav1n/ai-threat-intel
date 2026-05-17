"""
Reproduce every headline paper number from cached predictions.

Runs the full analysis chain OFFLINE — no Ollama, no API keys, no network — by
reusing the cached LLM predictions in data/evaluation/. Each step is an
existing script; this is the single entry point that ties them together and
reports pass/fail.

    python scripts/reproduce_all.py

Regenerating the cached predictions themselves (the expensive LLM phase) is a
separate, online step — see RESULTS.md.
"""
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable

# (description, argv) — every step reads cached data only.
STEPS = [
    ("Fit production calibrator (pooled, PRISM-inclusive)",
     ["scripts/fit_calibrator.py"]),
    ("Fit leave-one-out calibrator (PRISM held out)",
     ["scripts/fit_calibrator.py", "--exclude-dataset", "prism",
      "--out", "data/evaluation/fitted_calibrator_no_prism.json"]),
    ("C2 calibration study — synthetic",
     ["scripts/run_calibration_study.py", "--dataset", "synthetic"]),
    ("C2 calibration study — real_world_v2_gpt55",
     ["scripts/run_calibration_study.py", "--dataset", "real_world_v2_gpt55"]),
    ("C2 calibration study — otx",
     ["scripts/run_calibration_study.py", "--dataset", "otx"]),
    ("C2 calibration study — prism (gold)",
     ["scripts/run_calibration_study.py", "--dataset", "prism"]),
    ("C1 obfuscation ablation — prism (gold)",
     ["scripts/run_obfuscation_ablation.py", "--dataset", "prism"]),
    ("End-to-end pipeline F1 — prism (gold, held-out calibrator)",
     ["scripts/eval_pipeline_f1.py", "--dataset", "prism",
      "--calibrator", "data/evaluation/fitted_calibrator_no_prism.json"]),
    ("Gold-benchmark baseline comparison — prism",
     ["scripts/run_gold_benchmark.py", "--dataset", "prism"]),
    ("C2 selective-prediction triage — prism (gold, held-out calibrator)",
     ["scripts/selective_prediction.py", "--dataset", "prism",
      "--calibrator", "data/evaluation/fitted_calibrator_no_prism.json"]),
    ("C2 calibration transfer across report sources",
     ["scripts/calibration_transfer.py"]),
]


def main() -> None:
    print("Reproducing all paper numbers from cached predictions "
          "(offline — no LLM, no network).\n")
    outcomes = []
    for desc, argv in STEPS:
        print("=" * 72)
        print(f"▶ {desc}")
        print("=" * 72)
        rc = subprocess.run([PY, *argv], cwd=REPO_ROOT).returncode
        outcomes.append((desc, rc == 0))
        print()

    print("=" * 72)
    print("  REPRODUCTION SUMMARY")
    print("=" * 72)
    for desc, ok in outcomes:
        print(f"  {'✓' if ok else '✗'}  {desc}")
    n_ok = sum(ok for _, ok in outcomes)
    print(f"\n  {n_ok}/{len(outcomes)} steps succeeded.")
    sys.exit(0 if n_ok == len(outcomes) else 1)


if __name__ == "__main__":
    main()
