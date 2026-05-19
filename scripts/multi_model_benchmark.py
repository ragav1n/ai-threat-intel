"""
Multi-Model IOC-Extraction Benchmark (research contribution C3).

Runs the full pipeline (regex + deobfuscation + LLM verification) with several
LLM backends and compares them — local Qwen against the frontier cloud models
GPT-5.5, Claude and Gemini — on a gold dataset (PRISM by default). This is the
evidence for C3's claim that a small *local* LLM matches cloud-scale LLMs for
IOC extraction. Every P/R/F1 carries a 95% bootstrap confidence interval.

    python scripts/multi_model_benchmark.py                       # PRISM, full
    python scripts/multi_model_benchmark.py --max-samples 10       # quick smoke
    python scripts/multi_model_benchmark.py --models qwen3.5:9b,gpt-5.5

Cloud models need OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY — the
script loads them from a repo-root .env file. Results are written to
data/evaluation/multi_model_benchmark_<dataset>.json.
"""
import argparse
import json
import logging
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

logging.basicConfig(level=logging.WARNING, format="%(message)s")
logger = logging.getLogger(__name__)

# C3 default model set: one representative small local model + three frontier
# cloud vendors. Override with --models.
DEFAULT_MODELS = [
    {"name": "qwen3.5:9b",            "label": "Qwen3.5 9B (local)"},
    {"name": "gpt-5.5",               "label": "GPT-5.5 (OpenAI)"},
    {"name": "claude-sonnet-4-6",     "label": "Claude Sonnet 4.6 (Anthropic)"},
    {"name": "gemini-3-flash-preview", "label": "Gemini 3 Flash (Google)"},
]
STATIC_BASELINES = ["regex_only", "our_pipeline", "iocextract", "ioc_finder"]


def _load_dotenv(path: str) -> None:
    """Minimal KEY=value .env loader (cloud API keys); real env vars win."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def _row(result, boot) -> dict:
    """One results row: point P/R/F1 plus the F1 bootstrap CI."""
    return {
        "precision": round(result.precision, 4),
        "recall": round(result.recall, 4),
        "f1": round(result.f1, 4),
        "f1_ci": [round(boot.f1_ci.ci_lower, 4), round(boot.f1_ci.ci_upper, 4)],
        "true_positives": result.true_positives,
        "false_positives": result.false_positives,
        "false_negatives": result.false_negatives,
    }


def _format_table(rows: dict) -> str:
    lines = ["", "=" * 78,
             "  MULTI-MODEL BENCHMARK — IOC EXTRACTION (C3)",
             "=" * 78,
             f"  {'Baseline / Model':<34s} {'Prec':>7s} {'Recall':>7s} "
             f"{'F1':>7s} {'F1 95% CI':>16s}",
             f"  {'-'*34} {'-'*7} {'-'*7} {'-'*7} {'-'*16}"]
    for label, r in rows.items():
        ci = f"[{r['f1_ci'][0]:.3f},{r['f1_ci'][1]:.3f}]"
        lines.append(f"  {label:<34s} {r['precision']:>6.1%} {r['recall']:>6.1%} "
                     f"{r['f1']:>6.1%} {ci:>16s}")
    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Multi-model IOC-extraction benchmark.")
    ap.add_argument("--dataset", default="prism", help="registered dataset name")
    ap.add_argument("--max-samples", type=int, default=None,
                    help="cap the number of samples (for a quick smoke run)")
    ap.add_argument("--n-iterations", type=int, default=1000, help="bootstrap resamples")
    ap.add_argument("--models", default="",
                    help="comma-separated model names (default: qwen3.5:9b + 3 cloud)")
    ap.add_argument("--merge", action="store_true",
                    help="splice this run's model rows into the existing "
                         "benchmark file instead of overwriting it")
    args = ap.parse_args()

    _load_dotenv(os.path.join(REPO_ROOT, ".env"))

    from threat_intel_aggregator.evaluation.baseline_comparison import (
        BASELINES, run_baseline_comparison,
    )
    from threat_intel_aggregator.evaluation.bootstrap_ci import compute_bootstrap_ci
    from threat_intel_aggregator.evaluation.datasets import load_samples
    from threat_intel_aggregator.feed_collection import llm_ioc_verifier as _v

    if args.models:
        # Reuse the curated label from DEFAULT_MODELS when the name is known.
        known = {m["name"]: m["label"] for m in DEFAULT_MODELS}
        models = [{"name": n, "label": known.get(n, n)}
                  for n in (m.strip() for m in args.models.split(",")) if n]
    else:
        models = DEFAULT_MODELS

    samples = load_samples(args.dataset)
    if args.max_samples:
        samples = samples[:args.max_samples]
    print(f"=== Multi-model benchmark — dataset: {args.dataset} "
          f"({len(samples)} samples) ===")

    rows: dict = {}

    # Static, model-independent baselines — run once, with CIs.
    print("Running static baselines (no LLM)...")
    static_results, static_ps = run_baseline_comparison(
        samples, baselines=STATIC_BASELINES, collect_per_sample=True)
    for key, r in static_results.items():
        boot = compute_bootstrap_ci(static_ps[key], n_iterations=args.n_iterations)
        rows[BASELINES[key][0]] = _row(r, boot)
        print(f"  ✓ {BASELINES[key][0]}: F1={r.f1:.3f}")

    # Full LLM pipeline, once per model. Each model writes a JSONL verdict
    # cache, so a run interrupted by a rate limit resumes where it stopped on
    # re-invocation. Delete the cache file to force a fresh run.
    for m in models:
        print(f"Running LLM pipeline with: {m['name']} ...")
        os.environ["IOC_VERIFIER_MODEL"] = m["name"]
        safe_name = "".join(c if c.isalnum() else "_" for c in m["name"])
        cache_path = (f"data/evaluation/llm_verify_cache_"
                      f"{args.dataset}_{safe_name}.jsonl")
        os.environ["IOC_VERIFY_CACHE"] = cache_path
        if os.path.exists(cache_path):
            print(f"  ↻ resuming — reusing cached verdicts in {cache_path}")
        _v._verifier_instance = None  # force re-instantiation with the new model

        # Refuse to record a row for a backend that is not actually reachable.
        # Otherwise its verification silently falls back to regex-only and the
        # benchmark reports the regex baseline under the model's name.
        if not _v.get_llm_verifier().is_available():
            print(f"  ✗ {m['label']}: SKIPPED — backend unavailable "
                  f"(no quota, bad key, or unreachable)")
            continue

        results, per_sample = run_baseline_comparison(
            samples, baselines=["our_pipeline_llm"], collect_per_sample=True)
        r = results["our_pipeline_llm"]
        boot = compute_bootstrap_ci(per_sample["our_pipeline_llm"],
                                    n_iterations=args.n_iterations)
        rows[f"Our Pipeline + LLM [{m['label']}]"] = _row(r, boot)
        print(f"  ✓ {m['label']}: F1={r.f1:.3f}")

    print(_format_table(rows))

    out = {
        "dataset": args.dataset,
        "n_samples": len(samples),
        "n_iterations": args.n_iterations,
        "models": [m["name"] for m in models],
        "results": rows,
    }
    out_path = f"data/evaluation/multi_model_benchmark_{args.dataset}.json"
    os.makedirs("data/evaluation", exist_ok=True)

    if args.merge and os.path.exists(out_path):
        # Splice only this run's model-pipeline rows into the existing file;
        # leave its static baselines and other models' rows byte-identical.
        with open(out_path) as f:
            merged = json.load(f)
        new_model_rows = {k: v for k, v in rows.items()
                          if k.startswith("Our Pipeline + LLM [")}
        if not new_model_rows:
            print("\n⚠️  --merge: no model row was produced this run "
                  "(backend skipped?); leaving the existing file untouched.")
            return
        merged["results"].update(new_model_rows)
        for name in (m["name"] for m in models):
            if name not in merged["models"]:
                merged["models"].append(name)
        out = merged
        print(f"\n🔀 Merged {len(new_model_rows)} model row(s) into {out_path}")

    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n💾 Saved to {out_path}")


if __name__ == "__main__":
    main()
