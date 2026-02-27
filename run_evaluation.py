"""
Run the Full Phase 5 Evaluation Pipeline.

Usage: python run_evaluation.py

Includes:
  1. Core P/R/F1 metrics (micro, macro, weighted) + MCC + Cohen's κ
  2. Baseline comparison (our pipeline vs iocextract)
  3. Ablation study (regex-only → full pipeline)
  4. Bootstrap 95% confidence intervals
  5. Error analysis (FP/FN categorisation)
  6. Latency benchmarks
"""

import json
from threat_intel_aggregator.evaluation.ground_truth import GroundTruthDataset
from threat_intel_aggregator.evaluation.metrics_engine import MetricsEngine
from threat_intel_aggregator.evaluation.latency_benchmark import LatencyBenchmark
from threat_intel_aggregator.evaluation.baseline_comparison import run_baseline_comparison, format_comparison_table
from threat_intel_aggregator.evaluation.ablation_study import run_ablation_study, format_ablation_table
from threat_intel_aggregator.evaluation.bootstrap_ci import compute_bootstrap_ci, format_bootstrap_table
from threat_intel_aggregator.evaluation.error_analysis import run_error_analysis, format_error_analysis
from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence


def main():
    # ── Load dataset ────────────────────────────────────────
    dataset = GroundTruthDataset()
    print(f"Dataset: {dataset.total_samples} samples, {dataset.total_expected_iocs} expected IOCs")
    print(f"Categories: {json.dumps(dataset.category_counts())}\n")

    # ── Run extraction ──────────────────────────────────────
    eval_samples = []
    for sample in dataset.samples:
        matches = extract_iocs_with_confidence(sample.text, include_private_ips=False, min_confidence=0.0)
        extracted = [{"value": m.value, "type": str(m.ioc_type), "confidence": m.confidence} for m in matches]
        eval_samples.append({
            "id": sample.id,
            "text": sample.text,
            "expected_iocs": [e.to_dict() for e in sample.expected_iocs],
            "extracted_iocs": extracted,
            "category": sample.category,
        })

    # ── 1. Core Metrics ─────────────────────────────────────
    engine = MetricsEngine()
    m = engine.evaluate(eval_samples)

    print("=" * 68)
    print("  1. CORE EVALUATION METRICS")
    print("=" * 68)
    print(f"  Precision (Micro):  {m.precision:.4f} ({m.precision*100:.1f}%)")
    print(f"  Recall (Micro):     {m.recall:.4f} ({m.recall*100:.1f}%)")
    print(f"  F1 Score (Micro):   {m.f1:.4f} ({m.f1*100:.1f}%)")
    print()
    print(f"  Macro Precision:    {m.macro_precision:.4f} ({m.macro_precision*100:.1f}%)")
    print(f"  Macro Recall:       {m.macro_recall:.4f} ({m.macro_recall*100:.1f}%)")
    print(f"  Macro F1:           {m.macro_f1:.4f} ({m.macro_f1*100:.1f}%)")
    print(f"  Weighted F1:        {m.weighted_f1:.4f} ({m.weighted_f1*100:.1f}%)")
    print()
    print(f"  MCC:                {m.mcc:.4f}")
    print(f"  Cohen's Kappa:      {m.cohens_kappa:.4f}")
    print()
    print(f"  TP: {m.true_positives}  FP: {m.false_positives}  FN: {m.false_negatives}  TN: {m.true_negatives}")
    print()
    print("  Confidence Calibration:")
    print(f"    Avg TP Confidence: {m.avg_tp_confidence:.4f}")
    print(f"    Avg FP Confidence: {m.avg_fp_confidence:.4f}")
    print()
    print("  Category Accuracy:")
    for cat, acc in sorted(m.category_accuracy.items()):
        print(f"    {cat:20s} {acc*100:.1f}%")
    print()
    print("  Per-Type Breakdown:")
    print(f"    {'Type':8s} {'TP':>4s} {'FP':>4s} {'FN':>4s} {'Prec':>7s} {'Recall':>7s} {'F1':>7s}")
    for t in sorted(m.per_type.keys()):
        tm = m.per_type[t]
        print(f"    {t:8s} {tm.true_positives:4d} {tm.false_positives:4d} {tm.false_negatives:4d} {tm.precision:6.1%} {tm.recall:6.1%} {tm.f1:6.1%}")
    print()

    # ── 2. Baseline Comparison ──────────────────────────────
    print()
    baseline_results = run_baseline_comparison()
    print(format_comparison_table(baseline_results))
    print()

    # ── 3. Ablation Study ───────────────────────────────────
    ablation_results = run_ablation_study()
    print(format_ablation_table(ablation_results))
    print()

    # ── 4. Bootstrap Confidence Intervals ───────────────────
    bootstrap_result = compute_bootstrap_ci(eval_samples, n_iterations=1000)
    print(format_bootstrap_table(bootstrap_result))
    print()

    # ── 5. Error Analysis ───────────────────────────────────
    error_result = run_error_analysis(eval_samples)
    print(format_error_analysis(error_result))
    print()

    # ── 6. Latency Benchmarks ───────────────────────────────
    print("=" * 68)
    print("  6. LATENCY BENCHMARKS")
    print("=" * 68)
    texts = [s.text for s in dataset.samples]
    bench = LatencyBenchmark(include_llm=False)
    b = bench.run(texts)
    print(f"  Total Time:  {b.total_time_ms:.1f}ms")
    print(f"  Throughput:  {b.throughput_samples_per_sec:.0f} samples/sec")
    for name in ["deobfuscation", "regex_extraction", "end_to_end"]:
        if name in b.stages:
            s = b.stages[name]
            print(f"  {s.stage:20s}  mean={s.mean_ms:.3f}ms  p95={s.p95_ms:.3f}ms  p99={s.p99_ms:.3f}ms")
    print("=" * 68)


if __name__ == "__main__":
    main()
