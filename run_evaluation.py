"""
Run the Phase 5 Evaluation Pipeline.
Usage: python run_evaluation.py
"""
import json
from threat_intel_aggregator.evaluation.ground_truth import GroundTruthDataset
from threat_intel_aggregator.evaluation.metrics_engine import MetricsEngine
from threat_intel_aggregator.evaluation.latency_benchmark import LatencyBenchmark
from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence


def main():
    dataset = GroundTruthDataset()
    print(f"Dataset: {dataset.total_samples} samples, {dataset.total_expected_iocs} expected IOCs")
    print(f"Categories: {json.dumps(dataset.category_counts())}\n")

    # Run extraction on each sample
    eval_samples = []
    for sample in dataset.samples:
        matches = extract_iocs_with_confidence(sample.text, include_private_ips=False, min_confidence=0.0)
        extracted = [{"value": m.value, "type": str(m.ioc_type), "confidence": m.confidence} for m in matches]
        eval_samples.append({
            "expected_iocs": [e.to_dict() for e in sample.expected_iocs],
            "extracted_iocs": extracted,
            "category": sample.category,
        })

    # Compute metrics
    engine = MetricsEngine()
    m = engine.evaluate(eval_samples)

    print("=" * 60)
    print("  EVALUATION RESULTS")
    print("=" * 60)
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
    print(f"  True Positives:     {m.true_positives}")
    print(f"  False Positives:    {m.false_positives}")
    print(f"  False Negatives:    {m.false_negatives}")
    print(f"  True Negatives:     {m.true_negatives}")
    print(f"  Total Expected:     {m.total_expected}")
    print(f"  Total Extracted:    {m.total_extracted}")
    print()

    print("-- CONFIDENCE CALIBRATION --")
    print(f"  Avg TP Confidence: {m.avg_tp_confidence:.4f}")
    print(f"  Avg FP Confidence: {m.avg_fp_confidence:.4f}")
    print()

    print("-- CATEGORY ACCURACY --")
    for cat, acc in sorted(m.category_accuracy.items()):
        print(f"  {cat:20s} {acc*100:.1f}%")
    print()

    print("-- PER-TYPE BREAKDOWN --")
    print(f"  {'Type':8s} {'TP':>4s} {'FP':>4s} {'FN':>4s} {'Prec':>7s} {'Recall':>7s} {'F1':>7s}")
    for t in sorted(m.per_type.keys()):
        tm = m.per_type[t]
        print(f"  {t:8s} {tm.true_positives:4d} {tm.false_positives:4d} {tm.false_negatives:4d} {tm.precision:6.1%} {tm.recall:6.1%} {tm.f1:6.1%}")
    print()

    # Latency benchmark
    print("-- LATENCY BENCHMARKS --")
    texts = [s.text for s in dataset.samples]
    bench = LatencyBenchmark(include_llm=False)
    b = bench.run(texts)
    print(f"  Total Time:  {b.total_time_ms:.1f}ms")
    print(f"  Throughput:  {b.throughput_samples_per_sec:.0f} samples/sec")
    for name in ["deobfuscation", "regex_extraction", "end_to_end"]:
        if name in b.stages:
            s = b.stages[name]
            print(f"  {s.stage:20s}  mean={s.mean_ms:.3f}ms  p95={s.p95_ms:.3f}ms  p99={s.p99_ms:.3f}ms")
    print("=" * 60)


if __name__ == "__main__":
    main()
