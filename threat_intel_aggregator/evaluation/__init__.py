"""
Phase 5: Evaluation Framework.

Provides tools for measuring the accuracy and performance of the
IOC extraction pipeline against labeled ground-truth data.
"""

from threat_intel_aggregator.evaluation.metrics_engine import MetricsEngine, MetricsResult
from threat_intel_aggregator.evaluation.ground_truth import GroundTruthDataset, GroundTruthSample
from threat_intel_aggregator.evaluation.latency_benchmark import LatencyBenchmark, BenchmarkResult
from threat_intel_aggregator.evaluation.evaluator import Evaluator, EvaluationReport
from threat_intel_aggregator.evaluation.baseline_comparison import run_baseline_comparison
from threat_intel_aggregator.evaluation.ablation_study import run_ablation_study
from threat_intel_aggregator.evaluation.bootstrap_ci import compute_bootstrap_ci
from threat_intel_aggregator.evaluation.error_analysis import run_error_analysis

__all__ = [
    "MetricsEngine",
    "MetricsResult",
    "GroundTruthDataset",
    "GroundTruthSample",
    "LatencyBenchmark",
    "BenchmarkResult",
    "Evaluator",
    "EvaluationReport",
    "run_baseline_comparison",
    "run_ablation_study",
    "compute_bootstrap_ci",
    "run_error_analysis",
]

