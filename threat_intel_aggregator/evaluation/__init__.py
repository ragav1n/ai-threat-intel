"""
Phase 5: Evaluation Framework.

Provides tools for measuring the accuracy and performance of the
IOC extraction pipeline against labeled ground-truth data.
"""

from threat_intel_aggregator.evaluation.metrics_engine import MetricsEngine, MetricsResult
from threat_intel_aggregator.evaluation.ground_truth import GroundTruthDataset, GroundTruthSample
from threat_intel_aggregator.evaluation.latency_benchmark import LatencyBenchmark, BenchmarkResult
from threat_intel_aggregator.evaluation.evaluator import Evaluator, EvaluationReport

__all__ = [
    "MetricsEngine",
    "MetricsResult",
    "GroundTruthDataset",
    "GroundTruthSample",
    "LatencyBenchmark",
    "BenchmarkResult",
    "Evaluator",
    "EvaluationReport",
]
