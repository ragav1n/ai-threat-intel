"""
Evaluation Orchestrator.

Ties together:
  1. GroundTruthDataset — labelled samples
  2. IOC extraction pipeline — regex + deobfuscation
  3. MetricsEngine — Precision / Recall / F1
  4. LatencyBenchmark — per-stage timing
  5. MongoDB persistence — stores evaluation reports

Produces an EvaluationReport with all results.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from threat_intel_aggregator.evaluation.ground_truth import GroundTruthDataset
from threat_intel_aggregator.evaluation.metrics_engine import MetricsEngine, MetricsResult
from threat_intel_aggregator.evaluation.latency_benchmark import LatencyBenchmark, BenchmarkResult

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------
# Report data structure
# -------------------------------------------------------------------

@dataclass
class EvaluationReport:
    """Complete evaluation report combining metrics and benchmarks."""
    report_id: str = ""
    timestamp: str = ""
    dataset_summary: Dict[str, Any] = field(default_factory=dict)
    metrics: Optional[MetricsResult] = None
    benchmark: Optional[BenchmarkResult] = None
    pipeline_version: str = "phase5_v1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "pipeline_version": self.pipeline_version,
            "dataset_summary": self.dataset_summary,
            "metrics": self.metrics.to_dict() if self.metrics else None,
            "benchmark": self.benchmark.to_dict() if self.benchmark else None,
        }


# -------------------------------------------------------------------
# Evaluator
# -------------------------------------------------------------------

class Evaluator:
    """
    Orchestrate an evaluation run:

        evaluator = Evaluator()
        report = evaluator.run()
    """

    def __init__(
        self,
        dataset: Optional[GroundTruthDataset] = None,
        include_llm_benchmark: bool = False,
        min_confidence: float = 0.0,
    ):
        self.dataset = dataset or GroundTruthDataset()
        self.include_llm_benchmark = include_llm_benchmark
        self.min_confidence = min_confidence

    # ------------------------------------------------------------------
    # Run extraction against each sample
    # ------------------------------------------------------------------

    def _extract_for_sample(self, text: str) -> List[Dict[str, Any]]:
        """Run the IOC extraction pipeline on a single text sample."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import (
            extract_iocs_with_confidence,
        )
        matches = extract_iocs_with_confidence(
            text,
            include_private_ips=False,
            min_confidence=self.min_confidence,
        )
        return [
            {
                "value": m.value,
                "type": str(m.ioc_type),
                "confidence": m.confidence,
            }
            for m in matches
        ]

    # ------------------------------------------------------------------
    # Full evaluation run
    # ------------------------------------------------------------------

    def run(self, run_benchmark: bool = True) -> EvaluationReport:
        """
        Execute a full evaluation and return the report.

        Args:
            run_benchmark: whether to also run latency benchmarks.

        Returns:
            EvaluationReport with metrics and optional benchmarks.
        """
        now = datetime.now(timezone.utc)
        report = EvaluationReport(
            report_id=f"eval_{now.strftime('%Y%m%d_%H%M%S')}",
            timestamp=now.isoformat() + "Z",
            dataset_summary=self.dataset.summary(),
        )

        # --- Step 1: Run extraction on each sample -----------------------
        eval_samples: List[Dict[str, Any]] = []
        for sample in self.dataset.samples:
            extracted = self._extract_for_sample(sample.text)
            eval_samples.append({
                "expected_iocs": [e.to_dict() for e in sample.expected_iocs],
                "extracted_iocs": extracted,
                "category": sample.category,
            })

        # --- Step 2: Compute metrics via MetricsEngine --------------------
        engine = MetricsEngine()
        report.metrics = engine.evaluate(eval_samples)

        # --- Step 3: Latency benchmark (optional) -------------------------
        if run_benchmark:
            benchmark = LatencyBenchmark(include_llm=self.include_llm_benchmark)
            texts = [s.text for s in self.dataset.samples]
            report.benchmark = benchmark.run(texts)

        logger.info(
            f"Evaluation report {report.report_id}: "
            f"F1={report.metrics.f1:.3f}, "
            f"P={report.metrics.precision:.3f}, "
            f"R={report.metrics.recall:.3f}"
        )

        return report

    # ------------------------------------------------------------------
    # MongoDB persistence
    # ------------------------------------------------------------------

    def save_report(self, report: EvaluationReport) -> str:
        """
        Persist an EvaluationReport to MongoDB.

        Returns:
            The report_id.
        """
        try:
            from threat_intel_aggregator.feed_collection.mongo_writer import get_db
            db = get_db()
            collection = db["evaluations"]
            doc = report.to_dict()
            doc["_id"] = report.report_id
            collection.replace_one(
                {"_id": report.report_id},
                doc,
                upsert=True,
            )
            logger.info(f"Saved evaluation report {report.report_id} to MongoDB")
            return report.report_id
        except Exception as e:
            logger.error(f"Failed to save evaluation report: {e}")
            raise

    @staticmethod
    def load_latest_report() -> Optional[Dict[str, Any]]:
        """Load the most recent evaluation report from MongoDB."""
        try:
            from threat_intel_aggregator.feed_collection.mongo_writer import get_db
            db = get_db()
            collection = db["evaluations"]
            doc = collection.find_one(
                {},
                sort=[("timestamp", -1)],
            )
            if doc:
                doc.pop("_id", None)
            return doc
        except Exception as e:
            logger.error(f"Failed to load evaluation report: {e}")
            return None

    @staticmethod
    def load_report_history(limit: int = 20) -> List[Dict[str, Any]]:
        """Load recent evaluation report summaries from MongoDB."""
        try:
            from threat_intel_aggregator.feed_collection.mongo_writer import get_db
            db = get_db()
            collection = db["evaluations"]
            cursor = collection.find(
                {},
                {
                    "_id": 0,
                    "report_id": 1,
                    "timestamp": 1,
                    "pipeline_version": 1,
                    "metrics.precision": 1,
                    "metrics.recall": 1,
                    "metrics.f1": 1,
                    "metrics.true_positives": 1,
                    "metrics.false_positives": 1,
                    "metrics.false_negatives": 1,
                    "benchmark.total_time_ms": 1,
                    "benchmark.throughput_samples_per_sec": 1,
                },
            ).sort("timestamp", -1).limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Failed to load evaluation history: {e}")
            return []
