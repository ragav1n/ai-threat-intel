"""
Latency Benchmarking for IOC Extraction Pipeline.

Measures per-stage timing:
  - Regex extraction (extract_iocs_with_confidence)
  - Deobfuscation (deobfuscate_text)
  - LLM verification (LLMIOCVerifier.verify_ioc — skipped if Ollama unavailable)
  - End-to-end pipeline
  - Throughput (samples / second)
"""

import time
import logging
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------
# Data structures
# -------------------------------------------------------------------

@dataclass
class TimingStats:
    """Statistical summary for a set of timing measurements."""
    stage: str
    count: int = 0
    total_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    mean_ms: float = 0.0
    median_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    std_dev_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "count": self.count,
            "total_ms": round(self.total_ms, 3),
            "min_ms": round(self.min_ms, 3),
            "max_ms": round(self.max_ms, 3),
            "mean_ms": round(self.mean_ms, 3),
            "median_ms": round(self.median_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "p99_ms": round(self.p99_ms, 3),
            "std_dev_ms": round(self.std_dev_ms, 3),
        }


@dataclass
class BenchmarkResult:
    """Complete benchmark report."""
    total_samples: int = 0
    total_time_ms: float = 0.0
    throughput_samples_per_sec: float = 0.0
    stages: Dict[str, TimingStats] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "total_time_ms": round(self.total_time_ms, 3),
            "throughput_samples_per_sec": round(self.throughput_samples_per_sec, 3),
            "stages": {k: v.to_dict() for k, v in self.stages.items()},
        }


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _compute_stats(stage: str, timings_ms: List[float]) -> TimingStats:
    """Compute descriptive statistics from a list of timing measurements."""
    if not timings_ms:
        return TimingStats(stage=stage)

    sorted_times = sorted(timings_ms)
    n = len(sorted_times)

    return TimingStats(
        stage=stage,
        count=n,
        total_ms=sum(sorted_times),
        min_ms=sorted_times[0],
        max_ms=sorted_times[-1],
        mean_ms=statistics.mean(sorted_times),
        median_ms=statistics.median(sorted_times),
        p95_ms=sorted_times[int(n * 0.95)] if n > 1 else sorted_times[0],
        p99_ms=sorted_times[int(n * 0.99)] if n > 1 else sorted_times[0],
        std_dev_ms=statistics.stdev(sorted_times) if n > 1 else 0.0,
    )


# -------------------------------------------------------------------
# Benchmark runner
# -------------------------------------------------------------------

class LatencyBenchmark:
    """
    Run latency benchmarks against the IOC extraction pipeline.

    Usage:
        benchmark = LatencyBenchmark()
        result = benchmark.run(texts)
    """

    def __init__(self, include_llm: bool = False, llm_model: str = "qwen2.5:7b"):
        self.include_llm = include_llm
        self.llm_model = llm_model

    def run(self, texts: List[str]) -> BenchmarkResult:
        """
        Benchmark the extraction pipeline on a list of text samples.

        Args:
            texts: list of raw text strings to extract IOCs from.

        Returns:
            BenchmarkResult with per-stage timing stats.
        """
        from threat_intel_aggregator.feed_collection.ioc_deobfuscator import deobfuscate_text
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence

        deobfuscation_times: List[float] = []
        extraction_times: List[float] = []
        end_to_end_times: List[float] = []
        llm_times: List[float] = []

        overall_start = time.perf_counter()

        for text in texts:
            sample_start = time.perf_counter()

            # Stage 1: Deobfuscation
            t0 = time.perf_counter()
            deob_text, _ = deobfuscate_text(text)
            t1 = time.perf_counter()
            deobfuscation_times.append((t1 - t0) * 1000)

            # Stage 2: Regex extraction
            t0 = time.perf_counter()
            matches = extract_iocs_with_confidence(text)
            t1 = time.perf_counter()
            extraction_times.append((t1 - t0) * 1000)

            # Stage 3: LLM verification (optional)
            if self.include_llm and matches:
                try:
                    from threat_intel_aggregator.feed_collection.llm_ioc_verifier import (
                        LLMIOCVerifier,
                    )
                    verifier = LLMIOCVerifier(model=self.llm_model)
                    if verifier.is_available():
                        first_match = matches[0]
                        t0 = time.perf_counter()
                        verifier.verify_ioc(
                            first_match.value,
                            str(first_match.ioc_type),
                            first_match.context_snippet,
                        )
                        t1 = time.perf_counter()
                        llm_times.append((t1 - t0) * 1000)
                except Exception as e:
                    logger.warning(f"LLM benchmark skipped: {e}")

            sample_end = time.perf_counter()
            end_to_end_times.append((sample_end - sample_start) * 1000)

        overall_end = time.perf_counter()
        total_time_ms = (overall_end - overall_start) * 1000
        n = len(texts)

        result = BenchmarkResult(
            total_samples=n,
            total_time_ms=total_time_ms,
            throughput_samples_per_sec=(n / (total_time_ms / 1000)) if total_time_ms > 0 else 0.0,
        )

        result.stages["deobfuscation"] = _compute_stats("deobfuscation", deobfuscation_times)
        result.stages["regex_extraction"] = _compute_stats("regex_extraction", extraction_times)
        result.stages["end_to_end"] = _compute_stats("end_to_end", end_to_end_times)

        if llm_times:
            result.stages["llm_verification"] = _compute_stats("llm_verification", llm_times)

        logger.info(
            f"Benchmark complete: {n} samples in {total_time_ms:.1f}ms "
            f"({result.throughput_samples_per_sec:.1f} samples/sec)"
        )

        return result
