"""
Phase 5 Tests: Evaluation Framework.

Rigorous test suite covering:
  1.  Ground-Truth Dataset — structure, loading, filtering, category counts
  2.  Metrics Engine — perfect score, zero recall, partial matches, per-type, edge cases
  3.  Latency Benchmark — timer correctness, stat calculation, throughput
  4.  Evaluator — full pipeline integration, report structure
  5.  Edge Cases — empty input, obfuscated IOCs, confidence calibration
"""

import json
import time
import math
import pytest
from pathlib import Path
from typing import List, Dict, Any

# ============================================================
# Test 1: Ground-Truth Dataset
# ============================================================

from threat_intel_aggregator.evaluation.ground_truth import (
    GroundTruthDataset,
    GroundTruthSample,
    ExpectedIOC,
)


class TestGroundTruthDataset:
    """Tests for the ground-truth labeled dataset."""

    def setup_method(self):
        self.dataset = GroundTruthDataset()

    def test_dataset_not_empty(self):
        """Dataset must contain samples."""
        assert self.dataset.total_samples > 0

    def test_minimum_sample_count(self):
        """Must have at least 100 samples for statistical significance."""
        assert self.dataset.total_samples >= 100, (
            f"Expected ≥100 samples, got {self.dataset.total_samples}"
        )

    def test_has_all_categories(self):
        """Must contain all four sample categories."""
        counts = self.dataset.category_counts()
        for cat in ["true_positive", "true_negative", "obfuscated", "edge_case"]:
            assert cat in counts, f"Missing category: {cat}"
            assert counts[cat] >= 3, f"Category '{cat}' has fewer than 3 samples"

    def test_has_all_ioc_types(self):
        """Expected IOCs must span all major types."""
        type_counts = self.dataset.ioc_type_counts()
        for ioc_type in ["ip", "domain", "url", "md5", "sha1", "sha256", "cve", "email"]:
            assert ioc_type in type_counts, f"No expected IOCs of type '{ioc_type}'"
            assert type_counts[ioc_type] >= 2, f"Type '{ioc_type}' has < 2 expected IOCs"

    def test_true_negatives_have_no_iocs(self):
        """True negative samples must have zero expected IOCs."""
        for sample in self.dataset.filter_by_category("true_negative"):
            assert len(sample.expected_iocs) == 0, (
                f"True negative '{sample.id}' has {len(sample.expected_iocs)} expected IOCs"
            )

    def test_true_positives_have_iocs(self):
        """True positive samples must have at least one expected IOC."""
        for sample in self.dataset.filter_by_category("true_positive"):
            assert len(sample.expected_iocs) >= 1, (
                f"True positive '{sample.id}' has no expected IOCs"
            )

    def test_sample_ids_unique(self):
        """All sample IDs must be unique."""
        ids = [s.id for s in self.dataset.samples]
        assert len(ids) == len(set(ids)), "Duplicate sample IDs detected"

    def test_filter_by_ioc_type(self):
        """Filtering by IOC type returns relevant samples only."""
        ip_samples = self.dataset.filter_by_ioc_type("ip")
        assert len(ip_samples) > 0
        for sample in ip_samples:
            types = [e.type for e in sample.expected_iocs]
            assert "ip" in types

    def test_filter_by_tag(self):
        """Filtering by tag returns relevant samples."""
        malware_samples = self.dataset.filter_by_tag("malware")
        for sample in malware_samples:
            assert "malware" in sample.tags

    def test_serialization_roundtrip(self, tmp_path: Path):
        """Save and load produces identical data."""
        path = tmp_path / "gt.json"
        self.dataset.save(path)
        loaded = GroundTruthDataset.load(path)
        assert loaded.total_samples == self.dataset.total_samples
        assert loaded.total_expected_iocs == self.dataset.total_expected_iocs
        # Verify first and last sample
        assert loaded.samples[0].id == self.dataset.samples[0].id
        assert loaded.samples[-1].id == self.dataset.samples[-1].id

    def test_summary_structure(self):
        """Summary must contain all expected keys."""
        summary = self.dataset.summary()
        assert "total_samples" in summary
        assert "total_expected_iocs" in summary
        assert "category_counts" in summary
        assert "ioc_type_counts" in summary

    def test_expected_ioc_values_not_empty(self):
        """Expected IOC values must not be empty strings."""
        for sample in self.dataset.samples:
            for ioc in sample.expected_iocs:
                assert ioc.value.strip() != "", f"Empty IOC value in '{sample.id}'"
                assert ioc.type.strip() != "", f"Empty IOC type in '{sample.id}'"


# ============================================================
# Test 2: Metrics Engine
# ============================================================

from threat_intel_aggregator.evaluation.metrics_engine import (
    MetricsEngine,
    MetricsResult,
    TypeMetrics,
)


class TestMetricsEngine:
    """Tests for the metrics computation engine."""

    def setup_method(self):
        self.engine = MetricsEngine()

    def test_perfect_extraction(self):
        """Perfect extraction should produce P=1, R=1, F1=1."""
        samples = [
            {
                "expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
                "extracted_iocs": [{"value": "1.2.3.4", "type": "ip", "confidence": 0.9}],
                "category": "true_positive",
            },
            {
                "expected_iocs": [{"value": "evil.com", "type": "domain"}],
                "extracted_iocs": [{"value": "evil.com", "type": "domain", "confidence": 0.8}],
                "category": "true_positive",
            },
        ]
        result = self.engine.evaluate(samples)
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.f1 == 1.0
        assert result.true_positives == 2
        assert result.false_positives == 0
        assert result.false_negatives == 0

    def test_zero_extraction(self):
        """No extraction should produce P=0, R=0, F1=0."""
        samples = [
            {
                "expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
                "extracted_iocs": [],
                "category": "true_positive",
            }
        ]
        result = self.engine.evaluate(samples)
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.f1 == 0.0
        assert result.false_negatives == 1

    def test_all_false_positives(self):
        """Extracting only wrong IOCs should produce P=0, R=0."""
        samples = [
            {
                "expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
                "extracted_iocs": [
                    {"value": "5.6.7.8", "type": "ip", "confidence": 0.7},
                ],
                "category": "true_positive",
            }
        ]
        result = self.engine.evaluate(samples)
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.false_positives == 1
        assert result.false_negatives == 1

    def test_partial_match(self):
        """Partial match: 1 TP + 1 FN → P=1.0, R=0.5."""
        samples = [
            {
                "expected_iocs": [
                    {"value": "1.2.3.4", "type": "ip"},
                    {"value": "evil.com", "type": "domain"},
                ],
                "extracted_iocs": [
                    {"value": "1.2.3.4", "type": "ip", "confidence": 0.8},
                ],
                "category": "true_positive",
            }
        ]
        result = self.engine.evaluate(samples)
        assert result.true_positives == 1
        assert result.false_negatives == 1
        assert result.precision == 1.0
        assert result.recall == 0.5

    def test_per_type_breakdown(self):
        """Per-type metrics should be computed for each IOC type."""
        samples = [
            {
                "expected_iocs": [
                    {"value": "1.2.3.4", "type": "ip"},
                    {"value": "evil.com", "type": "domain"},
                ],
                "extracted_iocs": [
                    {"value": "1.2.3.4", "type": "ip", "confidence": 0.9},
                    {"value": "evil.com", "type": "domain", "confidence": 0.7},
                    {"value": "5.6.7.8", "type": "ip", "confidence": 0.5},
                ],
                "category": "true_positive",
            }
        ]
        result = self.engine.evaluate(samples)
        assert "ip" in result.per_type
        assert "domain" in result.per_type
        ip_m = result.per_type["ip"]
        assert ip_m.true_positives == 1
        assert ip_m.false_positives == 1
        assert ip_m.precision == 0.5
        assert ip_m.recall == 1.0
        dom_m = result.per_type["domain"]
        assert dom_m.true_positives == 1
        assert dom_m.false_positives == 0
        assert dom_m.precision == 1.0

    def test_confidence_calibration(self):
        """TP and FP confidence averages should be computed."""
        samples = [
            {
                "expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
                "extracted_iocs": [
                    {"value": "1.2.3.4", "type": "ip", "confidence": 0.9},  # TP
                    {"value": "5.6.7.8", "type": "ip", "confidence": 0.3},  # FP
                ],
                "category": "true_positive",
            }
        ]
        result = self.engine.evaluate(samples)
        assert result.avg_tp_confidence == pytest.approx(0.9, abs=0.01)
        assert result.avg_fp_confidence == pytest.approx(0.3, abs=0.01)

    def test_case_insensitive_matching(self):
        """IOC values should be compared case-insensitively."""
        samples = [
            {
                "expected_iocs": [{"value": "Evil.COM", "type": "domain"}],
                "extracted_iocs": [{"value": "evil.com", "type": "domain", "confidence": 0.8}],
                "category": "true_positive",
            }
        ]
        result = self.engine.evaluate(samples)
        assert result.true_positives == 1
        assert result.false_positives == 0

    def test_empty_samples_list(self):
        """Empty input should return zeroed metrics."""
        result = self.engine.evaluate([])
        assert result.total_samples == 0
        assert result.f1 == 0.0

    def test_true_negative_perfect(self):
        """True negatives: no expected IOCs and no extracted IOCs → perfect."""
        samples = [
            {
                "expected_iocs": [],
                "extracted_iocs": [],
                "category": "true_negative",
            }
        ]
        result = self.engine.evaluate(samples)
        assert result.true_positives == 0
        assert result.false_positives == 0
        assert result.false_negatives == 0
        assert result.category_accuracy["true_negative"] == 1.0

    def test_true_negative_with_fp(self):
        """True negative with extracted IOCs → false positive, 0% accuracy."""
        samples = [
            {
                "expected_iocs": [],
                "extracted_iocs": [
                    {"value": "1.2.3.4", "type": "ip", "confidence": 0.5},
                ],
                "category": "true_negative",
            }
        ]
        result = self.engine.evaluate(samples)
        assert result.false_positives == 1
        assert result.category_accuracy["true_negative"] == 0.0

    def test_category_accuracy(self):
        """Category accuracy should reflect per-category correctness."""
        samples = [
            {
                "expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
                "extracted_iocs": [{"value": "1.2.3.4", "type": "ip", "confidence": 0.9}],
                "category": "true_positive",
            },
            {
                "expected_iocs": [{"value": "evil.com", "type": "domain"}],
                "extracted_iocs": [],
                "category": "true_positive",
            },
        ]
        result = self.engine.evaluate(samples)
        assert result.category_accuracy["true_positive"] == 0.5

    def test_to_dict_structure(self):
        """MetricsResult.to_dict() should return a well-structured dict."""
        samples = [
            {
                "expected_iocs": [{"value": "x", "type": "ip"}],
                "extracted_iocs": [{"value": "x", "type": "ip", "confidence": 0.8}],
                "category": "tp",
            }
        ]
        result = self.engine.evaluate(samples)
        d = result.to_dict()
        assert "precision" in d
        assert "recall" in d
        assert "f1" in d
        assert "per_type" in d
        assert "ip" in d["per_type"]

    def test_f1_math_correctness(self):
        """F1 should be 2*P*R / (P+R)."""
        # 2 TP, 1 FP, 1 FN → P = 2/3, R = 2/3, F1 = 2/3
        samples = [
            {
                "expected_iocs": [
                    {"value": "1.2.3.4", "type": "ip"},
                    {"value": "5.6.7.8", "type": "ip"},
                    {"value": "9.10.11.12", "type": "ip"},
                ],
                "extracted_iocs": [
                    {"value": "1.2.3.4", "type": "ip", "confidence": 0.9},
                    {"value": "5.6.7.8", "type": "ip", "confidence": 0.8},
                    {"value": "99.99.99.99", "type": "ip", "confidence": 0.5},
                ],
                "category": "true_positive",
            }
        ]
        result = self.engine.evaluate(samples)
        expected_p = 2 / 3
        expected_r = 2 / 3
        expected_f1 = 2 * expected_p * expected_r / (expected_p + expected_r)
        assert result.precision == pytest.approx(expected_p, abs=0.001)
        assert result.recall == pytest.approx(expected_r, abs=0.001)
        assert result.f1 == pytest.approx(expected_f1, abs=0.001)

    def test_macro_f1(self):
        """Macro F1 should be the unweighted avg of per-type F1."""
        samples = [
            {
                "expected_iocs": [
                    {"value": "1.2.3.4", "type": "ip"},
                    {"value": "evil.com", "type": "domain"},
                ],
                "extracted_iocs": [
                    {"value": "1.2.3.4", "type": "ip", "confidence": 0.9},
                    # domain missed (FN)
                ],
                "category": "true_positive",
            }
        ]
        result = self.engine.evaluate(samples)
        # IP: P=1.0 R=1.0 F1=1.0; Domain: P=0 R=0 F1=0
        assert result.macro_f1 == pytest.approx(0.5, abs=0.01)

    def test_weighted_f1(self):
        """Weighted F1 should weight per-type F1 by support."""
        samples = [
            {
                "expected_iocs": [
                    {"value": "1.2.3.4", "type": "ip"},
                    {"value": "evil.com", "type": "domain"},
                ],
                "extracted_iocs": [
                    {"value": "1.2.3.4", "type": "ip", "confidence": 0.9},
                ],
                "category": "true_positive",
            }
        ]
        result = self.engine.evaluate(samples)
        # Each type has 1 expected (support=1), so weighted = macro
        assert result.weighted_f1 == pytest.approx(result.macro_f1, abs=0.01)

    def test_mcc_perfect(self):
        """MCC should be 1.0 with perfect results."""
        samples = [
            {
                "expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
                "extracted_iocs": [{"value": "1.2.3.4", "type": "ip", "confidence": 0.9}],
                "category": "true_positive",
            },
            {
                "expected_iocs": [],
                "extracted_iocs": [],
                "category": "true_negative",
            },
        ]
        result = self.engine.evaluate(samples)
        assert result.mcc == pytest.approx(1.0, abs=0.01)

    def test_cohens_kappa_perfect(self):
        """Cohen's kappa should be 1.0 with perfect agreement."""
        samples = [
            {
                "expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
                "extracted_iocs": [{"value": "1.2.3.4", "type": "ip", "confidence": 0.9}],
                "category": "true_positive",
            },
            {
                "expected_iocs": [],
                "extracted_iocs": [],
                "category": "true_negative",
            },
        ]
        result = self.engine.evaluate(samples)
        assert result.cohens_kappa == pytest.approx(1.0, abs=0.01)

    def test_true_negatives_counted(self):
        """TN count should track samples with zero expected and zero extracted."""
        samples = [
            {"expected_iocs": [], "extracted_iocs": [], "category": "tn"},
            {"expected_iocs": [], "extracted_iocs": [], "category": "tn"},
            {"expected_iocs": [{"value": "x", "type": "ip"}],
             "extracted_iocs": [{"value": "x", "type": "ip", "confidence": 0.8}],
             "category": "tp"},
        ]
        result = self.engine.evaluate(samples)
        assert result.true_negatives == 2

    def test_to_dict_has_new_metrics(self):
        """to_dict should include macro_f1, weighted_f1, mcc, cohens_kappa."""
        samples = [
            {
                "expected_iocs": [{"value": "x", "type": "ip"}],
                "extracted_iocs": [{"value": "x", "type": "ip", "confidence": 0.8}],
                "category": "tp",
            }
        ]
        result = self.engine.evaluate(samples)
        d = result.to_dict()
        assert "macro_f1" in d
        assert "weighted_f1" in d
        assert "mcc" in d
        assert "cohens_kappa" in d
        assert "true_negatives" in d


# ============================================================
# Test 3: Latency Benchmark
# ============================================================

from threat_intel_aggregator.evaluation.latency_benchmark import (
    LatencyBenchmark,
    BenchmarkResult,
    TimingStats,
    _compute_stats,
)


class TestLatencyBenchmark:
    """Tests for the latency benchmarking module."""

    def test_compute_stats_basic(self):
        """Stats should be computed correctly from measurements."""
        timings = [1.0, 2.0, 3.0, 4.0, 5.0]
        stats = _compute_stats("test", timings)
        assert stats.stage == "test"
        assert stats.count == 5
        assert stats.min_ms == 1.0
        assert stats.max_ms == 5.0
        assert stats.mean_ms == pytest.approx(3.0, abs=0.01)
        assert stats.median_ms == pytest.approx(3.0, abs=0.01)
        assert stats.total_ms == pytest.approx(15.0, abs=0.01)

    def test_compute_stats_empty(self):
        """Empty timings should return zeroed stats."""
        stats = _compute_stats("empty", [])
        assert stats.count == 0
        assert stats.mean_ms == 0.0

    def test_compute_stats_single_value(self):
        """Single measurement should have min == max == mean."""
        stats = _compute_stats("single", [5.5])
        assert stats.min_ms == 5.5
        assert stats.max_ms == 5.5
        assert stats.mean_ms == 5.5
        assert stats.std_dev_ms == 0.0

    def test_compute_stats_percentiles(self):
        """P95 and P99 should be computed from sorted values."""
        timings = list(range(1, 101))  # 1..100
        stats = _compute_stats("pct", [float(x) for x in timings])
        assert stats.p95_ms == pytest.approx(96.0, abs=1.0)
        assert stats.p99_ms == pytest.approx(100.0, abs=1.0)

    def test_benchmark_run_returns_result(self):
        """Benchmark.run() should return a BenchmarkResult."""
        benchmark = LatencyBenchmark(include_llm=False)
        texts = [
            "Malware connects to 185.220.101.34 for C2.",
            "Clean text with no indicators.",
            "Check hxxp://evil[.]com/payload for more info.",
        ]
        result = benchmark.run(texts)
        assert isinstance(result, BenchmarkResult)
        assert result.total_samples == 3
        assert result.total_time_ms > 0
        assert result.throughput_samples_per_sec > 0

    def test_benchmark_has_all_stages(self):
        """Benchmark must produce deobfuscation, regex, and end-to-end stages."""
        benchmark = LatencyBenchmark(include_llm=False)
        result = benchmark.run(["Test text with 1.2.3.4 IP."])
        assert "deobfuscation" in result.stages
        assert "regex_extraction" in result.stages
        assert "end_to_end" in result.stages

    def test_benchmark_to_dict(self):
        """BenchmarkResult.to_dict() should be JSON-serializable."""
        benchmark = LatencyBenchmark(include_llm=False)
        result = benchmark.run(["Test"])
        d = result.to_dict()
        serialized = json.dumps(d)  # Should not raise
        assert "stages" in d
        assert "throughput_samples_per_sec" in d

    def test_benchmark_on_empty_input(self):
        """Running benchmark on empty list should not crash."""
        benchmark = LatencyBenchmark(include_llm=False)
        result = benchmark.run([])
        assert result.total_samples == 0


# ============================================================
# Test 4: Evaluator (Integration)
# ============================================================

from threat_intel_aggregator.evaluation.evaluator import (
    Evaluator,
    EvaluationReport,
)


class TestEvaluator:
    """Integration tests for the evaluation orchestrator."""

    def test_evaluator_runs_against_dataset(self):
        """Evaluator.run() should complete and produce a report."""
        evaluator = Evaluator(min_confidence=0.0)
        report = evaluator.run(run_benchmark=False)
        assert isinstance(report, EvaluationReport)
        assert report.report_id.startswith("eval_")
        assert report.timestamp.endswith("Z")
        assert report.metrics is not None

    def test_evaluator_metrics_reasonable(self):
        """Metrics should be within [0, 1]."""
        evaluator = Evaluator(min_confidence=0.0)
        report = evaluator.run(run_benchmark=False)
        m = report.metrics
        assert 0.0 <= m.precision <= 1.0
        assert 0.0 <= m.recall <= 1.0
        assert 0.0 <= m.f1 <= 1.0

    def test_evaluator_with_benchmark(self):
        """Evaluator.run(run_benchmark=True) should include benchmark data."""
        evaluator = Evaluator(min_confidence=0.0)
        report = evaluator.run(run_benchmark=True)
        assert report.benchmark is not None
        assert report.benchmark.total_samples > 0
        assert report.benchmark.throughput_samples_per_sec > 0

    def test_evaluator_report_to_dict(self):
        """EvaluationReport serialisation should be JSON-ready."""
        evaluator = Evaluator(min_confidence=0.0)
        report = evaluator.run(run_benchmark=True)
        d = report.to_dict()
        serialized = json.dumps(d)  # Should not raise
        assert "metrics" in d
        assert "benchmark" in d
        assert "dataset_summary" in d

    def test_evaluator_dataset_summary(self):
        """Report should include a dataset summary."""
        evaluator = Evaluator()
        report = evaluator.run(run_benchmark=False)
        s = report.dataset_summary
        assert s["total_samples"] > 0
        assert s["total_expected_iocs"] > 0

    def test_evaluator_nonzero_tp(self):
        """Evaluator should find at least some true positives from known samples."""
        evaluator = Evaluator(min_confidence=0.0)
        report = evaluator.run(run_benchmark=False)
        assert report.metrics.true_positives > 0, (
            "Evaluator found zero true positives — extraction is broken"
        )

    def test_evaluator_min_confidence_filter(self):
        """Higher min_confidence should not increase true positives."""
        eval_lax = Evaluator(min_confidence=0.0)
        eval_strict = Evaluator(min_confidence=0.5)
        report_lax = eval_lax.run(run_benchmark=False)
        report_strict = eval_strict.run(run_benchmark=False)
        assert report_strict.metrics.true_positives <= report_lax.metrics.true_positives


# ============================================================
# Test 5: End-to-End Edge Cases
# ============================================================

class TestEdgeCases:
    """Edge case tests for the evaluation pipeline."""

    def test_extraction_on_empty_text(self):
        """Empty text should produce no IOCs."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        result = extract_iocs_with_confidence("")
        assert len(result) == 0

    def test_extraction_on_whitespace(self):
        """Whitespace-only text should produce no IOCs."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        result = extract_iocs_with_confidence("   \n\t\n   ")
        assert len(result) == 0

    def test_obfuscated_url_extraction(self):
        """Deobfuscated URLs should be extractable."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = "C2 at hxxp://malware-c2[.]ru/beacon"
        matches = extract_iocs_with_confidence(text)
        values = [m.value for m in matches]
        # Should extract the deobfuscated URL
        assert any("malware-c2.ru" in v for v in values)

    def test_obfuscated_domain_extraction(self):
        """Defanged domains should be extracted after deobfuscation."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = "The dropper contacts evil-domain[.]xyz for payload."
        matches = extract_iocs_with_confidence(text)
        values = [m.value for m in matches]
        assert "evil-domain.xyz" in values

    def test_private_ip_filtering(self):
        """Private IPs should be filtered out by default."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = "Internal server at 192.168.1.100 processes data."
        matches = extract_iocs_with_confidence(text, include_private_ips=False)
        ip_values = [m.value for m in matches if str(m.ioc_type) == "ip"]
        assert "192.168.1.100" not in ip_values

    def test_documentation_ip_not_filtered(self):
        """RFC 5737 documentation IPs should NOT be filtered as private."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = "The staging server is at 203.0.113.50 used by the APT group."
        matches = extract_iocs_with_confidence(text, include_private_ips=False)
        ip_values = [m.value for m in matches if str(m.ioc_type) == "ip"]
        assert "203.0.113.50" in ip_values

    def test_file_extension_not_extracted_as_domain(self):
        """File names like payload.exe should NOT be extracted as domains."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = "The malware downloads payload.exe and stage2.zip to disk."
        matches = extract_iocs_with_confidence(text)
        domain_values = [m.value for m in matches if str(m.ioc_type) == "domain"]
        assert "payload.exe" not in domain_values
        assert "stage2.zip" not in domain_values

    def test_ftp_url_extraction(self):
        """ftp:// URLs should now be extracted."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = "Exfiltration via ftp://data-exfil.cc/stolen.rar was observed."
        matches = extract_iocs_with_confidence(text)
        url_values = [m.value for m in matches if str(m.ioc_type) == "url"]
        assert any("ftp://data-exfil.cc" in v for v in url_values)

    def test_domain_in_url_deduped(self):
        """Domains inside URLs should be suppressed (URL is the more specific IOC)."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = "Payload at http://evil-payload.top/malware.exe was analysed."
        matches = extract_iocs_with_confidence(text)
        types = {str(m.ioc_type): m.value for m in matches}
        assert "url" in types  # URL should be extracted
        domain_values = [m.value for m in matches if str(m.ioc_type) == "domain"]
        assert "evil-payload.top" not in domain_values  # domain deduped

    def test_blacklisted_domain_filtering(self):
        """Blacklisted domains (google.com, etc.) should be filtered."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = "Visit google.com for more information."
        matches = extract_iocs_with_confidence(text)
        domain_values = [m.value for m in matches if str(m.ioc_type) == "domain"]
        assert "google.com" not in domain_values

    def test_cve_extraction(self):
        """CVEs should be extracted with high confidence."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = "The exploit targets CVE-2024-21762 for initial access."
        matches = extract_iocs_with_confidence(text)
        cve_matches = [m for m in matches if str(m.ioc_type) == "cve"]
        assert len(cve_matches) >= 1
        assert cve_matches[0].value == "CVE-2024-21762"
        assert cve_matches[0].confidence >= 0.85

    def test_multiple_iocs_in_single_text(self):
        """Multiple IOC types in one text should all be extracted."""
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        text = (
            "Indicators: IP 185.220.101.34, domain evil-c2.ru, "
            "hash d41d8cd98f00b204e9800998ecf8427e, CVE-2024-21762."
        )
        matches = extract_iocs_with_confidence(text)
        types_found = {str(m.ioc_type) for m in matches}
        assert "ip" in types_found
        assert "domain" in types_found
        assert "md5" in types_found
        assert "cve" in types_found

    def test_type_metrics_properties(self):
        """TypeMetrics P/R/F1 properties should compute correctly."""
        tm = TypeMetrics(ioc_type="ip", true_positives=8, false_positives=2, false_negatives=2)
        assert tm.precision == pytest.approx(0.8, abs=0.001)
        assert tm.recall == pytest.approx(0.8, abs=0.001)
        assert tm.f1 == pytest.approx(0.8, abs=0.001)

    def test_type_metrics_zero_division(self):
        """TypeMetrics with zeros should not raise."""
        tm = TypeMetrics(ioc_type="ip")
        assert tm.precision == 0.0
        assert tm.recall == 0.0
        assert tm.f1 == 0.0

    def test_metrics_result_properties(self):
        """MetricsResult aggregate P/R/F1 properties."""
        mr = MetricsResult(true_positives=10, false_positives=5, false_negatives=5)
        assert mr.precision == pytest.approx(10 / 15, abs=0.001)
        assert mr.recall == pytest.approx(10 / 15, abs=0.001)


# ============================================================
# Test 6: Ground Truth Sample Data Model
# ============================================================

class TestGroundTruthSampleModel:
    """Tests for the ground-truth sample data model."""

    def test_sample_to_dict(self):
        s = GroundTruthSample(
            id="test_001",
            text="test text",
            expected_iocs=[ExpectedIOC("1.2.3.4", "ip")],
            category="true_positive",
            tags=["test"],
        )
        d = s.to_dict()
        assert d["id"] == "test_001"
        assert len(d["expected_iocs"]) == 1
        assert d["expected_iocs"][0]["value"] == "1.2.3.4"

    def test_sample_from_dict(self):
        d = {
            "id": "test_002",
            "text": "some text",
            "expected_iocs": [{"value": "evil.com", "type": "domain"}],
            "category": "true_positive",
            "tags": ["domain"],
        }
        s = GroundTruthSample.from_dict(d)
        assert s.id == "test_002"
        assert len(s.expected_iocs) == 1
        assert s.expected_iocs[0].type == "domain"

    def test_expected_ioc_to_dict(self):
        e = ExpectedIOC("evil.com", "domain")
        d = e.to_dict()
        assert d == {"value": "evil.com", "type": "domain"}


# ============================================================
# Test 7: Baseline Comparison
# ============================================================

from threat_intel_aggregator.evaluation.baseline_comparison import (
    run_baseline_comparison,
    format_comparison_table,
    BaselineResult,
    _extract_with_iocextract,
)


class TestBaselineComparison:
    """Tests for the baseline comparison module."""

    def _make_samples(self):
        return [
            {
                "text": "Malware connects to 185.220.101.34 and CVE-2024-21762",
                "expected_iocs": [
                    {"value": "185.220.101.34", "type": "ip"},
                    {"value": "CVE-2024-21762", "type": "cve"},
                ],
                "category": "true_positive",
            },
            {
                "text": "Clean text with nothing here.",
                "expected_iocs": [],
                "category": "true_negative",
            },
        ]

    def test_run_returns_both_extractors(self):
        """Should return results for both our pipeline and iocextract."""
        results = run_baseline_comparison(self._make_samples())
        assert "our_pipeline" in results
        assert "iocextract" in results

    def test_baseline_result_structure(self):
        """BaselineResult should have P/R/F1 properties."""
        results = run_baseline_comparison(self._make_samples())
        for name, r in results.items():
            assert isinstance(r, BaselineResult)
            assert 0.0 <= r.precision <= 1.0
            assert 0.0 <= r.recall <= 1.0
            assert 0.0 <= r.f1 <= 1.0

    def test_baseline_to_dict(self):
        """to_dict should be JSON-serializable."""
        results = run_baseline_comparison(self._make_samples())
        for r in results.values():
            d = r.to_dict()
            json.dumps(d)  # Should not raise
            assert "precision" in d
            assert "per_type" in d

    def test_format_table(self):
        """format_comparison_table should return a non-empty string."""
        results = run_baseline_comparison(self._make_samples())
        table = format_comparison_table(results)
        assert "BASELINE COMPARISON" in table
        assert len(table) > 100

    def test_iocextract_finds_ips(self):
        """iocextract should at least find IP addresses."""
        extracted = _extract_with_iocextract("Server at 185.220.101.34 is malicious")
        values = {v for v, _ in extracted}
        assert "185.220.101.34" in values


# ============================================================
# Test 8: Ablation Study
# ============================================================

from threat_intel_aggregator.evaluation.ablation_study import (
    run_ablation_study,
    format_ablation_table,
    AblationConfig,
    AblationResult,
    ABLATION_CONFIGS,
)


class TestAblationStudy:
    """Tests for the ablation study module."""

    def _make_samples(self):
        return [
            {
                "text": "The dropper contacts evil-domain[.]xyz for payload delivery.",
                "expected_iocs": [{"value": "evil-domain.xyz", "type": "domain"}],
                "category": "obfuscated",
            },
            {
                "text": "Clean text with nothing.",
                "expected_iocs": [],
                "category": "true_negative",
            },
        ]

    def test_returns_all_configs(self):
        """Should return one result per config."""
        results = run_ablation_study(self._make_samples())
        assert len(results) == len(ABLATION_CONFIGS)

    def test_ablation_result_structure(self):
        """Each result should have valid P/R/F1."""
        results = run_ablation_study(self._make_samples())
        for r in results:
            assert isinstance(r, AblationResult)
            assert 0.0 <= r.precision <= 1.0
            assert 0.0 <= r.recall <= 1.0

    def test_deobfuscation_improves_recall(self):
        """Config B (with deobfuscation) should have >= recall vs Config A (without)."""
        results = run_ablation_study(self._make_samples())
        regex_only = results[0]   # A
        with_deobf = results[1]   # B
        assert with_deobf.recall >= regex_only.recall

    def test_format_table(self):
        """format_ablation_table should return readable output."""
        results = run_ablation_study(self._make_samples())
        table = format_ablation_table(results)
        assert "ABLATION STUDY" in table

    def test_to_dict(self):
        """AblationResult.to_dict should be JSON-serializable."""
        results = run_ablation_study(self._make_samples())
        for r in results:
            d = r.to_dict()
            json.dumps(d)
            assert "config" in d
            assert "f1" in d


# ============================================================
# Test 9: Bootstrap Confidence Intervals
# ============================================================

from threat_intel_aggregator.evaluation.bootstrap_ci import (
    compute_bootstrap_ci,
    format_bootstrap_table,
    BootstrapResult,
    ConfidenceInterval,
)


class TestBootstrapCI:
    """Tests for the bootstrap confidence interval module."""

    def _make_eval_samples(self):
        return [
            {
                "expected_iocs": [{"value": "1.2.3.4", "type": "ip"}],
                "extracted_iocs": [{"value": "1.2.3.4", "type": "ip", "confidence": 0.9}],
            },
            {
                "expected_iocs": [{"value": "evil.com", "type": "domain"}],
                "extracted_iocs": [{"value": "evil.com", "type": "domain", "confidence": 0.8}],
            },
            {"expected_iocs": [], "extracted_iocs": []},
        ]

    def test_returns_bootstrap_result(self):
        """Should return a BootstrapResult."""
        result = compute_bootstrap_ci(self._make_eval_samples(), n_iterations=100)
        assert isinstance(result, BootstrapResult)

    def test_ci_bounds(self):
        """CI lower <= point estimate <= CI upper."""
        result = compute_bootstrap_ci(self._make_eval_samples(), n_iterations=100)
        for ci in [result.precision_ci, result.recall_ci, result.f1_ci]:
            assert ci.ci_lower <= ci.point_estimate <= ci.ci_upper

    def test_perfect_data_tight_ci(self):
        """Perfect data should have tight CI (width near 0)."""
        samples = [
            {
                "expected_iocs": [{"value": f"1.2.3.{i}", "type": "ip"}],
                "extracted_iocs": [{"value": f"1.2.3.{i}", "type": "ip", "confidence": 0.9}],
            }
            for i in range(20)
        ]
        result = compute_bootstrap_ci(samples, n_iterations=500)
        assert result.f1_ci.ci_width < 0.05  # Very tight

    def test_reproducible_with_seed(self):
        """Same seed should produce identical results."""
        s = self._make_eval_samples()
        r1 = compute_bootstrap_ci(s, n_iterations=100, seed=42)
        r2 = compute_bootstrap_ci(s, n_iterations=100, seed=42)
        assert r1.f1_ci.ci_lower == r2.f1_ci.ci_lower
        assert r1.f1_ci.ci_upper == r2.f1_ci.ci_upper

    def test_to_dict(self):
        """to_dict should be JSON-serializable."""
        result = compute_bootstrap_ci(self._make_eval_samples(), n_iterations=50)
        d = result.to_dict()
        json.dumps(d)
        assert "precision" in d
        assert "recall" in d
        assert "f1" in d

    def test_format_table(self):
        """format_bootstrap_table should produce readable output."""
        result = compute_bootstrap_ci(self._make_eval_samples(), n_iterations=50)
        table = format_bootstrap_table(result)
        assert "BOOTSTRAP" in table
        assert "95% CI" in table


# ============================================================
# Test 10: Error Analysis
# ============================================================

from threat_intel_aggregator.evaluation.error_analysis import (
    run_error_analysis,
    format_error_analysis,
    ErrorAnalysisResult,
    ErrorInstance,
)


class TestErrorAnalysis:
    """Tests for the error analysis module."""

    def _make_samples(self):
        return [
            {
                "id": "test_fp",
                "text": "Connect to 185.220.101.34 at evil-phishing.xyz",
                "expected_iocs": [{"value": "185.220.101.34", "type": "ip"}],
                "extracted_iocs": [
                    {"value": "185.220.101.34", "type": "ip", "confidence": 0.9},
                    {"value": "evil-phishing.xyz", "type": "domain", "confidence": 0.7},
                ],
                "category": "true_positive",
            },
            {
                "id": "test_fn",
                "text": "Hidden IOC",
                "expected_iocs": [{"value": "hidden-c2.ru", "type": "domain"}],
                "extracted_iocs": [],
                "category": "true_positive",
            },
        ]

    def test_returns_error_analysis_result(self):
        """Should return an ErrorAnalysisResult."""
        result = run_error_analysis(self._make_samples())
        assert isinstance(result, ErrorAnalysisResult)

    def test_counts_fp_and_fn(self):
        """Should correctly count FPs and FNs."""
        result = run_error_analysis(self._make_samples())
        assert result.total_fp == 1  # evil-phishing.xyz
        assert result.total_fn == 1  # hidden-c2.ru

    def test_categories_populated(self):
        """FP and FN categories should be populated."""
        result = run_error_analysis(self._make_samples())
        assert len(result.fp_categories) > 0
        assert len(result.fn_categories) > 0

    def test_error_instances(self):
        """Individual errors should have all required fields."""
        result = run_error_analysis(self._make_samples())
        for err in result.errors:
            assert isinstance(err, ErrorInstance)
            assert err.sample_id
            assert err.value
            assert err.ioc_type
            assert err.error_type in ("false_positive", "false_negative")
            assert err.category
            assert err.explanation

    def test_to_dict(self):
        """to_dict should be JSON-serializable."""
        result = run_error_analysis(self._make_samples())
        d = result.to_dict()
        json.dumps(d)
        assert "fp_categories" in d
        assert "fn_categories" in d

    def test_format_error_analysis(self):
        """format_error_analysis should produce readable output."""
        result = run_error_analysis(self._make_samples())
        output = format_error_analysis(result)
        assert "ERROR ANALYSIS" in output

