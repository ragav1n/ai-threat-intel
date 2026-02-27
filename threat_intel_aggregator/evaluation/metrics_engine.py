"""
Metrics Engine for IOC Extraction Evaluation.

Computes Precision, Recall, F1 Score, per-type breakdowns,
confusion-matrix counts, and confidence calibration statistics
by comparing extracted IOCs against ground-truth labels.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------
# Data structures
# -------------------------------------------------------------------

@dataclass
class TypeMetrics:
    """Precision / Recall / F1 for a single IOC type."""
    ioc_type: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    avg_tp_confidence: float = 0.0
    avg_fp_confidence: float = 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_type": self.ioc_type,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "avg_tp_confidence": round(self.avg_tp_confidence, 4),
            "avg_fp_confidence": round(self.avg_fp_confidence, 4),
        }


@dataclass
class MetricsResult:
    """Aggregate evaluation metrics across all samples."""
    total_samples: int = 0
    total_expected: int = 0
    total_extracted: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0  # samples with no expected & no extracted
    per_type: Dict[str, TypeMetrics] = field(default_factory=dict)
    # confidence calibration
    avg_tp_confidence: float = 0.0
    avg_fp_confidence: float = 0.0
    # per-category accuracy
    category_accuracy: Dict[str, float] = field(default_factory=dict)

    # ── Micro-averaged (same as aggregate) ──────────────────────

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    micro_f1 = f1  # alias

    # ── Macro-averaged (unweighted mean of per-type F1) ─────────

    @property
    def macro_f1(self) -> float:
        if not self.per_type:
            return 0.0
        return sum(tm.f1 for tm in self.per_type.values()) / len(self.per_type)

    @property
    def macro_precision(self) -> float:
        if not self.per_type:
            return 0.0
        return sum(tm.precision for tm in self.per_type.values()) / len(self.per_type)

    @property
    def macro_recall(self) -> float:
        if not self.per_type:
            return 0.0
        return sum(tm.recall for tm in self.per_type.values()) / len(self.per_type)

    # ── Weighted F1 (weighted by support per type) ──────────────

    @property
    def weighted_f1(self) -> float:
        total_support = sum(
            tm.true_positives + tm.false_negatives for tm in self.per_type.values()
        )
        if total_support == 0:
            return 0.0
        return sum(
            tm.f1 * (tm.true_positives + tm.false_negatives)
            for tm in self.per_type.values()
        ) / total_support

    # ── Matthews Correlation Coefficient (MCC) ──────────────────

    @property
    def mcc(self) -> float:
        """
        Matthews Correlation Coefficient — ranges from -1 to +1.
        MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
        Preferred over F1 for imbalanced datasets (Chicco & Jurman, 2020).
        """
        import math
        tp, fp, fn, tn = self.true_positives, self.false_positives, self.false_negatives, self.true_negatives
        denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        return (tp * tn - fp * fn) / denom if denom > 0 else 0.0

    # ── Cohen's Kappa ───────────────────────────────────────────

    @property
    def cohens_kappa(self) -> float:
        """
        Cohen's Kappa — agreement beyond chance between expected and extracted.
        κ = (p_o - p_e) / (1 - p_e)
        """
        n = self.true_positives + self.false_positives + self.false_negatives + self.true_negatives
        if n == 0:
            return 0.0
        p_o = (self.true_positives + self.true_negatives) / n  # observed agreement
        p_pos = ((self.true_positives + self.false_positives) * (self.true_positives + self.false_negatives)) / (n * n)
        p_neg = ((self.true_negatives + self.false_negatives) * (self.true_negatives + self.false_positives)) / (n * n)
        p_e = p_pos + p_neg  # expected agreement by chance
        return (p_o - p_e) / (1 - p_e) if p_e < 1 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "total_expected": self.total_expected,
            "total_extracted": self.total_extracted,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            # Micro-averaged (standard)
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            # Macro-averaged
            "macro_precision": round(self.macro_precision, 4),
            "macro_recall": round(self.macro_recall, 4),
            "macro_f1": round(self.macro_f1, 4),
            # Weighted F1
            "weighted_f1": round(self.weighted_f1, 4),
            # Advanced metrics
            "mcc": round(self.mcc, 4),
            "cohens_kappa": round(self.cohens_kappa, 4),
            # Calibration
            "avg_tp_confidence": round(self.avg_tp_confidence, 4),
            "avg_fp_confidence": round(self.avg_fp_confidence, 4),
            "category_accuracy": {
                k: round(v, 4) for k, v in self.category_accuracy.items()
            },
            "per_type": {k: v.to_dict() for k, v in self.per_type.items()},
        }


# -------------------------------------------------------------------
# Engine
# -------------------------------------------------------------------

@dataclass
class _ExtractedIOC:
    """Lightweight representation of an extracted IOC for comparison."""
    value: str
    ioc_type: str
    confidence: float = 0.0


class MetricsEngine:
    """
    Compare extracted IOCs against a ground-truth label set and
    produce Precision / Recall / F1 metrics with per-type breakdown.
    """

    @staticmethod
    def _normalize(value: str) -> str:
        """Normalise IOC value for comparison (lowercase, strip)."""
        return value.strip().lower()

    @staticmethod
    def _normalize_type(t: str) -> str:
        """Normalise IOC type string."""
        return t.strip().lower()

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        samples: List[Dict[str, Any]],
    ) -> MetricsResult:
        """
        Evaluate extraction results against labelled ground-truth.

        Args:
            samples: list of dicts, each with keys:
                - "expected_iocs": list of {"value": str, "type": str}
                - "extracted_iocs": list of {"value": str, "type": str, "confidence": float}
                - "category": str  (optional, for per-category accuracy)

        Returns:
            MetricsResult with aggregate and per-type metrics.
        """
        result = MetricsResult()
        result.total_samples = len(samples)

        tp_confidences: List[float] = []
        fp_confidences: List[float] = []
        per_type_tp_conf: Dict[str, List[float]] = {}
        per_type_fp_conf: Dict[str, List[float]] = {}

        # per-category correct/total
        cat_correct: Dict[str, int] = {}
        cat_total: Dict[str, int] = {}

        for sample in samples:
            expected_set: Set[Tuple[str, str]] = {
                (self._normalize(e["value"]), self._normalize_type(e["type"]))
                for e in sample.get("expected_iocs", [])
            }
            extracted_list = sample.get("extracted_iocs", [])
            extracted_set: Set[Tuple[str, str]] = set()
            extracted_conf: Dict[Tuple[str, str], float] = {}
            for ex in extracted_list:
                key = (self._normalize(ex["value"]), self._normalize_type(ex["type"]))
                extracted_set.add(key)
                extracted_conf[key] = ex.get("confidence", 0.0)

            result.total_expected += len(expected_set)
            result.total_extracted += len(extracted_set)

            tp = expected_set & extracted_set
            fp = extracted_set - expected_set
            fn = expected_set - extracted_set

            result.true_positives += len(tp)
            result.false_positives += len(fp)
            result.false_negatives += len(fn)

            # True negatives: no expected and no extracted (correct rejection)
            if len(expected_set) == 0 and len(extracted_set) == 0:
                result.true_negatives += 1

            # Confidence tracking
            for key in tp:
                c = extracted_conf.get(key, 0.0)
                tp_confidences.append(c)
                ioc_type = key[1]
                per_type_tp_conf.setdefault(ioc_type, []).append(c)

            for key in fp:
                c = extracted_conf.get(key, 0.0)
                fp_confidences.append(c)
                ioc_type = key[1]
                per_type_fp_conf.setdefault(ioc_type, []).append(c)

            # Per-type TP/FP/FN
            all_types = {k[1] for k in expected_set | extracted_set}
            for t in all_types:
                if t not in result.per_type:
                    result.per_type[t] = TypeMetrics(ioc_type=t)
                tm = result.per_type[t]
                t_expected = {k for k in expected_set if k[1] == t}
                t_extracted = {k for k in extracted_set if k[1] == t}
                tm.true_positives += len(t_expected & t_extracted)
                tm.false_positives += len(t_extracted - t_expected)
                tm.false_negatives += len(t_expected - t_extracted)

            # Per-category accuracy
            category = sample.get("category", "unknown")
            cat_total[category] = cat_total.get(category, 0) + 1
            if len(fp) == 0 and len(fn) == 0:
                cat_correct[category] = cat_correct.get(category, 0) + 1

        # Aggregate confidence stats
        if tp_confidences:
            result.avg_tp_confidence = sum(tp_confidences) / len(tp_confidences)
        if fp_confidences:
            result.avg_fp_confidence = sum(fp_confidences) / len(fp_confidences)

        # Per-type confidence averages
        for t, tm in result.per_type.items():
            confs = per_type_tp_conf.get(t, [])
            tm.avg_tp_confidence = sum(confs) / len(confs) if confs else 0.0
            confs = per_type_fp_conf.get(t, [])
            tm.avg_fp_confidence = sum(confs) / len(confs) if confs else 0.0

        # Category accuracy
        for cat in cat_total:
            result.category_accuracy[cat] = (
                cat_correct.get(cat, 0) / cat_total[cat]
            )

        logger.info(
            f"Evaluation complete: P={result.precision:.3f} R={result.recall:.3f} "
            f"F1={result.f1:.3f} ({result.true_positives} TP, "
            f"{result.false_positives} FP, {result.false_negatives} FN)"
        )

        return result
