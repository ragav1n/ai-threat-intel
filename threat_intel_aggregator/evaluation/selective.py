"""
Selective prediction for IOC extraction (C2, operational layer).

A calibrated confidence score is only worth something when it drives a
decision. Given a set of extracted IOCs, each with a confidence in [0,1] and a
known correctness label, this module turns the scores into a triage policy:
accept (auto-apply) the most-confident IOCs, abstain on the rest and route
them to a human analyst.

  risk_coverage_curve  — error rate among accepted IOCs at every coverage level
  aurc                 — area under that curve; lower means better-ordered
                         confidence (this is calibration-invariant — it depends
                         only on the ranking)
  operating_point      — coverage and achieved risk at a fixed threshold
  target_risk_point    — accept everything the calibrated score rates at or
                         above (1 - target); the achieved risk tracks the
                         target only when the score is calibrated, which is
                         what makes calibration operationally useful

`risk` is the error rate among accepted IOCs (1 - precision); `coverage` is the
fraction of candidate IOCs the pipeline decides automatically rather than
handing to an analyst.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

# (confidence in [0,1], was the IOC correct?) — same shape as calibration.Prediction
Prediction = Tuple[float, bool]


@dataclass
class CoveragePoint:
    """One point on a risk-coverage curve."""
    threshold: float       # min accepted confidence at this point
    coverage: float        # fraction of candidates accepted (auto-applied)
    risk: float            # error rate among accepted (1 - precision)
    n_accepted: int

    def to_dict(self) -> dict:
        return {
            "threshold": round(self.threshold, 6),
            "coverage": round(self.coverage, 6),
            "risk": round(self.risk, 6),
            "n_accepted": self.n_accepted,
        }


def risk_coverage_curve(predictions: Sequence[Prediction]) -> List[CoveragePoint]:
    """Risk at each coverage level, accepting IOCs in descending confidence.

    Each point adds the next-most-confident IOC to the accepted set. Ties in
    confidence are resolved into a single point at the lowest covered index so
    the curve does not claim finer threshold resolution than the scores have.
    """
    preds = sorted(predictions, key=lambda p: p[0], reverse=True)
    n = len(preds)
    points: List[CoveragePoint] = []
    errors = 0
    for i, (conf, correct) in enumerate(preds, start=1):
        if not correct:
            errors += 1
        # Collapse a run of equal confidences into one point: the analyst
        # cannot separate IOCs the score rates identically.
        if i < n and preds[i][0] == conf:
            continue
        points.append(CoveragePoint(
            threshold=conf,
            coverage=i / n,
            risk=errors / i,
            n_accepted=i,
        ))
    return points


def aurc(predictions: Sequence[Prediction]) -> float:
    """Area under the risk-coverage curve (trapezoidal integration).

    Lower is better. It is invariant to any monotone rescaling of the
    confidences, so it measures how well the scores *rank* IOCs, separate from
    whether they are calibrated.
    """
    points = risk_coverage_curve(predictions)
    if not points:
        return 0.0
    area = 0.0
    prev_cov, prev_risk = 0.0, points[0].risk
    for p in points:
        area += (p.coverage - prev_cov) * (p.risk + prev_risk) / 2.0
        prev_cov, prev_risk = p.coverage, p.risk
    return area


def operating_point(predictions: Sequence[Prediction],
                    threshold: float) -> CoveragePoint:
    """Accept every IOC with confidence >= threshold; report coverage and risk."""
    preds = list(predictions)
    n = len(preds)
    accepted = [(c, y) for c, y in preds if c >= threshold]
    k = len(accepted)
    errors = sum(1 for _, y in accepted if not y)
    return CoveragePoint(
        threshold=threshold,
        coverage=k / n if n else 0.0,
        risk=errors / k if k else 0.0,
        n_accepted=k,
    )


def target_risk_point(predictions: Sequence[Prediction],
                      target_risk: float) -> CoveragePoint:
    """Operating point for a target error rate on a *calibrated* score.

    A calibrated confidence estimates P(correct), so accepting everything at or
    above ``1 - target_risk`` should yield an accepted set whose error rate is
    about ``target_risk``. The gap between target and achieved risk is exactly
    what a miscalibrated score gets wrong.
    """
    return operating_point(predictions, threshold=1.0 - target_risk)
