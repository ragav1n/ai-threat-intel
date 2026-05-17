"""Tests for selective prediction (evaluation.selective)."""
from threat_intel_aggregator.evaluation.selective import (
    aurc,
    operating_point,
    risk_coverage_curve,
    target_risk_point,
)


def test_risk_coverage_curve_perfect_ranking():
    # all correct IOCs rank above all incorrect ones
    preds = [(0.9, True), (0.8, True), (0.7, False), (0.6, False)]
    pts = risk_coverage_curve(preds)
    assert [p.n_accepted for p in pts] == [1, 2, 3, 4]
    assert pts[0].risk == 0.0 and pts[1].risk == 0.0   # top-2 accepted: no errors
    assert pts[-1].coverage == 1.0
    assert pts[-1].risk == 0.5                          # 2 of 4 wrong overall


def test_risk_coverage_curve_collapses_ties():
    # two IOCs share confidence 0.9 -> one combined point, not two
    pts = risk_coverage_curve([(0.9, True), (0.9, False), (0.5, True)])
    assert len(pts) == 2
    assert pts[0].n_accepted == 2 and pts[0].risk == 0.5


def test_risk_coverage_curve_empty():
    assert risk_coverage_curve([]) == []
    assert aurc([]) == 0.0


def test_aurc_lower_for_better_ranking():
    good = [(0.9, True), (0.8, True), (0.7, False), (0.6, False)]
    bad = [(0.9, False), (0.8, False), (0.7, True), (0.6, True)]
    assert aurc(good) < aurc(bad)


def test_operating_point_thresholds():
    preds = [(0.9, True), (0.8, False), (0.5, True)]
    op = operating_point(preds, threshold=0.7)
    assert op.n_accepted == 2          # 0.9 and 0.8 accepted
    assert op.coverage == 2 / 3
    assert op.risk == 0.5              # one of the two accepted is wrong


def test_operating_point_accept_none():
    op = operating_point([(0.4, True), (0.3, False)], threshold=0.9)
    assert op.n_accepted == 0
    assert op.coverage == 0.0 and op.risk == 0.0


def test_target_risk_point_uses_complement_threshold():
    preds = [(0.95, True), (0.92, True), (0.5, False)]
    op = target_risk_point(preds, target_risk=0.1)   # threshold 0.9
    assert op.threshold == 0.9
    assert op.n_accepted == 2
