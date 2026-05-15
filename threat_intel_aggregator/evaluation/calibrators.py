"""
Post-hoc Confidence Calibrators for IOC Extraction (research-paper C2).

Given a stream of (confidence, correct) observations, these calibrators learn a
mapping that makes the confidence score match the empirical accuracy. Two
standard methods are provided:

  TemperatureScaler  — parametric: rescales the confidence logit by a single
                       learned temperature T (Guo et al., 2017). T > 1 softens
                       overconfident scores; T < 1 sharpens underconfident ones.
  IsotonicCalibrator — non-parametric: fits a monotone step function via the
                       Pool-Adjacent-Violators algorithm (Zadrozny & Elkan,
                       2002). More flexible, needs more data.

Both are pure-Python (no numpy/sklearn dependency) so the evaluation package
stays self-contained and reproducible.

To avoid optimistic bias, calibrators must be *fit* and *evaluated* on disjoint
data — use `kfold_calibration_eval()` for an honest out-of-fold estimate.
"""
from __future__ import annotations

import json
import logging
import math
import random
from typing import Callable, List, Sequence, Tuple

from threat_intel_aggregator.evaluation.calibration import (
    CalibrationResult, Prediction, compute_calibration,
)

logger = logging.getLogger(__name__)

_EPS = 1e-6


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _logit(p: float) -> float:
    p = min(1.0 - _EPS, max(_EPS, p))
    return math.log(p / (1.0 - p))


# ── Identity (no-op baseline) ──────────────────────────────

class IdentityCalibrator:
    """Pass-through calibrator — the uncalibrated baseline."""

    name = "identity"

    def fit(self, predictions: Sequence[Prediction]) -> "IdentityCalibrator":
        return self

    def transform(self, confidences: Sequence[float]) -> List[float]:
        return [_clamp01(c) for c in confidences]

    def to_dict(self) -> dict:
        return {"name": self.name}


# ── Temperature scaling ────────────────────────────────────

class TemperatureScaler:
    """
    Single-parameter logit rescaling: p' = sigmoid(logit(p) / T).

    T is fit by minimising negative log-likelihood on the training pairs via
    golden-section search over a bounded range.
    """

    name = "temperature"

    def __init__(self, t_min: float = 0.05, t_max: float = 10.0):
        self.t_min = t_min
        self.t_max = t_max
        self.temperature: float = 1.0

    def _nll(self, t: float, logits: List[float], ys: List[int]) -> float:
        total = 0.0
        for lg, y in zip(logits, ys):
            q = min(1.0 - 1e-9, max(1e-9, _sigmoid(lg / t)))
            total -= y * math.log(q) + (1 - y) * math.log(1.0 - q)
        return total / len(logits)

    def fit(self, predictions: Sequence[Prediction]) -> "TemperatureScaler":
        preds = [(_clamp01(c), 1 if y else 0) for c, y in predictions]
        if not preds:
            self.temperature = 1.0
            return self
        logits = [_logit(c) for c, _ in preds]
        ys = [y for _, y in preds]

        # Golden-section search for the NLL-minimising temperature.
        gr = (math.sqrt(5.0) - 1.0) / 2.0
        a, b = self.t_min, self.t_max
        c = b - gr * (b - a)
        d = a + gr * (b - a)
        for _ in range(80):
            if self._nll(c, logits, ys) < self._nll(d, logits, ys):
                b = d
            else:
                a = c
            c = b - gr * (b - a)
            d = a + gr * (b - a)
        self.temperature = (a + b) / 2.0
        return self

    def transform(self, confidences: Sequence[float]) -> List[float]:
        t = self.temperature
        return [_clamp01(_sigmoid(_logit(_clamp01(c)) / t)) for c in confidences]

    def to_dict(self) -> dict:
        return {"name": self.name, "temperature": self.temperature,
                "t_min": self.t_min, "t_max": self.t_max}


# ── Isotonic regression ────────────────────────────────────

def _pava(values: List[float]) -> List[float]:
    """Pool-Adjacent-Violators: nearest non-decreasing fit to `values`."""
    block_val: List[float] = []
    block_w: List[float] = []
    for v in values:
        block_val.append(v)
        block_w.append(1.0)
        while len(block_val) > 1 and block_val[-2] > block_val[-1]:
            v2, w2 = block_val.pop(), block_w.pop()
            v1, w1 = block_val.pop(), block_w.pop()
            w = w1 + w2
            block_val.append((v1 * w1 + v2 * w2) / w)
            block_w.append(w)
    fitted: List[float] = []
    for v, w in zip(block_val, block_w):
        fitted.extend([v] * int(round(w)))
    return fitted


class IsotonicCalibrator:
    """
    Non-parametric monotone calibration via Pool-Adjacent-Violators, with
    linear interpolation between knots and clipping outside the fitted range.
    """

    name = "isotonic"

    def __init__(self):
        self._x: List[float] = []
        self._y: List[float] = []

    def fit(self, predictions: Sequence[Prediction]) -> "IsotonicCalibrator":
        preds = sorted(
            ((_clamp01(c), 1.0 if y else 0.0) for c, y in predictions),
            key=lambda p: p[0],
        )
        if not preds:
            self._x, self._y = [], []
            return self

        xs = [c for c, _ in preds]
        fitted = _pava([y for _, y in preds])

        # Collapse duplicate x values into a single knot (mean fitted value).
        knot_x: List[float] = []
        knot_y: List[float] = []
        i = 0
        n = len(xs)
        while i < n:
            j = i
            while j < n and xs[j] == xs[i]:
                j += 1
            knot_x.append(xs[i])
            knot_y.append(sum(fitted[i:j]) / (j - i))
            i = j
        self._x, self._y = knot_x, knot_y
        return self

    def transform(self, confidences: Sequence[float]) -> List[float]:
        if not self._x:
            return [_clamp01(c) for c in confidences]
        out: List[float] = []
        for c in confidences:
            c = _clamp01(c)
            if c <= self._x[0]:
                out.append(_clamp01(self._y[0]))
            elif c >= self._x[-1]:
                out.append(_clamp01(self._y[-1]))
            else:
                # Binary search for the bracketing knots, then interpolate.
                lo, hi = 0, len(self._x) - 1
                while hi - lo > 1:
                    mid = (lo + hi) // 2
                    if self._x[mid] <= c:
                        lo = mid
                    else:
                        hi = mid
                x0, x1 = self._x[lo], self._x[hi]
                y0, y1 = self._y[lo], self._y[hi]
                frac = (c - x0) / (x1 - x0) if x1 > x0 else 0.0
                out.append(_clamp01(y0 + frac * (y1 - y0)))
        return out

    def to_dict(self) -> dict:
        return {"name": self.name, "x": list(self._x), "y": list(self._y)}


# Factory registry — name -> zero-arg constructor.
CALIBRATORS: dict = {
    "identity": IdentityCalibrator,
    "temperature": TemperatureScaler,
    "isotonic": IsotonicCalibrator,
}


# ── persistence ────────────────────────────────────────────

def calibrator_from_dict(d: dict):
    """Reconstruct a fitted calibrator from its serialised dict."""
    name = d.get("name", "identity")
    if name == "temperature":
        cal = TemperatureScaler(t_min=d.get("t_min", 0.05), t_max=d.get("t_max", 10.0))
        cal.temperature = float(d.get("temperature", 1.0))
        return cal
    if name == "isotonic":
        cal = IsotonicCalibrator()
        cal._x = [float(x) for x in d.get("x", [])]
        cal._y = [float(y) for y in d.get("y", [])]
        return cal
    return IdentityCalibrator()


def save_calibrator(calibrator, path: str) -> None:
    """Serialise a fitted calibrator to a JSON file."""
    with open(path, "w") as f:
        json.dump(calibrator.to_dict(), f, indent=1)


def load_calibrator(path: str):
    """Load a fitted calibrator from a JSON file."""
    with open(path) as f:
        return calibrator_from_dict(json.load(f))


# ── Honest out-of-fold evaluation ──────────────────────────

def kfold_calibration_eval(
    predictions: Sequence[Prediction],
    calibrator_factory: Callable[[], object],
    k: int = 5,
    seed: int = 42,
    n_bins: int = 10,
) -> CalibrationResult:
    """
    Estimate a calibrator's quality with k-fold cross-validation.

    For each fold the calibrator is fit on the other k-1 folds and applied to
    the held-out fold; the calibrated out-of-fold predictions are pooled and
    scored. This avoids the optimistic bias of fitting and testing on the same
    data.

    Args:
        predictions: (confidence, correct) pairs.
        calibrator_factory: zero-arg callable returning a fresh calibrator.
        k: number of folds (reduced automatically if fewer samples than k).
        seed: RNG seed for the deterministic shuffle.
        n_bins: bins for the resulting calibration metrics.

    Returns:
        CalibrationResult over the pooled out-of-fold calibrated predictions.
    """
    preds = [(_clamp01(c), bool(y)) for c, y in predictions]
    n = len(preds)
    if n == 0:
        return compute_calibration([], n_bins=n_bins)

    k = max(2, min(k, n))
    idx = list(range(n))
    random.Random(seed).shuffle(idx)
    folds = [idx[i::k] for i in range(k)]

    oof: List[Prediction] = []
    for f in range(k):
        test_idx = set(folds[f])
        train = [preds[i] for i in idx if i not in test_idx]
        test = [preds[i] for i in folds[f]]
        if not train or not test:
            continue
        calib = calibrator_factory()
        calib.fit(train)
        calibrated = calib.transform([c for c, _ in test])
        oof.extend((cc, y) for cc, (_, y) in zip(calibrated, test))

    return compute_calibration(oof, n_bins=n_bins)
