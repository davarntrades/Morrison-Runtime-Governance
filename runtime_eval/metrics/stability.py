"""Stochastic stability metrics.

Quantifies how stable a planner's governance outcomes are across
samples (different temperatures, different seeds, different planners).
All metrics are deterministic functions of the input arrays — no
sampling here; the harness collects the samples upstream and feeds
them in.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Iterable


@dataclass
class StabilityReport:
    n_samples: int
    unique_verdicts: int
    majority_fraction: float
    entropy_bits: float
    disagreement_rate: float                # 1 - majority_fraction

    def as_dict(self) -> dict:
        return {"n_samples": self.n_samples,
                "unique_verdicts": self.unique_verdicts,
                "majority_fraction": round(self.majority_fraction, 4),
                "entropy_bits": round(self.entropy_bits, 4),
                "disagreement_rate": round(self.disagreement_rate, 4)}


def verdict_stability(verdicts: Iterable[str]) -> StabilityReport:
    """Across N samples of the *same* underlying intent, how stable is
    the verdict label? Bounded entropy in bits; deterministic."""
    vs = list(verdicts)
    n = len(vs)
    c = Counter(vs)
    if n == 0:
        return StabilityReport(0, 0, 0.0, 0.0, 0.0)
    majority = max(c.values()) / n
    entropy = -sum((v / n) * math.log2(v / n) for v in c.values())
    return StabilityReport(
        n_samples=n, unique_verdicts=len(c),
        majority_fraction=majority,
        entropy_bits=entropy,
        disagreement_rate=1.0 - majority,
    )


def planner_divergence(verdicts_by_planner: dict) -> dict:
    """Per pair of planners: fraction of steps where verdict label
    diverged. Inputs are equal-length sequences keyed by planner
    name. Output is a dict of pairs."""
    names = sorted(verdicts_by_planner)
    out = {}
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            va, vb = verdicts_by_planner[a], verdicts_by_planner[b]
            n = min(len(va), len(vb))
            if not n:
                out[(a, b)] = 0.0
                continue
            div = sum(1 for x, y in zip(va[:n], vb[:n]) if x != y)
            out[(a, b)] = round(div / n, 4)
    return out
