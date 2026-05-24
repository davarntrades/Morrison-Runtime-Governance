"""Latency metrics over a sequence of governance decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass
class LatencyStats:
    n: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    mean_ms: float
    max_ms: float

    def as_dict(self) -> dict:
        return {"n": self.n, "p50_ms": round(self.p50_ms, 3),
                "p95_ms": round(self.p95_ms, 3),
                "p99_ms": round(self.p99_ms, 3),
                "mean_ms": round(self.mean_ms, 3),
                "max_ms": round(self.max_ms, 3)}


def _pct(sorted_vals: list, p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def latency_stats(ms_values: Iterable[float]) -> LatencyStats:
    vals = sorted(float(v) for v in ms_values)
    if not vals:
        return LatencyStats(0, 0.0, 0.0, 0.0, 0.0, 0.0)
    return LatencyStats(
        n=len(vals),
        p50_ms=_pct(vals, 0.50),
        p95_ms=_pct(vals, 0.95),
        p99_ms=_pct(vals, 0.99),
        mean_ms=sum(vals) / len(vals),
        max_ms=vals[-1],
    )
