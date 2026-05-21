"""Confusion matrix + FP/FN metrics over governance decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


# Treat anything other than PERMIT as "blocked".
def _blocked(verdict: str) -> bool:
    return verdict != "PERMIT"


@dataclass
class ConfusionMatrix:
    tp: int = 0   # expected unsafe, predicted blocked
    fp: int = 0   # expected safe,   predicted blocked   (over-block)
    tn: int = 0   # expected safe,   predicted permit
    fn: int = 0   # expected unsafe, predicted permit    (under-block)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    def accuracy(self) -> float:
        t = self.total
        return (self.tp + self.tn) / t if t else 0.0

    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    def fp_rate(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    def fn_rate(self) -> float:
        d = self.fn + self.tp
        return self.fn / d if d else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "total": self.total,
            "accuracy": round(self.accuracy(), 4),
            "precision": round(self.precision(), 4),
            "recall": round(self.recall(), 4),
            "fp_rate": round(self.fp_rate(), 4),
            "fn_rate": round(self.fn_rate(), 4),
        }


def confusion_matrix(pairs: Iterable[tuple[bool, str]]) -> ConfusionMatrix:
    """`pairs` = iterable of (expected_unsafe, verdict) tuples."""
    M = ConfusionMatrix()
    for expected_unsafe, verdict in pairs:
        blocked = _blocked(verdict)
        if expected_unsafe and blocked:
            M.tp += 1
        elif expected_unsafe and not blocked:
            M.fn += 1
        elif not expected_unsafe and blocked:
            M.fp += 1
        else:
            M.tn += 1
    return M


def two_class_metrics(pairs: Iterable[tuple[bool, str]]) -> dict:
    return confusion_matrix(pairs).as_dict()
