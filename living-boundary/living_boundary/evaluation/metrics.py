"""Confusion-matrix arithmetic. Pure, dependency-free, no ground-truth access.

Every rate here is defined explicitly rather than left to the reader, because
"false positive rate" is ambiguous in the literature and LB-0's acceptance gate
is stated in terms of it:

    precision  tp / (tp + fp)          of what we flagged, how much was real
    recall     tp / (tp + fn)          of what was real, how much we flagged
    f1         harmonic mean of both
    fpr        fp / (fp + tn)          of the SAFE trajectories, how many we
                                       wrongly flagged  (per-negative rate)
    fnr        fn / (fn + tp)          of the UNSAFE trajectories, how many we
                                       missed            (per-positive rate)

`fpr` is deliberately the per-negative rate rather than `fp / (tp + fp)`. In a
governance setting the operational cost of over-blocking scales with how much
ordinary traffic is disrupted, which is the negative class.
"""

from __future__ import annotations

from dataclasses import dataclass


def _ratio(numerator: int, denominator: int) -> float:
    return (numerator / denominator) if denominator else 0.0


@dataclass(frozen=True)
class ConfusionMatrix:
    """Counts plus every derived rate LB-0 reports."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def positives(self) -> int:
        return self.tp + self.fn

    @property
    def negatives(self) -> int:
        return self.tn + self.fp

    @property
    def precision(self) -> float:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return _ratio(2 * p * r, p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return _ratio(self.tp + self.tn, self.total)

    @property
    def false_positive_rate(self) -> float:
        return _ratio(self.fp, self.negatives)

    @property
    def false_negative_rate(self) -> float:
        return _ratio(self.fn, self.positives)

    @property
    def mcc(self) -> float:
        """Matthews correlation coefficient: +1 perfect, 0 chance, -1 inverted.

        Reported because F1 is not a safe statistic for the memorisation control
        in this setting, and that was measured rather than assumed. The combined
        predictor is `baseline OR candidate`, and the baseline here has recall
        0.29 at precision 1.0 — so ALMOST ANY predictor that fires at all raises
        F1, simply by converting false negatives into a mix of true and false
        positives. A candidate fitted to deliberately SHUFFLED labels improved
        held-out F1 by +0.05 that way, which says nothing about whether it found
        structure.

        MCC uses all four cells and is ~0 for a predictor uncorrelated with the
        outcome regardless of class balance, so the noise control has somewhere
        to fail.
        """
        numerator = (self.tp * self.tn) - (self.fp * self.fn)
        denominator = ((self.tp + self.fp) * (self.tp + self.fn)
                       * (self.tn + self.fp) * (self.tn + self.fn))
        if denominator <= 0:
            return 0.0
        return numerator / (denominator ** 0.5)

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "total": self.total, "positives": self.positives,
            "negatives": self.negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "mcc": round(self.mcc, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
        }


def confusion(predictions, truths) -> ConfusionMatrix:
    """Build a confusion matrix from two aligned boolean sequences."""
    tp = fp = tn = fn = 0
    for predicted, actual in zip(predictions, truths):
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1
    return ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)


def mcnemar_counts(predictions_a, predictions_b, truths) -> dict:
    """Discordant-pair counts between two predictors on the same cases.

    Reported instead of a p-value. LB-0's held-out sets are generated rather
    than sampled from a population, so a significance test would be answering a
    question about sampling error that does not arise here. The discordant
    counts say the useful thing directly: on how many cases did B fix what A got
    wrong, and on how many did it break what A got right.
    """
    b_fixes_a = 0
    a_fixes_b = 0
    for pred_a, pred_b, actual in zip(predictions_a, predictions_b, truths):
        correct_a = bool(pred_a) == bool(actual)
        correct_b = bool(pred_b) == bool(actual)
        if correct_b and not correct_a:
            b_fixes_a += 1
        elif correct_a and not correct_b:
            a_fixes_b += 1
    return {"b_corrects_a": b_fixes_a, "b_breaks_a": a_fixes_b,
            "net_improvement": b_fixes_a - a_fixes_b}
