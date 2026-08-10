"""Score predictors against ground truth. The independent half of the pipeline.

The evaluator takes a callable `trajectory -> bool` and a set of trajectories,
asks the ORACLE what actually happened, and reports the confusion matrix. It
knows nothing about how the predictor was built, cannot influence it, and is
imported by no module under `discovery/`.

GROUND TRUTH COMES FROM THE ORACLE, NOT FROM THE TRACE LABEL.

For dataset trajectories the two agree — the generator wrote the oracle's answer
into `trajectory_outcome`. For falsification cases they cannot: those
trajectories were constructed after the dataset was built and carry no label.
Scoring everything through the oracle means one definition of truth across the
whole run, and it removes the possibility of a perturbation silently inheriting
its seed trajectory's label.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.evaluation.metrics import (
    ConfusionMatrix, confusion, mcnemar_counts,
)
from living_boundary.experiments import hidden_ground_truth as oracle


def ground_truth_labels(trajectories) -> list:
    """The oracle's verdict for each trajectory, as booleans (True = unsafe)."""
    return [oracle.is_unsafe(t.events) for t in trajectories]


def evaluate_predictor(predictor, trajectories, truths=None) -> ConfusionMatrix:
    """Confusion matrix for `predictor` over `trajectories`."""
    if truths is None:
        truths = ground_truth_labels(trajectories)
    predictions = [bool(predictor(t)) for t in trajectories]
    return confusion(predictions, truths)


@dataclass
class ComparisonResult:
    """One predictor measured against one baseline on one split."""

    split: str
    baseline_name: str
    candidate_name: str
    baseline: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    candidate: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    discordance: dict = field(default_factory=dict)

    @property
    def f1_delta(self) -> float:
        return self.candidate.f1 - self.baseline.f1

    @property
    def improved(self) -> bool:
        return self.f1_delta > 0.0

    def as_dict(self) -> dict:
        return {
            "split": self.split,
            "baseline_name": self.baseline_name,
            "candidate_name": self.candidate_name,
            "baseline": self.baseline.as_dict(),
            "candidate": self.candidate.as_dict(),
            "f1_delta": round(self.f1_delta, 4),
            "improved": self.improved,
            "discordance": dict(self.discordance),
        }


def compare_to_baseline(split_name, trajectories, baseline_predictor,
                        candidate_predictor, baseline_name="baseline",
                        candidate_name="living_boundary") -> ComparisonResult:
    """Measure both predictors on identical cases with identical ground truth."""
    truths = ground_truth_labels(trajectories)
    baseline_predictions = [bool(baseline_predictor(t)) for t in trajectories]
    candidate_predictions = [bool(candidate_predictor(t)) for t in trajectories]
    return ComparisonResult(
        split=split_name,
        baseline_name=baseline_name,
        candidate_name=candidate_name,
        baseline=confusion(baseline_predictions, truths),
        candidate=confusion(candidate_predictions, truths),
        discordance=mcnemar_counts(baseline_predictions, candidate_predictions,
                                   truths))


def combined_predictor(ontology, candidate):
    """`baseline OR candidate` — how a new primitive would actually be used.

    A candidate primitive ADDS to an ontology; it does not replace it. Scoring
    the candidate alone would understate recall (it never sees the classes the
    ontology already handles) and would not describe any deployment anyone would
    consider. The union is the honest comparison against the baseline alone.
    """
    def _predict(trajectory) -> bool:
        if ontology.evaluate(trajectory).predicted_unsafe:
            return True
        return candidate.matches(trajectory)
    return _predict


def baseline_predictor(ontology):
    def _predict(trajectory) -> bool:
        return ontology.evaluate(trajectory).predicted_unsafe
    return _predict


def residual_recovery(trajectories, ontology, candidate) -> dict:
    """How much of the ontology's blind spot the candidate actually recovers.

    Reported separately from F1 because the headline metric is dominated by the
    classes the baseline already handles. This is the number that speaks to the
    LB-0 question directly: of the unsafe trajectories the current ontology
    cannot represent at all, how many does the candidate catch, and at what cost
    among the safe trajectories it also cannot represent?
    """
    truths = ground_truth_labels(trajectories)
    covered = [ontology.evaluate(t).predicted_unsafe for t in trajectories]
    uncovered = [t for t, seen in zip(trajectories, covered) if not seen]
    uncovered_truth = [truth for truth, seen in zip(truths, covered) if not seen]
    matrix = confusion([candidate.matches(t) for t in uncovered], uncovered_truth)
    return {
        "uncovered_trajectories": len(uncovered),
        "uncovered_unsafe": sum(1 for truth in uncovered_truth if truth),
        "recovered_unsafe": matrix.tp,
        "recovery_rate": round(matrix.recall, 4),
        "false_positives_on_uncovered_safe": matrix.fp,
        "false_positive_rate_on_uncovered_safe": round(matrix.false_positive_rate, 4),
    }
