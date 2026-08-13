"""Evidence evaluation. Independent of candidate generation by construction.

`evaluation/` imports nothing from `discovery/`. The evaluator scores whatever
predicate it is handed against ground truth; it has no view on where that
predicate came from and no way to help it. If an LLM is ever introduced as a
candidate generator, this separation is what keeps the blueprint's requirement
satisfied without any further work: the thing that judges the evidence cannot
be the thing that produced the claim.
"""

from __future__ import annotations

from living_boundary.evaluation.evaluator import (
    ComparisonResult, evaluate_predictor, compare_to_baseline, ground_truth_labels,
)
from living_boundary.evaluation.metrics import ConfusionMatrix, confusion

__all__ = ["ComparisonResult", "evaluate_predictor", "compare_to_baseline",
           "ground_truth_labels", "ConfusionMatrix", "confusion"]
