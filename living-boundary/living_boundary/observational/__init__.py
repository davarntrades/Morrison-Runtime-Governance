"""Observational analysis of sealed, irreversible governance evidence.

LB-2's analysis layer. It receives a `SealedArchive` and nothing else — no
environment, no oracle, no way to execute anything — and must decide whether the
current representation is insufficient using only what already happened.

    archive.py         sealed evidence, and the record identity that replaces
                       replay
    strata.py          feature-level vs record-level disagreement
    uncertainty.py     Wilson intervals, Mantel-Haenszel pooling
    cohorts.py         matched cohorts and counterfactual proxies
    temporal.py        consistency across collection periods
    counterfactual.py  record-level shadow perturbation (executes nothing)
    inference.py       the verdict ladder, with abstention as a first-class
                       outcome

`tests/test_lb2_isolation.py` proves this package cannot reach the harness that
knows what actually drives each scenario, and cannot execute anything at all.
"""

from __future__ import annotations

from living_boundary.observational.archive import (
    SealedArchive, SealedTrajectory, feature_signature, record_signature,
)
from living_boundary.observational.cohorts import CohortAnalysis, analyse_cohorts
from living_boundary.observational.counterfactual import shadow_consistency
from living_boundary.observational.inference import (
    INADEQUATE_VERDICTS, Lb2Assessment, Lb2Verdict, assess,
)
from living_boundary.observational.strata import StratifiedCollisions, stratify
from living_boundary.observational.temporal import (
    check_consistency, distribution_shift,
)
from living_boundary.observational.uncertainty import Interval, wilson

__all__ = [
    "SealedArchive", "SealedTrajectory", "feature_signature",
    "record_signature", "CohortAnalysis", "analyse_cohorts",
    "shadow_consistency", "INADEQUATE_VERDICTS", "Lb2Assessment", "Lb2Verdict",
    "assess", "StratifiedCollisions", "stratify", "check_consistency",
    "distribution_shift", "Interval", "wilson",
]
