"""LB-3: cross-environment structural transfer.

The analysis half of LB-3. Nothing here may import the harness — not the world
definitions, not the generators, not the hidden rule — and
`tests/test_lb3_isolation.py` proves it on the import graph rather than trusting
the convention.
"""

from living_boundary.transfer.evaluator import (
    ABSTAINED, COLLAPSED, DEGRADED, TRANSFERRED, EnvironmentResult,
    evaluate_environment, invariance_battery,
)
from living_boundary.transfer.freeze import (
    FrozenCandidate, FrozenCandidateError, freeze,
)
from living_boundary.transfer.grammars import (
    GRAMMARS, grammar_fn, grammar_version, relational_features,
    surface_features, typed_features,
)
from living_boundary.transfer.hypotheses import HYPOTHESES, Hypothesis
from living_boundary.transfer.retention import (
    MIN_DISCOVERY_LIFT, Retention, aggregate, baseline_f1, lift, retention,
)
from living_boundary.transfer.roles import (
    ROLE_COUNT, STATISTIC_NAMES, RoleModel, align, alignment_cost, induce_roles,
)

__all__ = [
    "ABSTAINED", "COLLAPSED", "DEGRADED", "TRANSFERRED", "EnvironmentResult",
    "evaluate_environment", "invariance_battery",
    "FrozenCandidate", "FrozenCandidateError", "freeze",
    "GRAMMARS", "grammar_fn", "grammar_version", "relational_features",
    "surface_features", "typed_features",
    "HYPOTHESES", "Hypothesis",
    "MIN_DISCOVERY_LIFT", "Retention", "aggregate", "baseline_f1", "lift",
    "retention",
    "ROLE_COUNT", "STATISTIC_NAMES", "RoleModel", "align", "alignment_cost",
    "induce_roles",
]
