"""Finite-model global safety verification for Morrison Runtime Governance.

This package proves only what it enumerates. It never claims universal or
open-world safety.
"""

from .comparison import (
    ComparisonResult,
    compare_control_and_governed,
    run_composition_experiment,
)
from .environment import FiniteEnvironment
from .evidence import GraphEvidence, build_verification_artifact
from .governance import GovernanceDecision, MorrisonKernelAdapter
from .scenarios import SCENARIOS, get_scenario, perturbation_matrix
from .state import VerificationState
from .unsafe import DEFAULT_UNSAFE_INVARIANTS, UnsafeInvariant
from .verifier import (
    INCONCLUSIVE,
    SAFE_WITHIN_MODEL,
    UNSAFE_COUNTEREXAMPLE_FOUND,
    ExhaustiveVerifier,
    TraversalResult,
    VerificationLimits,
)

__all__ = [
    "ComparisonResult",
    "DEFAULT_UNSAFE_INVARIANTS",
    "ExhaustiveVerifier",
    "FiniteEnvironment",
    "GraphEvidence",
    "GovernanceDecision",
    "INCONCLUSIVE",
    "MorrisonKernelAdapter",
    "SAFE_WITHIN_MODEL",
    "SCENARIOS",
    "TraversalResult",
    "UNSAFE_COUNTEREXAMPLE_FOUND",
    "UnsafeInvariant",
    "VerificationLimits",
    "VerificationState",
    "build_verification_artifact",
    "compare_control_and_governed",
    "get_scenario",
    "perturbation_matrix",
    "run_composition_experiment",
]

