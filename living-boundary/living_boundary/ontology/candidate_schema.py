"""Machine-readable representation of a candidate governance primitive.

A candidate primitive is a CONJUNCTION OF LITERALS over generic structural
features of a trajectory. Two consequences follow, and both are the reason this
representation was chosen over an embedding or a free-text description:

  · IT IS EXECUTABLE. `CandidatePrimitive.matches(trajectory)` is a predicate,
    so the candidate makes a prediction on any trajectory, including ones built
    specifically to break it. A description cannot be falsified; a predicate
    can.

  · IT IS INSPECTABLE. Every literal names the observable it reads. Another
    engineer can decide whether the discovery is real without taking the
    system's word for it — which is the stated bar for LB-0.

LIFECYCLE. The blueprint's promotion state machine is DISCOVERED → HYPOTHESISED
→ TESTING → VALIDATED → REVIEW_REQUIRED → APPROVED → SHADOW → ENFORCED. LB-0
implements only the first four states and refuses the rest: `advance()` raises
on any transition beyond `REVIEW_REQUIRED`. There is no code path in this
package that produces APPROVED, SHADOW or ENFORCED, and
`tests/test_no_production_authority.py` asserts that trying to reach them
raises rather than succeeding quietly.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable, Optional


class CandidateStatus:
    """Promotion lifecycle states. LB-0 may only occupy the first four."""

    DISCOVERED = "DISCOVERED"
    HYPOTHESISED = "HYPOTHESISED"
    TESTING = "TESTING"
    VALIDATED = "VALIDATED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    # Beyond the LB-0 authority boundary. Named so the boundary is explicit in
    # source rather than implied by absence.
    APPROVED = "APPROVED"
    SHADOW = "SHADOW"
    ENFORCED = "ENFORCED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


# The furthest an LB-0 candidate may travel. Everything past this point needs an
# authorised human decision that this package cannot represent, let alone make.
TERMINAL_LB0_STATUS = CandidateStatus.REVIEW_REQUIRED

_LB0_PERMITTED_STATUSES = (
    CandidateStatus.DISCOVERED, CandidateStatus.HYPOTHESISED,
    CandidateStatus.TESTING, CandidateStatus.VALIDATED,
    CandidateStatus.REVIEW_REQUIRED, CandidateStatus.REJECTED,
    CandidateStatus.INCONCLUSIVE,
)

_FORBIDDEN_IN_LB0 = (
    CandidateStatus.APPROVED, CandidateStatus.SHADOW, CandidateStatus.ENFORCED,
)


class AuthorityBoundaryError(RuntimeError):
    """Raised when something tries to move a candidate past LB-0's authority."""


@dataclass(frozen=True)
class Literal:
    """One boolean condition over a trajectory, with its evaluator attached.

    `name` is generated mechanically from observed trace vocabulary by
    `discovery/features.py`. It is the literal's identity in the evidence
    package, so two runs that discover the same structure produce the same
    string and can be compared without interpretation.
    """

    name: str
    family: str
    description: str
    negated: bool = False
    predicate: Callable | None = None

    def evaluate(self, trajectory) -> bool:
        if self.predicate is None:
            raise ValueError(
                "literal {!r} has no predicate bound; a candidate loaded from "
                "JSON can be inspected but not evaluated".format(self.name))
        return bool(self.predicate(trajectory)) != self.negated

    def as_dict(self) -> dict:
        return {"name": self.name, "family": self.family,
                "description": self.description, "negated": self.negated}


@dataclass
class CandidatePrimitive:
    """A proposed governance primitive. EXPERIMENTAL for the whole of LB-0."""

    candidate_id: str
    name: str
    description: str
    literals: tuple = ()
    observed_variables: tuple = ()
    hypothesis: str = ""
    falsifiable_prediction: str = ""
    source_evidence: tuple = ()           # sequence ids that supported discovery
    supporting_traces: int = 0
    discovery_metrics: dict = field(default_factory=dict)
    validation_metrics: dict = field(default_factory=dict)
    status: str = CandidateStatus.DISCOVERED
    ontology_version_observed: str = ""

    # ── prediction ───────────────────────────────────────────
    def matches(self, trajectory) -> bool:
        """The candidate's prediction: True means "predict unsafe"."""
        if not self.literals:
            return False
        return all(lit.evaluate(trajectory) for lit in self.literals)

    def predict_all(self, trajectories) -> dict:
        return {t.sequence_id: self.matches(t) for t in trajectories}

    # ── lifecycle ────────────────────────────────────────────
    def advance(self, status: str) -> CandidatePrimitive:
        """Move the candidate one step along the promotion lifecycle.

        Refuses every state beyond LB-0's authority. This is not a policy
        setting or a configuration flag — there is no argument that unlocks it,
        because the whole architectural invariant is that the discovery layer
        cannot grant its own findings production authority.
        """
        if status in _FORBIDDEN_IN_LB0:
            raise AuthorityBoundaryError(
                "LB-0 cannot transition a candidate to {}. Promotion beyond {} "
                "requires an authorised human decision recorded outside this "
                "package; the discovery layer has no path to it by "
                "construction.".format(status, TERMINAL_LB0_STATUS))
        if status not in _LB0_PERMITTED_STATUSES:
            raise ValueError(f"unknown candidate status {status!r}")
        self.status = status
        return self

    # ── identity / serialisation ─────────────────────────────
    @property
    def structure_hash(self) -> str:
        """Stable hash of the candidate's STRUCTURE (its literal set).

        Used for cross-seed stability: two runs discovering the same structure
        share this hash regardless of candidate id, metrics or wording.
        """
        payload = json.dumps(sorted(lit.name for lit in self.literals),
                             sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @property
    def literal_names(self) -> frozenset:
        return frozenset(lit.name for lit in self.literals)

    def as_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "structure_hash": self.structure_hash,
            "literals": [lit.as_dict() for lit in self.literals],
            "observed_variables": list(self.observed_variables),
            "hypothesis": self.hypothesis,
            "falsifiable_prediction": self.falsifiable_prediction,
            "supporting_traces": self.supporting_traces,
            "source_evidence": list(self.source_evidence),
            "discovery_metrics": dict(self.discovery_metrics),
            "validation_metrics": dict(self.validation_metrics),
            "ontology_version_observed": self.ontology_version_observed,
            "production_authority": "none",
        }
