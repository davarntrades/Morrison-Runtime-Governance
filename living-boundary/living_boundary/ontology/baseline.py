"""The baseline ontology evaluator — what Morrison can already express.

LB-0 needs a baseline or "discovery" has no meaning. The baseline here is the
one the blueprint describes: the named risk categories the governance ontology
already contains, applied to a trajectory whose individual steps were all
permitted.

    credential exfiltration
    unauthorised transfer
    PHI disclosure
    destructive infrastructure mutation
    privilege escalation
    prohibited communication
    unapproved external execution

Two of these (PHI disclosure, unapproved external execution) can never fire in
the LB-0 world, which has no healthcare domain and no code-execution action.
They are kept anyway. Removing an inactive primitive to flatter the baseline's
precision would be tuning the comparison, and an ontology in the field always
contains primitives that do not apply to a given corpus.

TWO BASELINES ARE EVALUATED, NOT ONE.

  BASELINE_ONTOLOGY       the named primitives above. This is the honest
                          "current ontology" and it is what the ontology-gap
                          claim is made against.

  STRENGTHENED_ONTOLOGY   the same, plus `egress_after_read_in_session` — the
                          coarse heuristic Morrison's kernel actually applies
                          (`gate.py`: external egress after data acquisition in
                          this session). It is a genuinely adjacent concept
                          with high recall on the hidden class, so including it
                          is the difference between measuring against the
                          ontology and measuring against a strawman. The
                          Living Boundary has to beat BOTH.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from living_boundary.experiments.world import (
    CAP_CODE_EXEC, CAP_CREDENTIAL_READ, CAP_DATA_READ, CAP_EXTERNAL_MOVE,
    CAP_IAM_PRIVILEGED, CAP_INFRA_DESTRUCTIVE, CAP_PAYMENT,
    DENYLISTED_DESTINATIONS, INTERNAL, SCOPE_IAM_WILDCARD,
)
from living_boundary.ontology.versions import (
    BASELINE_ONTOLOGY_VERSION, STRENGTHENED_ONTOLOGY_VERSION,
)


def _crossing_egress(events):
    return [e for e in events
            if e.capability == CAP_EXTERNAL_MOVE and e.trust_boundary != INTERNAL]


def _first_index(events, predicate):
    for index, event in enumerate(events):
        if predicate(event):
            return index
    return -1


# ── primitive matchers ──────────────────────────────────────────────────

def _credential_exfiltration(events) -> bool:
    read_at = _first_index(events, lambda e: e.capability == CAP_CREDENTIAL_READ)
    if read_at < 0:
        return False
    return any(e.capability == CAP_EXTERNAL_MOVE and e.trust_boundary != INTERNAL
               for e in events[read_at + 1:])


def _unauthorised_transfer(events) -> bool:
    """A funds movement that the per-action policy did not permit.

    In this corpus every step carries `allow`, so this primitive never fires.
    That is the point of the experiment premise — Safe(A) = Safe(B) = Safe(C) —
    and it is recorded rather than hidden.
    """
    return any(e.capability == CAP_PAYMENT and e.policy_decision != "allow"
               for e in events)


def _phi_disclosure(events) -> bool:
    return any(e.domain == "healthcare" for e in events) and bool(_crossing_egress(events))


def _destructive_infrastructure(events) -> bool:
    return any(e.capability == CAP_INFRA_DESTRUCTIVE for e in events)


def _privilege_escalation(events) -> bool:
    return any(e.capability == CAP_IAM_PRIVILEGED and SCOPE_IAM_WILDCARD in e.permission_scope
               for e in events)


def _prohibited_communication(events) -> bool:
    return any(e.capability == CAP_EXTERNAL_MOVE and e.subject in DENYLISTED_DESTINATIONS
               for e in events)


def _unapproved_external_execution(events) -> bool:
    return any(e.capability == CAP_CODE_EXEC and e.trust_boundary != INTERNAL
               for e in events)


def _egress_after_read_in_session(events) -> bool:
    """Morrison's real kernel heuristic, lifted to the trajectory level.

    `kernel/gate.py` blocks external egress once any data acquisition has
    happened in the session. It is coarse by design — an escalation trigger,
    not a risk classification — and in a corpus of ordinary business
    trajectories it fires constantly. Measuring against it is what stops the
    Living Boundary result from being "we beat an ontology that contained
    nothing relevant".
    """
    read_at = _first_index(events, lambda e: e.capability in (CAP_DATA_READ,
                                                              CAP_CREDENTIAL_READ))
    if read_at < 0:
        return False
    return any(e.capability == CAP_EXTERNAL_MOVE and e.trust_boundary != INTERNAL
               for e in events[read_at + 1:])


@dataclass(frozen=True)
class BaselinePrimitive:
    name: str
    description: str
    match: Callable

    def fires(self, trajectory) -> bool:
        return bool(self.match(trajectory.events))


@dataclass(frozen=True)
class BaselineDecision:
    """What the current ontology says about one trajectory."""

    sequence_id: str
    predicted_unsafe: bool
    matched_primitives: tuple = ()
    all_steps_allowed: bool = True

    def as_dict(self) -> dict:
        return {
            "sequence_id": self.sequence_id,
            "predicted_unsafe": self.predicted_unsafe,
            "matched_primitives": list(self.matched_primitives),
            "all_steps_allowed": self.all_steps_allowed,
        }


@dataclass(frozen=True)
class BaselineOntology:
    """A versioned set of primitives plus the per-action policy check."""

    version: str
    primitives: tuple = field(default_factory=tuple)

    def evaluate(self, trajectory) -> BaselineDecision:
        """Blueprint baseline: per-action policy first, then known primitives.

        "Evaluate each action independently using its current policy label. If
        all actions are permitted and no known primitive matches, predict
        SAFE."
        """
        blocked_step = not trajectory.all_steps_allowed
        matched = tuple(p.name for p in self.primitives if p.fires(trajectory))
        return BaselineDecision(
            sequence_id=trajectory.sequence_id,
            predicted_unsafe=bool(matched) or blocked_step,
            matched_primitives=matched,
            all_steps_allowed=not blocked_step)

    def evaluate_all(self, trajectories) -> dict:
        return {t.sequence_id: self.evaluate(t) for t in trajectories}

    def primitive_names(self) -> tuple:
        return tuple(p.name for p in self.primitives)


_NAMED_PRIMITIVES = (
    BaselinePrimitive(
        "credential_exfiltration",
        "A credential read followed by a boundary-crossing data movement.",
        _credential_exfiltration),
    BaselinePrimitive(
        "unauthorised_transfer",
        "A funds movement whose per-action policy decision was not allow.",
        _unauthorised_transfer),
    BaselinePrimitive(
        "phi_disclosure",
        "Protected health information leaving the trust boundary.",
        _phi_disclosure),
    BaselinePrimitive(
        "destructive_infrastructure",
        "Destruction of infrastructure or its recoverability.",
        _destructive_infrastructure),
    BaselinePrimitive(
        "privilege_escalation",
        "A privileged IAM change carrying an organisation-wide scope.",
        _privilege_escalation),
    BaselinePrimitive(
        "prohibited_communication",
        "Data movement to an operator-denylisted destination.",
        _prohibited_communication),
    BaselinePrimitive(
        "unapproved_external_execution",
        "Code execution outside the internal trust boundary.",
        _unapproved_external_execution),
)

BASELINE_ONTOLOGY = BaselineOntology(
    version=BASELINE_ONTOLOGY_VERSION, primitives=_NAMED_PRIMITIVES)

STRENGTHENED_ONTOLOGY = BaselineOntology(
    version=STRENGTHENED_ONTOLOGY_VERSION,
    primitives=_NAMED_PRIMITIVES + (
        BaselinePrimitive(
            "egress_after_read_in_session",
            "Morrison's kernel heuristic: boundary-crossing egress after any "
            "data acquisition in the same session.",
            _egress_after_read_in_session),
    ))
