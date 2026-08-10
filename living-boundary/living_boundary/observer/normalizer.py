"""Trace normalisation into a stable, closed schema.

The schema is the one in `living-boundary/README.md` §4, which is itself a
Morrison-compatible evidence shape: capability, domain, identity, permission
scope, trust boundary, resource, policy decision, execution outcome,
provenance.

TWO PROPERTIES MATTER HERE, AND BOTH ARE SECURITY PROPERTIES OF THE EXPERIMENT:

  1. THE KEY SET IS CLOSED. An event carrying a key outside `ALLOWED_EVENT_KEYS`
     is rejected, not ignored. If it were ignored, a future generator (or a
     careless replay of real traces) could smuggle an annotation such as
     `"rule_that_fired": "..."` into the discovery layer, and the experiment
     would silently become a retrieval test rather than a discovery test.

  2. NORMALISATION IS TOTAL AND DETERMINISTIC. No clock, no RNG, no I/O. Two
     runs over the same events produce byte-identical normalised output, which
     is what makes the seeded run reproducible end to end.

The normaliser deliberately performs ONE derived normalisation beyond field
copying: `boundary_class`, which collapses the raw trust boundary into
`internal` vs `crossing`. That is a generic trust-boundary observable (does
this step leave the internal boundary?) and is applied uniformly to every
event, with no reference to any particular action, domain or rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

BOUNDARY_INTERNAL = "internal"
BOUNDARY_CROSSING = "crossing"

# The closed schema. Every key an LB-0 trace event may carry.
ALLOWED_EVENT_KEYS = frozenset({
    "trace_id", "sequence_id", "step_index", "timestamp", "environment",
    "provider", "region", "session_tag", "actor_id", "identity_id",
    "capability", "action", "resource", "domain", "trust_boundary",
    "permission_scope", "policy_decision", "execution_outcome",
    "trajectory_outcome", "existing_ontology_labels", "provenance",
})

# Without these the event cannot be placed in a trajectory or evaluated at all.
REQUIRED_EVENT_KEYS = frozenset({
    "trace_id", "sequence_id", "step_index", "capability", "action",
    "domain", "trust_boundary", "identity_id", "permission_scope",
    "policy_decision", "execution_outcome", "resource",
})

_VALID_DECISIONS = frozenset({"allow", "escalate", "block"})
_VALID_OUTCOMES = frozenset({"success", "failure", "not_executed"})
_VALID_TRAJECTORY_OUTCOMES = frozenset({"safe", "unsafe", ""})


class MalformedTraceError(ValueError):
    """Raised when an event cannot be trusted as evidence.

    LB-0 rejects rather than repairs. A repaired event is an invented event,
    and an experiment whose inputs are partly invented cannot support a claim
    about what was discovered.
    """


@dataclass(frozen=True)
class NormalisedEvent:
    """One governed step, normalised. Immutable by construction."""

    trace_id: str
    sequence_id: str
    step_index: int
    capability: str
    action: str
    domain: str
    trust_boundary: str
    identity_id: str
    resource: str
    permission_scope: tuple
    policy_decision: str
    execution_outcome: str
    actor_id: str = ""
    timestamp: str = ""
    environment: str = ""
    provider: str = ""
    region: str = ""
    session_tag: str = ""
    trajectory_outcome: str = ""
    existing_ontology_labels: tuple = ()
    provenance: dict = field(default_factory=dict)

    # ── generic derived observables ──────────────────────────
    @property
    def boundary_class(self) -> str:
        """`internal` or `crossing` — does this step leave the trust boundary?

        Uniform over every event and independent of action semantics. Raw
        `trust_boundary` remains available; this only removes the distinction
        between the several ways of being outside.
        """
        return (BOUNDARY_INTERNAL if self.trust_boundary == BOUNDARY_INTERNAL
                else BOUNDARY_CROSSING)

    @property
    def subject(self) -> str:
        """The resource's subject identifier — the part after the last '/'.

        Resource strings are `type/subject` (`customer/cust_00042`,
        `payee/cust_00042`). The subject is what lets a generic feature ask
        whether two steps touched the same underlying thing, without the
        feature having to know what any particular resource type means.
        """
        return self.resource.rsplit("/", 1)[-1] if self.resource else ""

    @property
    def resource_type(self) -> str:
        return self.resource.rsplit("/", 1)[0] if "/" in self.resource else ""

    @property
    def token(self) -> str:
        """The step's structural token: capability @ domain @ boundary class.

        This is the alphabet the ordering features are written over. It is
        derived mechanically from three observable fields — it encodes no
        knowledge of which combinations matter.
        """
        return f"{self.capability}@{self.domain}@{self.boundary_class}"

    def as_dict(self) -> dict:
        return {
            "trace_id": self.trace_id, "sequence_id": self.sequence_id,
            "step_index": self.step_index, "timestamp": self.timestamp,
            "environment": self.environment, "provider": self.provider,
            "region": self.region, "session_tag": self.session_tag,
            "actor_id": self.actor_id, "identity_id": self.identity_id,
            "capability": self.capability, "action": self.action,
            "resource": self.resource, "domain": self.domain,
            "trust_boundary": self.trust_boundary,
            "permission_scope": list(self.permission_scope),
            "policy_decision": self.policy_decision,
            "execution_outcome": self.execution_outcome,
            "trajectory_outcome": self.trajectory_outcome,
            "existing_ontology_labels": list(self.existing_ontology_labels),
            "provenance": dict(self.provenance),
        }


def _require_str(raw: Mapping, key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise MalformedTraceError(
            f"event field {key!r} must be a non-empty string, got {value!r}")
    return value


def normalise_event(raw: Any) -> NormalisedEvent:
    """Validate and normalise one raw trace event.

    Raises `MalformedTraceError` on anything that cannot be trusted. The caller
    decides whether to skip or abort; `read_events` aborts, because a dataset
    with silently dropped steps is a dataset whose trajectories are wrong.
    """
    if not isinstance(raw, Mapping):
        raise MalformedTraceError(
            f"trace event must be a mapping, got {type(raw).__name__}")

    unknown = sorted(set(map(str, raw.keys())) - ALLOWED_EVENT_KEYS)
    if unknown:
        raise MalformedTraceError(
            "trace event carries keys outside the closed LB-0 schema: {}. "
            "Unknown keys are rejected rather than dropped: an out-of-schema "
            "annotation reaching the discovery layer would turn this "
            "experiment into a retrieval test.".format(unknown))

    missing = sorted(REQUIRED_EVENT_KEYS - set(map(str, raw.keys())))
    if missing:
        raise MalformedTraceError(
            f"trace event is missing required fields: {missing}")

    step_index = raw.get("step_index")
    if not isinstance(step_index, int) or isinstance(step_index, bool) or step_index < 0:
        raise MalformedTraceError(
            f"step_index must be a non-negative int, got {step_index!r}")

    scope = raw.get("permission_scope")
    if not isinstance(scope, (list, tuple)) or not all(isinstance(s, str) for s in scope):
        raise MalformedTraceError(
            f"permission_scope must be a list of strings, got {scope!r}")

    decision = _require_str(raw, "policy_decision")
    if decision not in _VALID_DECISIONS:
        raise MalformedTraceError(
            f"policy_decision {decision!r} is not one of {sorted(_VALID_DECISIONS)}")

    outcome = _require_str(raw, "execution_outcome")
    if outcome not in _VALID_OUTCOMES:
        raise MalformedTraceError(
            f"execution_outcome {outcome!r} is not one of {sorted(_VALID_OUTCOMES)}")

    trajectory_outcome = raw.get("trajectory_outcome", "") or ""
    if trajectory_outcome not in _VALID_TRAJECTORY_OUTCOMES:
        raise MalformedTraceError(
            "trajectory_outcome {!r} is not one of {}".format(
                trajectory_outcome, sorted(_VALID_TRAJECTORY_OUTCOMES)))

    labels = raw.get("existing_ontology_labels", ()) or ()
    if not isinstance(labels, (list, tuple)) or not all(isinstance(s, str) for s in labels):
        raise MalformedTraceError(
            f"existing_ontology_labels must be a list of strings, got {labels!r}")

    provenance = raw.get("provenance", {}) or {}
    if not isinstance(provenance, Mapping):
        raise MalformedTraceError(
            f"provenance must be a mapping, got {provenance!r}")

    return NormalisedEvent(
        trace_id=_require_str(raw, "trace_id"),
        sequence_id=_require_str(raw, "sequence_id"),
        step_index=step_index,
        capability=_require_str(raw, "capability"),
        action=_require_str(raw, "action"),
        domain=_require_str(raw, "domain"),
        trust_boundary=_require_str(raw, "trust_boundary"),
        identity_id=_require_str(raw, "identity_id"),
        resource=_require_str(raw, "resource"),
        permission_scope=tuple(sorted(scope)),
        policy_decision=decision,
        execution_outcome=outcome,
        actor_id=str(raw.get("actor_id", "") or ""),
        timestamp=str(raw.get("timestamp", "") or ""),
        environment=str(raw.get("environment", "") or ""),
        provider=str(raw.get("provider", "") or ""),
        region=str(raw.get("region", "") or ""),
        session_tag=str(raw.get("session_tag", "") or ""),
        trajectory_outcome=trajectory_outcome,
        existing_ontology_labels=tuple(labels),
        provenance=dict(provenance),
    )


def normalise_events(rows: Any, source: str | None = None) -> list:
    """Normalise an iterable of raw events, preserving input order."""
    out = []
    for index, row in enumerate(rows):
        try:
            out.append(normalise_event(row))
        except MalformedTraceError as exc:
            where = f" in {source}" if source else ""
            raise MalformedTraceError(
                f"event {index}{where}: {exc}") from exc
    return out
