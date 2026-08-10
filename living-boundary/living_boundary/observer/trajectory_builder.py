"""Group normalised events into trajectories.

A trajectory is the unit the Living Boundary reasons about, because the whole
LB-0 hypothesis is that the governing structure lives at the level of the
COMPOSITION rather than the individual action. Everything a trajectory exposes
below is a mechanical roll-up of per-event fields — no interpretation, no
scoring, no risk model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from living_boundary.observer.normalizer import (
    BOUNDARY_INTERNAL, MalformedTraceError,
)


@dataclass(frozen=True)
class NormalisedTrajectory:
    """An ordered, immutable sequence of governed steps sharing a sequence id."""

    sequence_id: str
    events: tuple

    # ── identity / provenance roll-ups ───────────────────────
    @property
    def trace_ids(self) -> tuple:
        return tuple(e.trace_id for e in self.events)

    @property
    def outcome(self) -> str:
        """The observed trajectory outcome recorded by the environment.

        This is an OBSERVATION ("what happened"), not the governing rule ("why
        it happened"). The discovery layer is supervised on this label and
        never sees the rule that produced it.
        """
        return self.events[-1].trajectory_outcome if self.events else ""

    @property
    def is_unsafe_observed(self) -> bool:
        return self.outcome == "unsafe"

    # ── structural roll-ups ──────────────────────────────────
    @property
    def tokens(self) -> tuple:
        return tuple(e.token for e in self.events)

    @property
    def capabilities(self) -> tuple:
        return tuple(e.capability for e in self.events)

    @property
    def domains(self) -> tuple:
        return tuple(e.domain for e in self.events)

    @property
    def identities(self) -> frozenset:
        return frozenset(e.identity_id for e in self.events)

    @property
    def cumulative_scope(self) -> frozenset:
        return frozenset(s for e in self.events for s in e.permission_scope)

    @property
    def subjects(self) -> frozenset:
        return frozenset(e.subject for e in self.events if e.subject)

    @property
    def boundary_transitions(self) -> tuple:
        """Consecutive (from, to) trust-boundary pairs where the boundary changes."""
        out = []
        for prev, nxt in zip(self.events, self.events[1:]):
            if prev.trust_boundary != nxt.trust_boundary:
                out.append((prev.trust_boundary, nxt.trust_boundary))
        return tuple(out)

    @property
    def crosses_trust_boundary(self) -> bool:
        return any(e.trust_boundary != BOUNDARY_INTERNAL for e in self.events)

    @property
    def all_steps_allowed(self) -> bool:
        return all(e.policy_decision == "allow" for e in self.events)

    @property
    def all_steps_executed(self) -> bool:
        return all(e.execution_outcome == "success" for e in self.events)

    @property
    def provider(self) -> str:
        return self.events[0].provider if self.events else ""

    @property
    def region(self) -> str:
        return self.events[0].region if self.events else ""

    @property
    def session_tag(self) -> str:
        return self.events[0].session_tag if self.events else ""

    def __len__(self) -> int:
        return len(self.events)

    def as_dict(self) -> dict:
        return {
            "sequence_id": self.sequence_id,
            "steps": len(self.events),
            "trace_ids": list(self.trace_ids),
            "tokens": list(self.tokens),
            "outcome": self.outcome,
            "events": [e.as_dict() for e in self.events],
        }


def build_trajectories(events, require_contiguous: bool = True) -> list:
    """Group events by `sequence_id`, ordered by `step_index`.

    Sequence ORDER of the returned list follows first appearance, so a
    deterministic input yields a deterministic dataset ordering.

    `require_contiguous` asserts the step indices of each sequence are exactly
    0..n-1. A gap means an event was lost between the runtime and here, and a
    trajectory with a missing step is not the trajectory that was executed —
    LB-0 refuses to reason about it rather than guessing what was dropped.
    """
    order: list = []
    grouped: dict = {}
    for event in events:
        if event.sequence_id not in grouped:
            grouped[event.sequence_id] = []
            order.append(event.sequence_id)
        grouped[event.sequence_id].append(event)

    trajectories = []
    for sequence_id in order:
        steps = sorted(grouped[sequence_id], key=lambda e: e.step_index)
        if require_contiguous:
            expected = list(range(len(steps)))
            actual = [e.step_index for e in steps]
            if actual != expected:
                raise MalformedTraceError(
                    "sequence {!r} has non-contiguous step indices {} (expected "
                    "{}); a trajectory missing a step is not the trajectory that "
                    "ran".format(sequence_id, actual, expected))
        outcomes = {e.trajectory_outcome for e in steps}
        if len(outcomes) > 1:
            raise MalformedTraceError(
                "sequence {!r} carries conflicting trajectory outcomes "
                "{}".format(sequence_id, sorted(outcomes)))
        trajectories.append(NormalisedTrajectory(
            sequence_id=sequence_id, events=tuple(steps)))
    return trajectories


def index_by_sequence(trajectories) -> dict:
    return {t.sequence_id: t for t in trajectories}


def find(trajectories, sequence_id: str) -> NormalisedTrajectory | None:
    for t in trajectories:
        if t.sequence_id == sequence_id:
            return t
    return None
