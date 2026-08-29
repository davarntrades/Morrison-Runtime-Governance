"""Shortest unsafe-trajectory evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CounterexampleStep:
    action: str
    proposed_action: dict[str, Any]
    governance_verdict: str
    governance_layer: str
    governance_reason: str
    resulting_state: dict[str, Any]
    resulting_state_id: str
    unsafe_invariants: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "proposed_action": self.proposed_action,
            "governance_verdict": self.governance_verdict,
            "governance_layer": self.governance_layer,
            "governance_reason": self.governance_reason,
            "resulting_state": self.resulting_state,
            "resulting_state_id": self.resulting_state_id,
            "unsafe_invariants": list(self.unsafe_invariants),
        }


@dataclass(frozen=True)
class Counterexample:
    initial_state: dict[str, Any]
    initial_state_id: str
    steps: tuple[CounterexampleStep, ...]
    violated_invariants: tuple[dict[str, str], ...]
    final_unsafe_state: dict[str, Any]
    final_unsafe_state_id: str

    @property
    def distance(self) -> int:
        return len(self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "initial_state": self.initial_state,
            "initial_state_id": self.initial_state_id,
            "steps": [step.to_dict() for step in self.steps],
            "violated_invariants": list(self.violated_invariants),
            "final_unsafe_state": self.final_unsafe_state,
            "final_unsafe_state_id": self.final_unsafe_state_id,
            "distance": self.distance,
        }

