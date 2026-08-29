"""Bounded deterministic environment contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .actions import ActionDefinition
from .state import VerificationState, stable_hash
from .unsafe import DEFAULT_UNSAFE_INVARIANTS, UnsafeInvariant, violated_invariants


@dataclass(frozen=True)
class FiniteEnvironment:
    name: str
    version: str
    initial_states: tuple[VerificationState, ...]
    actions: tuple[ActionDefinition, ...]
    unsafe_invariants: tuple[UnsafeInvariant, ...] = DEFAULT_UNSAFE_INVARIANTS
    assumptions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    perturbation: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.initial_states:
            raise ValueError("X0 must contain at least one admissible initial state")
        action_names = [action.name for action in self.actions]
        if len(action_names) != len(set(action_names)):
            raise ValueError("action names must be unique within an environment")
        invariant_ids = [item.identifier for item in self.unsafe_invariants]
        if len(invariant_ids) != len(set(invariant_ids)):
            raise ValueError("unsafe invariant identifiers must be unique")

    def available_actions(self, state: VerificationState) -> tuple[ActionDefinition, ...]:
        return tuple(action for action in self.actions if action.available(state))

    def transition(
        self, state: VerificationState, action: ActionDefinition
    ) -> VerificationState:
        if action not in self.actions:
            raise ValueError(f"action {action.name!r} is outside this model")
        if not action.available(state):
            raise ValueError(f"action {action.name!r} preconditions are not satisfied")
        return action.apply(state)

    def unsafe(self, state: VerificationState) -> tuple[UnsafeInvariant, ...]:
        return violated_invariants(state, self.unsafe_invariants)

    def definition(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "initial_states": [s.to_dict() for s in self.initial_states],
            "actions": [action.definition() for action in self.actions],
            "unsafe_invariants": [item.definition() for item in self.unsafe_invariants],
            "assumptions": list(self.assumptions),
            "limitations": list(self.limitations),
            "perturbation": self.perturbation,
        }

    @property
    def model_hash(self) -> str:
        return stable_hash(self.definition())

