"""Bounded deterministic environment contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .actions import ActionDefinition
from .liveness import LivenessGoal
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
    # Legitimate goal states this model exists to reach (see liveness.py). A
    # model with none must say why in `adversarial_only`, so "safe because
    # nothing can happen" is visible rather than silent.
    goals: tuple[LivenessGoal, ...] = ()
    adversarial_only: str = ""

    def __post_init__(self) -> None:
        if not self.initial_states:
            raise ValueError("X0 must contain at least one admissible initial state")
        action_names = [action.name for action in self.actions]
        if len(action_names) != len(set(action_names)):
            raise ValueError("action names must be unique within an environment")
        invariant_ids = [item.identifier for item in self.unsafe_invariants]
        if len(invariant_ids) != len(set(invariant_ids)):
            raise ValueError("unsafe invariant identifiers must be unique")
        goal_ids = [item.identifier for item in self.goals]
        if len(goal_ids) != len(set(goal_ids)):
            raise ValueError("liveness goal identifiers must be unique")

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

    def goals_met(self, state: VerificationState) -> tuple[LivenessGoal, ...]:
        """Goals a state satisfies LEGITIMATELY: an unsafe state completes no
        goal, however much of the goal predicate it satisfies."""
        if not self.goals or self.unsafe(state):
            return ()
        return tuple(goal for goal in self.goals if goal.evaluate(state))

    def definition(self) -> dict[str, Any]:
        liveness: dict[str, Any] = {}
        if self.goals:
            liveness["goals"] = [goal.definition() for goal in self.goals]
        if self.adversarial_only:
            liveness["adversarial_only"] = self.adversarial_only
        definition = {
            "name": self.name,
            "version": self.version,
            "initial_states": [s.to_dict() for s in self.initial_states],
            "actions": [action.definition() for action in self.actions],
            "unsafe_invariants": [item.definition() for item in self.unsafe_invariants],
            "assumptions": list(self.assumptions),
            "limitations": list(self.limitations),
            "perturbation": self.perturbation,
        }
        definition.update(liveness)
        return definition

    @property
    def model_hash(self) -> str:
        return stable_hash(self.definition())

