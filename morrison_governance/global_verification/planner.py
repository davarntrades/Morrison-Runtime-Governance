"""Deterministic worst-case planner used only as supplemental evidence."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .actions import ActionDefinition
from .environment import FiniteEnvironment
from .state import VerificationState


@dataclass(frozen=True)
class PlannedStep:
    action: str
    distance_to_unsafe_after_step: int | None


class AdversarialPlanner:
    """Choose the available action with minimum control distance to unsafe."""

    def __init__(self, environment: FiniteEnvironment):
        self.environment = environment

    def choose(self, state: VerificationState) -> ActionDefinition | None:
        choices = []
        for action in self.environment.available_actions(state):
            successor = self.environment.transition(state, action)
            distance = self.distance_to_unsafe(successor)
            choices.append((float("inf") if distance is None else distance, action.name, action))
        return min(choices, default=(None, None, None))[2]

    def distance_to_unsafe(self, start: VerificationState) -> int | None:
        if self.environment.unsafe(start):
            return 0
        queue = deque([(start, 0)])
        seen = {start}
        while queue:
            state, depth = queue.popleft()
            for action in self.environment.available_actions(state):
                successor = self.environment.transition(state, action)
                if self.environment.unsafe(successor):
                    return depth + 1
                if successor not in seen:
                    seen.add(successor)
                    queue.append((successor, depth + 1))
        return None

    def plan(self, start: VerificationState, max_steps: int = 32) -> tuple[PlannedStep, ...]:
        state = start
        steps = []
        for _ in range(max_steps):
            if self.environment.unsafe(state):
                break
            action = self.choose(state)
            if action is None:
                break
            state = self.environment.transition(state, action)
            steps.append(PlannedStep(action.name, self.distance_to_unsafe(state)))
        return tuple(steps)

