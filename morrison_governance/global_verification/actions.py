"""Finite deterministic action definitions for verification environments."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict

from .state import VerificationState


Precondition = Callable[[VerificationState], bool]
Transition = Callable[[VerificationState], VerificationState]
ProposalFactory = Callable[[VerificationState], Dict[str, Any]]


@dataclass(frozen=True)
class ActionDefinition:
    """An action with explicit availability, tool representation and semantics."""

    name: str
    description: str
    consequences: tuple[str, ...]
    precondition: Precondition = field(compare=False, repr=False)
    transition: Transition = field(compare=False, repr=False)
    proposal_factory: ProposalFactory = field(compare=False, repr=False)
    version: str = "1.0"
    repeatable: bool = False

    def available(self, state: VerificationState) -> bool:
        if not self.repeatable and self.name in state.actions_completed:
            return False
        return bool(self.precondition(state))

    def propose(self, state: VerificationState) -> dict[str, Any]:
        proposal = self.proposal_factory(state)
        if not isinstance(proposal, dict) or not isinstance(proposal.get("tool"), str):
            raise ValueError(f"action {self.name!r} produced an invalid tool proposal")
        if "args" not in proposal:
            proposal = {**proposal, "args": {}}
        return proposal

    def apply(self, state: VerificationState) -> VerificationState:
        successor = self.transition(state)
        if not isinstance(successor, VerificationState):
            raise TypeError(f"action {self.name!r} did not return VerificationState")
        completed = successor.actions_completed | {self.name}
        return successor.evolve(actions_completed=completed)

    def definition(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "consequences": list(self.consequences),
            "version": self.version,
            "repeatable": self.repeatable,
        }


def proposal(tool: str, args: dict[str, Any], *, awareness: str = "") -> ProposalFactory:
    """Build a deterministic structured proposal factory.

    Awareness metadata is deliberately non-authoritative. It survives in graph
    evidence but Morrison independently determines execution authority.
    """

    def build(_: VerificationState) -> dict[str, Any]:
        call: dict[str, Any] = {"tool": tool, "args": dict(args)}
        if awareness:
            call["planner_metadata"] = {
                "constraint_awareness": True,
                "statement": awareness,
            }
        return call

    return build


def add_to(field_name: str, value: str) -> Transition:
    def transition(state: VerificationState) -> VerificationState:
        current = getattr(state, field_name)
        return state.evolve(**{field_name: current | {value}})

    return transition
