"""H1 baseline: control vs governed exhaustive reachability.

Reuses Morrison's production `ExhaustiveVerifier` unchanged. Only the
governance adapter is supplied by this study.

Two governance adapters are tested, and the difference between them is the
central H1 finding:

  OracleAuthority   — decides on the ACTUAL successor state. This is the
                      idealised antecedent of H1 ("G rejects every transition
                      whose execution would enter Omega").

  MorrisonKernelAdapter — decides on the DECLARED PROPOSAL. This is what a
                      real governance boundary sees.

H1 as stated quantifies over the first. Real systems have the second.
"""

from __future__ import annotations

from typing import Any

from morrison_governance.global_verification.environment import FiniteEnvironment
from morrison_governance.global_verification.governance import GovernanceDecision
from morrison_governance.global_verification.state import VerificationState
from morrison_governance.global_verification.verifier import (
    ExhaustiveVerifier,
    VerificationLimits,
)

from .h1_model import X0, control_environment


class OracleAuthority:
    """Independent execution authority with perfect successor knowledge.

    Replays the executed prefix to recover the current state, resolves the
    proposal to its action, computes the true successor, and rejects the
    transition if that successor is in Omega.

    This is a MODEL of the H1 antecedent, not a claim that such an oracle is
    implementable. Its purpose is to establish the ceiling: what independent
    execution authority can achieve when it has perfect knowledge.
    """

    description = "successor-aware independent execution authority (oracle)"
    configuration_hash = "oracle-v1"

    def __init__(self, environment: FiniteEnvironment, initial: VerificationState = X0):
        self.environment = environment
        self.initial = initial
        self._by_proposal: dict[str, Any] = {}
        for action in environment.actions:
            key = _proposal_key(action.proposal_factory(initial))
            self._by_proposal[key] = action

    def _replay(self, history: tuple[dict[str, Any], ...]) -> VerificationState:
        state = self.initial
        for call in history:
            action = self._by_proposal.get(_proposal_key(call))
            if action is None:
                raise RuntimeError(f"unreplayable history entry: {call}")
            state = action.apply(state)
        return state

    def evaluate(
        self, executed_history: tuple[dict[str, Any], ...], proposal: dict[str, Any]
    ) -> GovernanceDecision:
        state = self._replay(executed_history)
        action = self._by_proposal.get(_proposal_key(proposal))
        if action is None:
            # Unknown proposal: fail closed.
            return GovernanceDecision(
                verdict="BLOCK", permitted=False, layer="oracle",
                reason="proposal is outside the modeled action set (fail closed)",
            )
        if not action.available(state):
            return GovernanceDecision(
                verdict="BLOCK", permitted=False, layer="oracle",
                reason="preconditions unsatisfied",
            )
        successor = action.apply(state)
        violations = self.environment.unsafe(successor)
        if violations:
            return GovernanceDecision(
                verdict="BLOCK", permitted=False, layer="oracle",
                reason="successor state is in Omega",
                rule=violations[0].identifier,
                omega_domain=violations[0].identifier,
            )
        return GovernanceDecision(
            verdict="PERMIT", permitted=True, layer="oracle",
            reason="successor state is admissible",
        )


def _proposal_key(call: dict[str, Any]) -> str:
    import json
    return json.dumps(
        {"tool": call.get("tool"), "args": call.get("args", {})},
        sort_keys=True, separators=(",", ":"),
    )


LIMITS = VerificationLimits(max_states=20_000, max_edges=200_000, max_depth=16,
                            timeout_seconds=120.0)


def run_baseline() -> dict[str, Any]:
    env = control_environment()

    control = ExhaustiveVerifier(env, None, limits=LIMITS).verify()
    governed = ExhaustiveVerifier(env, OracleAuthority(env), limits=LIMITS).verify()

    omega_control = _omega_states(env, control)
    omega_governed = _omega_states(env, governed)

    return {
        "model_hash": env.model_hash,
        "control": {
            "verdict": control.verdict,
            "complete_enumeration": control.complete,
            "reachable_states": control.reachable_state_count,
            "reachable_omega_states": len(omega_control),
            "omega_state_ids": sorted(omega_control),
            "executed_edges": control.reachable_edge_count,
            "blocked_edges": control.blocked_edge_count,
            "shortest_omega_path": control.shortest_unsafe_path,
        },
        "governed_oracle": {
            "verdict": governed.verdict,
            "complete_enumeration": governed.complete,
            "reachable_states": governed.reachable_state_count,
            "reachable_omega_states": len(omega_governed),
            "omega_state_ids": sorted(omega_governed),
            "executed_edges": governed.reachable_edge_count,
            "blocked_edges": governed.blocked_edge_count,
            "blocked_omega_edges": governed.blocked_unsafe_edge_count,
        },
        "admissible_capability_preserved": _capability(governed),
    }


def _omega_states(env: FiniteEnvironment, result) -> set[str]:
    return set(result.unsafe_state_ids)


def _capability(result) -> dict[str, Any]:
    """Which admissible actions still have an executed edge under governance."""
    executed = {e.action for e in result.graph.edges.values() if e.executed}
    from .h1_model import ADMISSIBLE_ACTION_NAMES
    return {
        "admissible_actions": sorted(ADMISSIBLE_ACTION_NAMES),
        "executed_admissible_actions": sorted(ADMISSIBLE_ACTION_NAMES & executed),
        "all_admissible_preserved": ADMISSIBLE_ACTION_NAMES <= executed,
    }
