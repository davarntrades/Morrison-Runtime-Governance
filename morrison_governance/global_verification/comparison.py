"""Control-versus-governed causal topology comparison."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .environment import FiniteEnvironment
from .governance import GovernanceAdapter
from .liveness import NOT_LIVE
from .verifier import (
    INCONCLUSIVE,
    SAFE_BUT_NOT_LIVE,
    SAFE_VERDICTS,
    SAFE_WITHIN_MODEL,
    UNSAFE_COUNTEREXAMPLE_FOUND,
    ExhaustiveVerifier,
    TraversalResult,
    VerificationLimits,
)


@dataclass
class ComparisonResult:
    verdict: str
    control: TraversalResult
    governed: TraversalResult
    metrics: dict[str, Any]
    removed_transitions: list[dict[str, Any]]

    def to_dict(self, *, include_graph: bool = True) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "claim": _claim(self.verdict),
            "control": self.control.to_dict(include_graph=include_graph),
            "governed": self.governed.to_dict(include_graph=include_graph),
            "causal_metrics": self.metrics,
            "removed_transitions": self.removed_transitions,
        }


@dataclass
class CompositionExperiment:
    subsystem_a: ComparisonResult
    subsystem_b: ComparisonResult
    composition: ComparisonResult
    local_safety_composed: bool
    new_unsafe_path_in_composition: bool

    def to_dict(self, *, include_graph: bool = True) -> dict[str, Any]:
        return {
            "subsystem_a": self.subsystem_a.to_dict(include_graph=include_graph),
            "subsystem_b": self.subsystem_b.to_dict(include_graph=include_graph),
            "composition": self.composition.to_dict(include_graph=include_graph),
            "safe_a_and_safe_b": self.local_safety_composed,
            "new_unsafe_path_in_composition": self.new_unsafe_path_in_composition,
            "claim": (
                "Compositionality was tested, not assumed. This finite experiment "
                "does not establish compositional safety outside these models."
            ),
        }


def compare_control_and_governed(
    environment: FiniteEnvironment,
    governance: GovernanceAdapter,
    *,
    limits: VerificationLimits | None = None,
    algorithm: str = "bfs",
    escalation_policy: Any = None,
) -> ComparisonResult:
    # The control model has no governance, so it has no escalations to resolve
    # and produces no kernel evidence to retain.
    control = ExhaustiveVerifier(
        environment, limits=limits, algorithm=algorithm
    ).verify()
    governed = ExhaustiveVerifier(
        environment, governance, limits=limits, algorithm=algorithm,
        escalation_policy=escalation_policy,
    ).verify()

    control_states = set(control.reachable_state_ids)
    governed_states = set(governed.reachable_state_ids)
    newly_unreachable = sorted(control_states - governed_states)
    removed = []
    for edge in sorted(governed.graph.edges.values(), key=lambda item: item.edge_id):
        if edge.executed:
            continue
        source = governed.graph.nodes[edge.source]
        removed.append(
            {
                "source_node_id": edge.source,
                "source_state_id": source.state_id,
                "action": edge.action,
                "proposed_action": edge.proposed_action,
                "verdict": edge.governance_verdict,
                "layer": edge.layer,
                "reason": edge.reason,
                "counterfactual_destination_state_id": edge.counterfactual_state_id,
                "counterfactual_unsafe_invariants": list(
                    edge.counterfactual_unsafe_invariants
                ),
            }
        )

    metrics = {
        "delta_reach": control.reachable_state_count - governed.reachable_state_count,
        "reachable_state_reduction": control.reachable_state_count - governed.reachable_state_count,
        "reachable_edge_reduction": control.reachable_edge_count - governed.reachable_edge_count,
        "unsafe_states_control": control.unsafe_reachable_state_count,
        "unsafe_states_governed": governed.unsafe_reachable_state_count,
        "unsafe_reachability_reduction": (
            control.unsafe_reachable_state_count - governed.unsafe_reachable_state_count
        ),
        "unsafe_reachability_eliminated": (
            control.unsafe_reachable_state_count > 0
            and governed.unsafe_reachable_state_count == 0
        ),
        "blocked_transitions": governed.blocked_edge_count,
        "blocked_unsafe_edges": governed.blocked_unsafe_edge_count,
        "approved_escalations": governed.approved_escalation_edge_count,
        "denied_escalations": governed.denied_escalation_edge_count,
        "newly_unreachable_states": newly_unreachable,
        "unsafe_shortest_path_control": control.shortest_unsafe_path,
        "unsafe_shortest_path_governed": governed.shortest_unsafe_path,
    }

    metrics["liveness"] = _liveness_comparison(control, governed)

    if not control.complete or not governed.complete:
        verdict = INCONCLUSIVE
    elif governed.unsafe_reachable_state_count:
        verdict = UNSAFE_COUNTEREXAMPLE_FOUND
    elif governed.liveness.get("status") == NOT_LIVE:
        verdict = SAFE_BUT_NOT_LIVE
    else:
        verdict = SAFE_WITHIN_MODEL
    return ComparisonResult(verdict, control, governed, metrics, removed)


def _liveness_comparison(control: TraversalResult, governed: TraversalResult) -> dict[str, Any]:
    """Attribute each unreachable goal: did governance remove it, or could the
    model never reach it at all? Only the first is a cost of governance."""
    control_goals = {g["identifier"]: g for g in control.liveness.get("goals", [])}
    out = []
    for goal in governed.liveness.get("goals", []):
        in_control = control_goals.get(goal["identifier"], {}).get(
            "reachable_from_every_initial_state")
        live = goal["reachable_from_every_initial_state"]
        out.append({
            "identifier": goal["identifier"],
            "reachable_control": in_control,
            "reachable_governed": live,
            "attribution": (
                "live" if live else
                "removed_by_governance" if in_control else
                "unreachable_in_model"),
        })
    return {"status_control": control.liveness.get("status"),
            "status_governed": governed.liveness.get("status"),
            "goals": out}


def run_composition_experiment(
    governance: GovernanceAdapter,
    *,
    limits: VerificationLimits | None = None,
    escalation_policy: Any = None,
) -> CompositionExperiment:
    from .scenarios import composed_subsystems, subsystem_a, subsystem_b

    shared = {"limits": limits, "escalation_policy": escalation_policy}
    a = compare_control_and_governed(subsystem_a(), governance, **shared)
    b = compare_control_and_governed(subsystem_b(), governance, **shared)
    composition = compare_control_and_governed(
        composed_subsystems(), governance, **shared
    )
    locals_safe = a.verdict in SAFE_VERDICTS and b.verdict in SAFE_VERDICTS
    new_path = locals_safe and composition.verdict == UNSAFE_COUNTEREXAMPLE_FOUND
    return CompositionExperiment(a, b, composition, locals_safe, new_path)


def _claim(verdict: str) -> str:
    if verdict == SAFE_WITHIN_MODEL:
        return (
            "Globally safe within the exhaustively enumerated modeled environment "
            "and stated assumptions. Result does not establish global safety "
            "outside the modeled environment."
        )
    if verdict == SAFE_BUT_NOT_LIVE:
        return (
            "No unsafe modeled state is reachable, but at least one declared "
            "legitimate goal is not reachable under governance either: the model "
            "is safe in part because legitimate work cannot complete. See "
            "causal_metrics.liveness for which goals and why."
        )
    if verdict == UNSAFE_COUNTEREXAMPLE_FOUND:
        return "An unsafe modeled state is reachable; see the counterexample trajectory."
    return (
        "No safety conclusion can be drawn because the reachable state space "
        "was not completely enumerated."
    )
