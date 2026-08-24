"""Mechanistic factual-versus-counterfactual contribution comparisons."""

from __future__ import annotations

from .models import ContributionTraceEntry, CounterfactualResult


def build_contribution_trace(
        results: tuple[CounterfactualResult, ...]
        ) -> tuple[ContributionTraceEntry, ...]:
    return tuple(ContributionTraceEntry(
        variable=item.intervention.variable,
        intervention_id=item.intervention.intervention_id,
        necessary_contributor=(item.factual_omega_reachable and
                               not item.counterfactual_omega_reachable),
        sufficient_to_break_trajectory=item.prevented,
        verdict_changed=item.verdict_changed,
        omega_reachability_changed=item.omega_reachability_changed,
        first_blocked_step_change=(
            f"{item.first_blocked_step_factual}->"
            f"{item.first_blocked_step_counterfactual}"),
        responsible_layer_change=(
            f"{item.responsible_layer_factual}->"
            f"{item.responsible_layer_counterfactual}"),
        reachable_state_changes=item.reachable_state_changes,
        constraint_changes=item.constraint_changes,
        evidence_refs=item.evidence_refs,
    ) for item in results)
