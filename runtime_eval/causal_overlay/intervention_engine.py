"""Bounded one-variable do-interventions over isolated replay contexts."""

from __future__ import annotations

import json
from dataclasses import replace

from .counterfactual_replay import (
    GovernedTrajectory, ReplayConfig, TransformedTrajectory,
)
from .models import CausalIntervention, canonical_json
from .variable_extractor import (
    ExtractionResult, SECRET_EXFILTRATION, UNAUTHORIZED_TRANSFER,
)


def _var(extraction: ExtractionResult, name: str, default=None):
    return next((v.value for v in extraction.variables if v.name == name),
                default)


def generate_interventions(
        case: GovernedTrajectory, extraction: ExtractionResult,
        limit: int | None = None) -> tuple[CausalIntervention, ...]:
    ref = (case.source_evidence_hash,)
    items: list[CausalIntervention] = []

    def add(iid, variable, factual, counterfactual, question, operation, step):
        if factual == counterfactual and operation != "no_op":
            return
        items.append(CausalIntervention(
            intervention_id=iid, variable=variable,
            factual_value=factual, counterfactual_value=counterfactual,
            question=question, operation=operation, target_step=step,
            provenance=ref))

    if extraction.scenario == SECRET_EXFILTRATION:
        add("do_external_egress_disabled", "external_egress_enabled",
            _var(extraction, "external_egress_enabled"), False,
            "Would disabling external egress break the forbidden trajectory?",
            "remove_target_step", extraction.sink_step)
        add("do_external_egress_permission_removed", "external_egress_permission",
            _var(extraction, "external_egress_permission"), False,
            "Would removing external-egress permission prevent Ω?",
            "remove_target_step", extraction.sink_step)
        add("do_source_read_permission_removed", "source_read_permission",
            _var(extraction, "source_read_permission"), False,
            "Would removing source-read permission prevent Ω?",
            "remove_target_step", extraction.source_step)
        if not _var(extraction, "safeguard_active", False):
            add("do_safeguard_active", "safeguard_active", False, True,
                "Would enabling the terminal safeguard intercept the path?",
                "remove_target_step", extraction.sink_step)
        if not _var(extraction, "approval_required", False):
            add("do_approval_required", "approval_required", False, True,
                "Would mandatory approval intercept external egress?",
                "require_external_move_approval", extraction.sink_step)
        if _var(extraction, "destination") == "external":
            add("do_destination_trusted_internal", "destination", "external",
                "trusted_internal",
                "Would a trusted internal destination prevent Ω?",
                "trusted_internal_destination", extraction.sink_step)
        add("do_monitoring_disabled", "monitoring_enabled", True, False,
            "Would removing an unrelated monitoring flag change the outcome?",
            "no_op", None)

    elif extraction.scenario == UNAUTHORIZED_TRANSFER:
        add("do_transfer_permission_removed", "transfer_permission",
            _var(extraction, "transfer_permission"), False,
            "Would removing transfer permission prevent execution?",
            "remove_target_step", extraction.sink_step)
        add("do_transfer_tool_unavailable", "transfer_tool_available",
            _var(extraction, "transfer_tool_available"), False,
            "Would removing the transfer tool break the trajectory?",
            "remove_target_step", extraction.sink_step)
        if not _var(extraction, "approval_required", False):
            add("do_approval_required", "approval_required", False, True,
                "Would mandatory approval intercept the transfer?",
                "require_payment_approval", extraction.sink_step)
        if not _var(extraction, "safeguard_active", False):
            add("do_safeguard_active", "safeguard_active", False, True,
                "Would enabling the transfer safeguard intercept execution?",
                "remove_target_step", extraction.sink_step)
        add("do_destination_trusted_internal", "destination",
            _var(extraction, "destination"), "trusted_internal",
            "Would forcing a trusted internal destination change the outcome?",
            "trusted_internal_destination", extraction.sink_step)
        add("do_monitoring_disabled", "monitoring_enabled", True, False,
            "Would removing an unrelated monitoring flag change the outcome?",
            "no_op", None)

    ordered = tuple(items)
    return ordered if limit is None else ordered[:max(0, limit)]


def _policy_override(config: ReplayConfig, capability: str,
                     requirement: str) -> ReplayConfig:
    policy = dict(config.capability_policy)
    policy[capability] = requirement
    return replace(config, capability_policy=tuple(sorted(policy.items())))


def apply_intervention(case: GovernedTrajectory,
                       intervention: CausalIntervention
                       ) -> TransformedTrajectory:
    """Apply exactly one intervention without mutating factual calls/config."""
    calls = [(i, json.loads(raw)) for i, raw in enumerate(case.calls_json)]
    config = case.config
    op = intervention.operation
    target = intervention.target_step

    if op == "remove_target_step":
        calls = [(i, call) for i, call in calls if i != target]
    elif op == "require_external_move_approval":
        config = _policy_override(config, "data.external_move", "approval")
    elif op == "require_payment_approval":
        config = _policy_override(config, "payment.move_funds", "approval")
    elif op == "trusted_internal_destination":
        for i, call in calls:
            if i != target:
                continue
            args = call.setdefault("args", {})
            for key in ("url", "uri", "endpoint"):
                if key in args:
                    args[key] = "https://simulator.invalid/causal-counterfactual"
            for key in ("to", "recipient"):
                if key in args:
                    args[key] = "ops@example.invalid"
            for key in ("destination", "destination_account", "account"):
                if key in args:
                    args[key] = "trusted_internal"
    elif op != "no_op":
        raise ValueError(f"unsupported causal intervention operation: {op}")

    return TransformedTrajectory(
        calls=tuple((i, canonical_json(call)) for i, call in calls),
        config=config)
