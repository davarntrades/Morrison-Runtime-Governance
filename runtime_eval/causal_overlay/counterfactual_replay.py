"""Isolated full replay through the existing Morrison kernel and Ω engine."""

from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import GovernanceKernel
from morrison_governance.kernel.policy import CAPABILITY_POLICY
from morrison_governance.kernel.trust import Principal, SecurityContext
from runtime_eval.frontier.tool_schema import tool_manifest

from .models import ReplayOutcome, StepOutcome, canonical_json


_STRICTNESS = {"PERMIT": 0, "ESCALATE": 1, "ENVIRONMENT_SENSITIVE": 2,
               "NO_VALID_SOLUTION": 2, "BLOCK": 3}
_OMEGA_LAYERS = frozenset({"A_safe", "V2", "V3"})


@dataclass(frozen=True)
class ReplayConfig:
    domains: tuple[str, ...] = (
        "finance", "cybersecurity", "data_privacy", "enterprise", "compliance")
    internal_email_domains: tuple[str, ...] = ("example.invalid",)
    internal_url_hosts: tuple[str, ...] = ("simulator.invalid",)
    tool_capabilities: tuple[tuple[str, tuple[str, ...]], ...] = field(
        default_factory=lambda: tuple(sorted(
            (name, tuple(values)) for name, values in tool_manifest().items())))
    capability_policy: tuple[tuple[str, str], ...] = ()
    principal_grants: tuple[str, ...] = ()
    payment_auto_approve_max: float = 0.0
    egress_requires_approval_after_read: bool = True
    unknown_tool_policy: str = "escalate"

    def manifest(self) -> dict[str, list[str]]:
        return {name: list(values) for name, values in self.tool_capabilities}

    def policy(self) -> dict[str, str]:
        return {**CAPABILITY_POLICY, **dict(self.capability_policy)}


@dataclass(frozen=True)
class GovernedTrajectory:
    trajectory_id: str
    calls_json: tuple[str, ...]
    factual: ReplayOutcome
    source_evidence_hash: str
    config: ReplayConfig = field(default_factory=ReplayConfig)
    source_kind: str = "morrison_evidence_chain"
    scenario_hint: Optional[str] = None

    @property
    def calls(self) -> list[dict]:
        return [json.loads(item) for item in self.calls_json]


@dataclass(frozen=True)
class TransformedTrajectory:
    calls: tuple[tuple[int, str], ...]
    config: ReplayConfig

    def decoded_calls(self) -> list[tuple[int, dict]]:
        return [(idx, json.loads(raw)) for idx, raw in self.calls]


def _build_kernel(config: ReplayConfig) -> tuple[GovernanceLayer, GovernanceKernel]:
    domains = [OmegaDomain(value) for value in config.domains]
    layer = GovernanceLayer(
        domains=domains, log_all=False,
        internal_email_domains=config.internal_email_domains,
        internal_url_hosts=config.internal_url_hosts,
    )
    context = SecurityContext(
        principal=Principal(
            id="causal-replay", tenant="synthetic",
            granted_capabilities=frozenset(config.principal_grants)),
        tool_manifest=config.manifest(),
        internal_email_domains=config.internal_email_domains,
        internal_url_hosts=config.internal_url_hosts,
        unknown_tool_policy=config.unknown_tool_policy,
        policy_values={
            "capability_policy": config.policy(),
            "payment_auto_approve_max": config.payment_auto_approve_max,
            "egress_requires_approval_after_read":
                config.egress_requires_approval_after_read,
        },
    )
    return layer, GovernanceKernel(layer, context, engine_version="causal-replay")


def _omega_for_step(step, scenario_hint: Optional[str]) -> tuple[str, ...]:
    labels = []
    if step.rule:
        labels.append(step.rule)
    elif step.omega_domain:
        labels.append(step.omega_domain)
    elif step.layer in _OMEGA_LAYERS and scenario_hint:
        labels.append(scenario_hint)
    return tuple(labels)


def full_replay(transformed: TransformedTrajectory,
                scenario_hint: Optional[str] = None) -> ReplayOutcome:
    """Replay the complete transformed executable path on a fresh kernel.

    No kernel or evaluator object is shared between interventions. Removed
    actions represent a do-intervention on availability/permission; every
    remaining action is evaluated by the unchanged production path.
    """
    started = time.perf_counter()
    layer, kernel = _build_kernel(transformed.config)
    decoded = transformed.decoded_calls()
    steps: list[StepOutcome] = []
    omega: list[str] = []
    if not decoded:
        # The existing reachability evaluator accepts an empty executable plan
        # and returns PERMIT. This keeps even the zero-action counterfactual on
        # Morrison's evaluation path rather than inventing an overlay verdict.
        empty = layer.evaluate_plan([])
        return ReplayOutcome(
            verdict=empty.verdict.value, omega=(), omega_reachable=False,
            first_blocked_step=None, responsible_layer=empty.layer,
            reachable_steps=(), constraint_layers=(), steps=(),
            evidence_hashes=(),
            replay_latency_ms=(time.perf_counter() - started) * 1000.0)

    for original_step, call in decoded:
        decision = kernel.authorize(copy.deepcopy(call))
        executed = False
        if decision.permitted:
            kernel.record_remote_execution(decision)
            executed = True
        step = StepOutcome(
            original_step=original_step,
            tool=str(decision.action.get("tool", "")),
            verdict=decision.verdict, layer=decision.layer,
            rule=decision.rule, omega_domain=decision.omega_domain,
            executed=executed, action_hash=decision.action_hash,
            evidence_hash=(decision.evidence.record_hash
                           if decision.evidence else ""),
            capabilities=tuple(sorted(decision.capabilities)),
            requirement=decision.requirement,
            destination_external=bool(decision.destination.get("external")),
            authorization_approved=bool(
                decision.authorization.get("approved")),
            reason=decision.reason,
        )
        steps.append(step)
        for label in _omega_for_step(step, scenario_hint):
            if label not in omega:
                omega.append(label)

    verdict = max((s.verdict for s in steps), key=lambda v: _STRICTNESS[v])
    blocked = [s for s in steps if s.verdict != "PERMIT"]
    first = blocked[0].original_step if blocked else None
    responsible = blocked[0].layer if blocked else steps[-1].layer
    return ReplayOutcome(
        verdict=verdict,
        omega=tuple(omega),
        omega_reachable=bool(omega),
        first_blocked_step=first,
        responsible_layer=responsible,
        reachable_steps=tuple(s.original_step for s in steps if s.executed),
        constraint_layers=tuple(dict.fromkeys(
            s.layer for s in steps if s.verdict != "PERMIT")),
        steps=tuple(steps),
        evidence_hashes=tuple(s.evidence_hash for s in steps
                              if s.evidence_hash),
        replay_latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def _trajectory_hash(calls: list[dict]) -> str:
    return hashlib.sha256(canonical_json(calls).encode()).hexdigest()


def capture_governed_trajectory(
        calls: list[dict], *, trajectory_id: Optional[str] = None,
        config: Optional[ReplayConfig] = None,
        scenario_hint: Optional[str] = None) -> GovernedTrajectory:
    """Create a replay case from an actually governed trajectory."""
    cfg = config or ReplayConfig()
    calls_json = tuple(canonical_json(call) for call in calls)
    transformed = TransformedTrajectory(
        calls=tuple((i, raw) for i, raw in enumerate(calls_json)), config=cfg)
    factual = full_replay(transformed, scenario_hint=scenario_hint)
    source_hash = (factual.evidence_hashes[-1] if factual.evidence_hashes
                   else hashlib.sha256(canonical_json(
                       factual.semantic_dict()).encode()).hexdigest())
    return GovernedTrajectory(
        trajectory_id=trajectory_id or _trajectory_hash(calls),
        calls_json=calls_json, factual=factual,
        source_evidence_hash=source_hash, config=cfg,
        scenario_hint=scenario_hint)


def case_from_frontier_record(
        record: dict, *, scenario_hint: Optional[str] = None,
        config: Optional[ReplayConfig] = None) -> GovernedTrajectory:
    """Adapt an already-sealed Frontier experiment record without rerunning it.

    Counterfactuals use a fresh runtime later; the factual outcome here is
    reconstructed only from the record's canonical decision projection.
    """
    decisions = list(record.get("governance_decisions") or [])
    calls = list(record.get("model_tool_calls") or [])
    steps = []
    omega = []
    hint = scenario_hint
    for index, row in enumerate(decisions):
        proposed = row.get("proposed") or (calls[index] if index < len(calls)
                                           else {})
        metadata = row.get("metadata") or {}
        rule = row.get("rule")
        domain = row.get("omega_domain")
        layer_name = str(row.get("layer", ""))
        if rule:
            if rule not in omega:
                omega.append(rule)
        elif domain:
            if domain not in omega:
                omega.append(domain)
        elif layer_name in _OMEGA_LAYERS and hint and hint not in omega:
            omega.append(hint)
        steps.append(StepOutcome(
            original_step=index,
            tool=str(proposed.get("tool", "")),
            verdict=str(row.get("verdict", "BLOCK")),
            layer=layer_name,
            rule=rule,
            omega_domain=domain,
            executed=bool(row.get("executed")),
            action_hash=str(row.get("trajectory_hash", "")),
            evidence_hash=str(metadata.get("evidence_hash") or ""),
            capabilities=tuple(sorted(metadata.get("capabilities") or ())),
            requirement=str(metadata.get("requirement", "")),
            destination_external=bool(
                (metadata.get("destination") or {}).get("external")),
            authorization_approved=bool(
                (metadata.get("authorization") or {}).get("approved")),
            reason=str(row.get("reason", "")),
        ))
    verdict = str(record.get("final_verdict") or (
        max((s.verdict for s in steps), key=lambda v: _STRICTNESS.get(v, 3))
        if steps else "PERMIT"))
    blocked = [step for step in steps if step.verdict != "PERMIT"]
    source_hashes = tuple(record.get("morrison_evidence_hashes") or ())
    source_hash = (source_hashes[-1] if source_hashes else
                   str(record.get("experiment_record_hash") or ""))
    if not source_hash:
        raise ValueError("Frontier record has no canonical evidence hash")
    factual = ReplayOutcome(
        verdict=verdict, omega=tuple(omega), omega_reachable=bool(omega),
        first_blocked_step=(blocked[0].original_step if blocked else None),
        responsible_layer=(blocked[0].layer if blocked else
                           (steps[-1].layer if steps else "V4")),
        reachable_steps=tuple(s.original_step for s in steps if s.executed),
        constraint_layers=tuple(dict.fromkeys(
            s.layer for s in steps if s.verdict != "PERMIT")),
        steps=tuple(steps), evidence_hashes=source_hashes,
        replay_latency_ms=float(
            (record.get("latency") or {}).get("governance_ms", 0.0)),
    )
    return GovernedTrajectory(
        trajectory_id=str(record.get("trajectory_hash") or
                          record.get("run_id") or _trajectory_hash(calls)),
        calls_json=tuple(canonical_json(call) for call in calls),
        factual=factual, source_evidence_hash=source_hash,
        config=config or ReplayConfig(), source_kind="frontier_experiment_record",
        scenario_hint=hint)


def transformed_identity(case: GovernedTrajectory) -> TransformedTrajectory:
    return TransformedTrajectory(
        calls=tuple((i, raw) for i, raw in enumerate(case.calls_json)),
        config=case.config)
