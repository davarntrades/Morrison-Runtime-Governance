"""Deterministic construction from declared and already-governed evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from morrison_governance import GovernanceLayer, OmegaDomain, __version__
from morrison_governance.kernel import ruleset_hash, ruleset_manifest
from morrison_governance.kernel.policy import (
    CAPABILITY_POLICY, DEFAULT_POLICY_VALUES,
)
from runtime_eval.causal_overlay.causal_templates import CAUSAL_TEMPLATE_VERSION
from runtime_eval.causal_overlay.counterfactual_replay import (
    GovernedTrajectory, ReplayConfig,
)
from runtime_eval.causal_overlay.models import (
    CausalAnalysisReport, OVERLAY_VERSION,
)

from .models import (
    EvidenceCoverage, OperatingConditions, SafetyEnvelope, SafetyEvidence,
    digest,
)


@dataclass(frozen=True)
class EvaluationManifest:
    model_planner_set: tuple[str, ...] = ()
    agent_counts: tuple[int, ...] = ()
    execution_modes: tuple[str, ...] = ()
    trajectory_horizon: Optional[int] = None
    scenario_families: tuple[str, ...] = ()
    perturbation_families: tuple[str, ...] = ()
    baseline_cases: tuple[str, ...] = ()
    adversarial_cases: tuple[str, ...] = ()
    state_variable_schema: tuple[str, ...] = ()
    environmental_assumptions: tuple[str, ...] = ()
    allowed_state_definition: Optional[str] = None
    forbidden_state_definition: Optional[str] = None
    enforcement_point: Optional[str] = None
    connector_environment_identifiers: tuple[str, ...] = ()
    concurrency_assumptions: tuple[str, ...] = ()
    memory_assumptions: tuple[str, ...] = ()
    network_assumptions: tuple[str, ...] = ()
    unsupported_untested_regions: tuple[str, ...] = ()
    timestamp: Optional[str] = None
    evidence_coverage: EvidenceCoverage = EvidenceCoverage()
    provenance: tuple[str, ...] = ()


def governance_fingerprints(config: ReplayConfig) -> tuple[str, str, str]:
    """Fingerprint existing policy and Ω rules without evaluating an action."""
    layer = GovernanceLayer(
        domains=[OmegaDomain(value) for value in config.domains],
        log_all=False,
        internal_email_domains=config.internal_email_domains,
        internal_url_hosts=config.internal_url_hosts,
    )
    policy_payload = {
        "capability_policy": config.policy(),
        "payment_auto_approve_max": config.payment_auto_approve_max,
        "egress_requires_approval_after_read":
            config.egress_requires_approval_after_read,
        "unknown_tool_policy": config.unknown_tool_policy,
        "principal_grants": sorted(config.principal_grants),
    }
    policy_hash = digest(policy_payload)
    omega_hash = digest(ruleset_manifest(layer.rules))
    canonical = ruleset_hash(layer.rules, extra={
        "capability_policy": CAPABILITY_POLICY,
        "policy_values": {**DEFAULT_POLICY_VALUES, **{
            "capability_policy": config.policy(),
            "payment_auto_approve_max": config.payment_auto_approve_max,
            "egress_requires_approval_after_read":
                config.egress_requires_approval_after_read,
        }},
        "unknown_tool_policy": config.unknown_tool_policy,
    })
    return canonical, policy_hash, omega_hash


def _trust(config: ReplayConfig) -> tuple[str, ...]:
    return tuple(sorted(
        [f"internal_email_domain:{x}" for x in config.internal_email_domains]
        + [f"internal_url_host:{x}" for x in config.internal_url_hosts]))


def _capabilities(config: ReplayConfig) -> tuple[str, ...]:
    return tuple(sorted({cap for _, caps in config.tool_capabilities
                         for cap in caps}))


def _tool_capabilities(config: ReplayConfig) -> tuple[str, ...]:
    return tuple(sorted(f"{tool}:{','.join(sorted(caps))}"
                        for tool, caps in config.tool_capabilities))


def _permissions(config: ReplayConfig) -> tuple[tuple[str, str], ...]:
    entries = [(f"policy:{key}", str(value))
               for key, value in config.policy().items()]
    entries.extend((f"principal_grant:{value}", "true")
                   for value in config.principal_grants)
    return tuple(sorted(entries))


def build_envelope(
        trajectory: GovernedTrajectory, manifest: EvaluationManifest, *,
        causal_report: Optional[CausalAnalysisReport] = None) -> SafetyEnvelope:
    """Build an envelope only from declared or provenance-linked values."""
    cfg = trajectory.config
    canonical, policy_hash, omega_hash = governance_fingerprints(cfg)
    source_hashes = {trajectory.source_evidence_hash}
    if causal_report is not None:
        source_hashes.add(causal_report.artifact_hash)
    envelope = SafetyEnvelope(
        envelope_id="", governance_version=__version__,
        canonical_ruleset_hash=canonical, policy_hash=policy_hash,
        omega_hash=omega_hash,
        causal_overlay_version=(causal_report.overlay_version
                                if causal_report else OVERLAY_VERSION),
        causal_template_version=CAUSAL_TEMPLATE_VERSION,
        model_planner_set=tuple(sorted(set(manifest.model_planner_set))),
        tool_set=tuple(sorted(name for name, _ in cfg.tool_capabilities)),
        capability_set=_capabilities(cfg),
        tool_capability_manifest=_tool_capabilities(cfg),
        permission_configuration=_permissions(cfg),
        trust_boundary_configuration=_trust(cfg),
        agent_counts=tuple(sorted(set(manifest.agent_counts))),
        execution_modes=tuple(sorted(set(manifest.execution_modes))),
        trajectory_horizon=manifest.trajectory_horizon,
        scenario_families=tuple(sorted(set(manifest.scenario_families))),
        state_variable_schema=tuple(sorted(set(
            manifest.state_variable_schema))),
        environmental_assumptions=tuple(sorted(set(
            manifest.environmental_assumptions))),
        perturbation_families=tuple(sorted(set(
            manifest.perturbation_families))),
        baseline_cases=tuple(sorted(set(manifest.baseline_cases))),
        adversarial_cases=tuple(sorted(set(manifest.adversarial_cases))),
        allowed_state_definition=manifest.allowed_state_definition,
        forbidden_state_definition=manifest.forbidden_state_definition,
        enforcement_point=manifest.enforcement_point,
        connector_environment_identifiers=tuple(sorted(set(
            manifest.connector_environment_identifiers))),
        concurrency_assumptions=tuple(sorted(set(
            manifest.concurrency_assumptions))),
        memory_assumptions=tuple(sorted(set(manifest.memory_assumptions))),
        network_assumptions=tuple(sorted(set(manifest.network_assumptions))),
        evidence_coverage=manifest.evidence_coverage,
        unsupported_untested_regions=tuple(sorted(set(
            manifest.unsupported_untested_regions))),
        timestamp=manifest.timestamp,
        source_hashes=tuple(sorted(x for x in source_hashes if x)),
        provenance=tuple(sorted(set(manifest.provenance + (
            trajectory.source_evidence_hash,)))),
    )
    return envelope.with_seal()


def build_safety_evidence(
        trajectory: GovernedTrajectory, safety_property: str, *,
        causal_report: Optional[CausalAnalysisReport] = None,
        forbidden_state_reached: Optional[bool] = None,
        causal_evidence_required: bool = False,
        causal_resolution_threshold: Optional[float] = None,
        additional_verdicts: tuple[str, ...] = (),
        additional_trajectory_ids: tuple[str, ...] = ()) -> SafetyEvidence:
    """Project existing factual/causal artifacts into assurance evidence."""
    interventions = causal_report.interventions if causal_report else ()
    causal_covered = bool(causal_report and causal_report.causal_edges)
    return SafetyEvidence(
        safety_property=safety_property,
        canonical_verdicts=additional_verdicts + (trajectory.factual.verdict,),
        omega_reachable_trajectories=int(
            trajectory.factual.omega_reachable),
        forbidden_state_reached=forbidden_state_reached,
        trajectory_ids=additional_trajectory_ids + (trajectory.trajectory_id,),
        evidence_refs=(trajectory.source_evidence_hash,),
        source_hashes=(trajectory.source_evidence_hash,),
        causal_report_hashes=((causal_report.artifact_hash,)
                              if causal_report else ()),
        causal_questions_answered=tuple(
            item.intervention.question for item in interventions),
        sufficient_interventions=(causal_report.sufficient_interventions
                                  if causal_report else ()),
        ineffective_interventions=tuple(
            item.intervention.intervention_id for item in interventions
            if not item.prevented),
        causal_template_coverage=((trajectory.scenario_hint,)
                                  if causal_covered and
                                  trajectory.scenario_hint else ()),
        causal_resolution_score=(causal_report.causal_resolution_score
                                 if causal_report else None),
        causal_evidence_required=causal_evidence_required,
        causal_resolution_threshold=causal_resolution_threshold,
    )


def conditions_from_envelope(envelope: SafetyEnvelope) -> OperatingConditions:
    """Construct the identical declared operating point for replay/tests."""
    return OperatingConditions(
        canonical_ruleset_hash=envelope.canonical_ruleset_hash,
        policy_hash=envelope.policy_hash, omega_hash=envelope.omega_hash,
        model_planners=envelope.model_planner_set, tools=envelope.tool_set,
        capabilities=envelope.capability_set,
        permission_configuration=envelope.permission_configuration,
        trust_boundary_configuration=envelope.trust_boundary_configuration,
        agent_count=(envelope.agent_counts[0]
                     if len(envelope.agent_counts) == 1 else None),
        execution_mode=(envelope.execution_modes[0]
                        if len(envelope.execution_modes) == 1 else None),
        trajectory_horizon=envelope.trajectory_horizon,
        scenario_family=(envelope.scenario_families[0]
                         if len(envelope.scenario_families) == 1 else None),
        perturbation_family=(envelope.perturbation_families[0]
                             if len(envelope.perturbation_families) == 1
                             else None),
        connector_environment_identifiers=(
            envelope.connector_environment_identifiers),
        source_hashes=envelope.source_hashes,
        provenance=envelope.provenance,
    )
