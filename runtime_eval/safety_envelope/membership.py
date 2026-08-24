"""Conservative membership checks: uncovered changes never inherit claims."""

from __future__ import annotations

from .models import (
    MembershipResult, MembershipStatus, OperatingConditions, SafetyEnvelope,
)


def _missing(name: str, value) -> tuple[str, ...]:
    return (name,) if value is None or value == () or value == "" else ()


def classify_membership(envelope: SafetyEnvelope,
                        current: OperatingConditions) -> MembershipResult:
    missing = []
    for name, declared, observed in (
        ("canonical_ruleset_hash", envelope.canonical_ruleset_hash,
         current.canonical_ruleset_hash),
        ("policy_hash", envelope.policy_hash, current.policy_hash),
        ("omega_hash", envelope.omega_hash, current.omega_hash),
        ("model_planners", envelope.model_planner_set,
         current.model_planners),
        ("tools", envelope.tool_set, current.tools),
        ("permission_configuration", envelope.permission_configuration,
         current.permission_configuration),
        ("trust_boundary_configuration",
         envelope.trust_boundary_configuration,
         current.trust_boundary_configuration),
        ("agent_count", envelope.agent_counts, current.agent_count),
        ("execution_mode", envelope.execution_modes,
         current.execution_mode),
        ("trajectory_horizon", envelope.trajectory_horizon,
         current.trajectory_horizon),
        ("scenario_family", envelope.scenario_families,
         current.scenario_family),
    ):
        missing.extend(_missing(f"declared:{name}", declared))
        missing.extend(_missing(f"observed:{name}", observed))
    if not current.source_hashes or not current.provenance:
        missing.append("observed:provenance")
    if not envelope.source_hashes or not envelope.provenance:
        missing.append("declared:provenance")
    if missing:
        return MembershipResult(
            MembershipStatus.INSUFFICIENT_EVIDENCE, None, (),
            tuple(sorted(set(missing))))

    changes = []
    if current.canonical_ruleset_hash != envelope.canonical_ruleset_hash:
        changes.append("canonical ruleset hash changed")
    if current.policy_hash != envelope.policy_hash:
        changes.append("policy hash changed")
    if current.omega_hash != envelope.omega_hash:
        changes.append("Omega definition hash changed")
    if not set(current.model_planners).issubset(envelope.model_planner_set):
        changes.append("untested model/planner introduced")
    if not set(current.tools).issubset(envelope.tool_set):
        changes.append("new tool introduced")
    if not set(current.capabilities).issubset(envelope.capability_set):
        changes.append("new capability introduced")
    if current.permission_configuration != envelope.permission_configuration:
        changes.append("permission configuration changed")
    if (current.trust_boundary_configuration !=
            envelope.trust_boundary_configuration):
        changes.append("trust-boundary configuration changed")
    if current.agent_count not in envelope.agent_counts:
        changes.append("agent count is not covered")
    if (current.execution_mode is not None and
            current.execution_mode not in envelope.execution_modes):
        changes.append("execution mode is not covered")
    if current.trajectory_horizon > envelope.trajectory_horizon:
        changes.append("trajectory horizon exceeds tested horizon")
    if current.scenario_family not in envelope.scenario_families:
        changes.append("scenario family is not covered")
    if (current.perturbation_family is not None and
            current.perturbation_family not in envelope.perturbation_families):
        changes.append("perturbation family is not covered")
    if not set(current.connector_environment_identifiers).issubset(
            envelope.connector_environment_identifiers):
        changes.append("connector/environment identifier is not covered")
    if ("external" in current.destination_classifications and
            not any("external" in item.lower()
                    for item in envelope.network_assumptions)):
        changes.append("external destination is not covered")

    if changes:
        return MembershipResult(MembershipStatus.OUTSIDE, False,
                                tuple(sorted(set(changes))), ())
    return MembershipResult(MembershipStatus.INSIDE, True, (), ())
