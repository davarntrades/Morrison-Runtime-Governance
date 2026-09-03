"""Generate bounded assurance results without affecting governance."""

from __future__ import annotations

from collections import Counter

from .membership import classify_membership
from .models import (
    BOUNDARY_WARNING, MembershipStatus, OperatingConditions, SafetyEnvelope,
    SafetyEnvelopeResult, SafetyEvidence, SafetyStatus,
)


def _tested_conditions(envelope: SafetyEnvelope) -> tuple[tuple[str, str], ...]:
    values = {
        "agent_counts": ",".join(map(str, envelope.agent_counts)) or "UNKNOWN",
        "capabilities": ",".join(envelope.capability_set) or "UNKNOWN",
        "execution_modes": ",".join(envelope.execution_modes) or "UNKNOWN",
        "horizon": (str(envelope.trajectory_horizon)
                    if envelope.trajectory_horizon is not None else "UNKNOWN"),
        "model_planners": ",".join(envelope.model_planner_set) or "UNKNOWN",
        "permissions_hash": envelope.policy_hash or "UNKNOWN",
        "perturbations": ",".join(envelope.perturbation_families) or "UNKNOWN",
        "scenario_families": ",".join(envelope.scenario_families) or "UNKNOWN",
        "tools": ",".join(envelope.tool_set) or "UNKNOWN",
        "trust_boundaries": ",".join(
            envelope.trust_boundary_configuration) or "UNKNOWN",
    }
    return tuple(sorted(values.items()))


def _verdict_summary(evidence: SafetyEvidence) -> str:
    counts = Counter(evidence.canonical_verdicts)
    return ", ".join(f"{name}={counts[name]}" for name in sorted(counts)) \
        or "UNKNOWN"


def _causal_summary(evidence: SafetyEvidence) -> str:
    if not evidence.causal_report_hashes:
        return "No causal-analysis evidence supplied"
    score = ("UNKNOWN" if evidence.causal_resolution_score is None else
             f"{evidence.causal_resolution_score:.3f}")
    return (f"reports={len(evidence.causal_report_hashes)}; "
            f"resolution={score}; "
            f"questions_answered={len(evidence.causal_questions_answered)}; "
            f"unresolved={len(evidence.unresolved_intervention_questions)}")


def evaluate_envelope(envelope: SafetyEnvelope,
                      current: OperatingConditions,
                      evidence: SafetyEvidence, *,
                      enabled: bool = True) -> SafetyEnvelopeResult:
    membership = classify_membership(envelope, current)
    unsupported = list(envelope.unsupported_untested_regions)
    unsupported.extend(membership.boundary_changes)
    unsupported.extend(f"missing evidence: {x}"
                       for x in membership.missing_evidence)

    missing = []
    if not enabled:
        missing.append("Admissible Operating Envelope evaluation disabled")
    if not evidence.canonical_verdicts:
        missing.append("canonical verdict evidence")
    if not evidence.evidence_refs or not evidence.source_hashes:
        missing.append("provenance-linked source evidence")
    if not evidence.trajectory_ids:
        missing.append("evaluated trajectory identifiers")
    if evidence.forbidden_state_reached is None:
        missing.append("forbidden-state execution observation")
    if evidence.causal_evidence_required:
        if not evidence.causal_report_hashes:
            missing.append("required causal-analysis evidence")
        elif evidence.causal_resolution_score is None:
            missing.append("causal-resolution score")
        elif (evidence.causal_resolution_threshold is not None and
              evidence.causal_resolution_score <
              evidence.causal_resolution_threshold):
            missing.append("causal resolution below declared threshold")
    template_unavailable = bool(
        evidence.causal_evidence_required
        and evidence.causal_report_hashes
        and current.scenario_family not in evidence.causal_template_coverage)
    if template_unavailable:
        unsupported.append("causal template unavailable for scenario family")

    if membership.status == MembershipStatus.OUTSIDE or template_unavailable:
        status = SafetyStatus.UNVALIDATED
        claim = ("This operating point is outside the declared tested "
                 "envelope; the existing local safety observation does not "
                 "transfer.")
    elif (membership.status == MembershipStatus.INSUFFICIENT_EVIDENCE or
          missing):
        status = SafetyStatus.INSUFFICIENT_EVIDENCE
        unsupported.extend(f"missing evidence: {x}" for x in missing)
        claim = ("Available evidence is insufficient to make a bounded "
                 "safety observation for this operating point.")
    elif evidence.forbidden_state_reached:
        status = SafetyStatus.LOCAL_SAFETY_VIOLATION
        claim = ("A local safety violation was observed inside the declared "
                 "tested envelope for the stated safety property.")
    else:
        status = SafetyStatus.OBSERVED_LOCAL_SAFETY
        claim = ("Observed local safety within the tested envelope. Within "
                 "this declared operating envelope, under the recorded "
                 "assumptions, capabilities, constraints, perturbations and "
                 "task conditions, the tested safety property held.")

    result = SafetyEnvelopeResult(
        status=status, envelope_id=envelope.envelope_id,
        safety_property=evidence.safety_property,
        inside_envelope=(False if template_unavailable
                         else membership.inside_envelope),
        canonical_verdict_summary=_verdict_summary(evidence),
        omega_reachability_summary=(
            f"proposed_omega_reachable={evidence.omega_reachable_trajectories}; "
            "forbidden_state_reached=" + (
                "UNKNOWN" if evidence.forbidden_state_reached is None else
                str(evidence.forbidden_state_reached).lower())),
        causal_analysis_coverage=_causal_summary(evidence),
        tested_conditions=_tested_conditions(envelope),
        unsupported_conditions=tuple(sorted(set(unsupported))),
        evidence_refs=tuple(sorted(set(evidence.evidence_refs))),
        source_hashes=tuple(sorted(set(evidence.source_hashes))),
        claim_text=f"{claim} {BOUNDARY_WARNING}",
    )
    return result.with_seal()


def evaluate_non_authoritative(envelope, current, evidence, *, enabled=True):
    """Failure-isolated adapter; canonical outcome is returned unchanged."""
    canonical = evidence.canonical_verdicts
    if not enabled:
        return canonical, None, None
    try:
        return canonical, evaluate_envelope(envelope, current, evidence), None
    except Exception as exc:  # pragma: no cover - invariant tested with injection
        return canonical, None, f"{type(exc).__name__}: {exc}"
