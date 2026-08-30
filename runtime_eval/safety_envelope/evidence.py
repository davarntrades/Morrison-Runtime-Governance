"""Deterministic, replayable Admissible Operating Envelope evidence packages."""

from __future__ import annotations

from .models import (
    SafetyEnvelope, SafetyEnvelopeResult, SafetyEvidence,
    SafetyEvidencePackage,
)


def build_evidence_package(
        envelope: SafetyEnvelope, result: SafetyEnvelopeResult,
        supporting_evidence: SafetyEvidence, *,
        test_results: tuple[str, ...] = (), failures: tuple[str, ...] = (),
        replay_results: tuple[str, ...] = (),
        provenance: tuple[str, ...] = ()) -> SafetyEvidencePackage:
    package = SafetyEvidencePackage(
        safety_envelope=envelope, result=result,
        supporting_evidence=supporting_evidence,
        scenario_manifest=envelope.scenario_families,
        perturbation_manifest=envelope.perturbation_families,
        model_planner_manifest=envelope.model_planner_set,
        tool_capability_manifest=envelope.tool_capability_manifest,
        test_results=tuple(sorted(test_results)),
        failures=tuple(sorted(failures)),
        replay_results=tuple(sorted(replay_results)),
        unsupported_regions=tuple(sorted(set(
            envelope.unsupported_untested_regions
            + result.unsupported_conditions))),
        provenance=tuple(sorted(set(provenance + envelope.provenance
                                    + result.evidence_refs))),
    )
    return package.with_seal()
