"""Sealing, provenance, and explicit-unknown tests."""

from __future__ import annotations

from dataclasses import replace

from runtime_eval.safety_envelope import (
    EvidenceCoverage, EvaluationManifest, SafetyEvidence, SafetyStatus,
    build_envelope, build_evidence_package, conditions_from_envelope,
    evaluate_envelope,
)
from runtime_eval.causal_overlay import capture_governed_trajectory


def _objects():
    case = capture_governed_trajectory(
        [{"tool": "read_account", "args": {}}],
        trajectory_id="evidence-control")
    manifest = EvaluationManifest(
        model_planner_set=("deterministic/model",), agent_counts=(1,),
        execution_modes=("shadow",), trajectory_horizon=8,
        scenario_families=("clean_control",),
        perturbation_families=("semantic_mutation",),
        evidence_coverage=EvidenceCoverage(
            trajectories_evaluated=1, baseline_cases=1, denominator=1),
        timestamp="2026-08-20T00:00:00Z",
        unsupported_untested_regions=("unseen models",),
        provenance=("manifest:clean-control",),
    )
    envelope = build_envelope(case, manifest)
    conditions = conditions_from_envelope(envelope)
    evidence = SafetyEvidence(
        safety_property="No forbidden state reached execution",
        canonical_verdicts=(case.factual.verdict,),
        omega_reachable_trajectories=0, forbidden_state_reached=False,
        trajectory_ids=(case.trajectory_id,),
        evidence_refs=(case.source_evidence_hash,),
        source_hashes=(case.source_evidence_hash,),
    )
    result = evaluate_envelope(envelope, conditions, evidence)
    return case, envelope, evidence, result


def test_envelope_evidence_is_provenance_linked():
    case, envelope, evidence, result = _objects()
    package = build_evidence_package(
        envelope, result, evidence, test_results=("1 passed",),
        replay_results=("canonical full replay",))
    assert case.source_evidence_hash in envelope.source_hashes
    assert case.source_evidence_hash in result.source_hashes
    assert case.source_evidence_hash in package.provenance


def test_evidence_package_is_deterministic_and_replayable():
    _, envelope, evidence, result = _objects()
    first = build_evidence_package(envelope, result, evidence,
                                   test_results=("1 passed",))
    second = build_evidence_package(envelope, result, evidence,
                                    test_results=("1 passed",))
    assert first == second
    assert first.package_hash == second.package_hash
    assert first.deterministic_json() == second.deterministic_json()


def test_unknown_required_envelope_field_is_not_fabricated():
    _, envelope, _, result = _objects()
    assert envelope.allowed_state_definition is None
    assert envelope.forbidden_state_definition is None
    assert result.status == SafetyStatus.OBSERVED_LOCAL_SAFETY


def test_missing_membership_provenance_is_insufficient():
    _, envelope, _, result = _objects()
    conditions = replace(conditions_from_envelope(envelope), provenance=())
    evidence = SafetyEvidence(
        safety_property=result.safety_property,
        canonical_verdicts=("PERMIT",), omega_reachable_trajectories=0,
        forbidden_state_reached=False, trajectory_ids=("one",),
        evidence_refs=("ref",), source_hashes=("hash",))
    new_result = evaluate_envelope(envelope, conditions, evidence)
    assert new_result.status == SafetyStatus.INSUFFICIENT_EVIDENCE


def test_unknown_forbidden_state_observation_is_insufficient():
    _, envelope, evidence, _ = _objects()
    result = evaluate_envelope(
        envelope, conditions_from_envelope(envelope),
        replace(evidence, forbidden_state_reached=None))
    assert result.status == SafetyStatus.INSUFFICIENT_EVIDENCE
