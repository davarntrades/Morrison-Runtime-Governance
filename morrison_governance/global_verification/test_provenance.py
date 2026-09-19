"""Provenance and artifact-integrity tests for finite-model verification.

The property under test is not "the model is safe". It is that a reviewer who
does not trust the run can still tell what was enumerated, under which ruleset,
by which code, and whether the document in front of them has been edited.
"""

from __future__ import annotations

import copy

from .comparison import compare_control_and_governed
from .evidence import build_verification_artifact, transition_relation_id
from .governance import MorrisonKernelAdapter
from .provenance import (
    ARTIFACT_SCHEMA,
    VerificationEvidenceLedger,
    artifact_digest,
    validate_verification_artifact,
    verification_identity,
    verifier_identity,
)
from .scenarios import secret_exfiltration
from .test_escalation_enumeration import APPROVE_AND_DENY, approval_gated_privilege
from .verifier import (
    ESCALATION_APPROVE,
    ESCALATION_DENY,
    ExhaustiveVerifier,
    VerificationLimits,
)


def _run(environment=None, policy=None):
    environment = environment or approval_gated_privilege()
    ledger = VerificationEvidenceLedger()
    governance = MorrisonKernelAdapter(ledger=ledger)
    limits = VerificationLimits()
    comparison = compare_control_and_governed(
        environment, governance, limits=limits, escalation_policy=policy
    )
    artifact = build_verification_artifact(
        environment, governance, comparison,
        algorithm="bfs", limits=limits, ledger=ledger,
    )
    return environment, governance, comparison, ledger, artifact


# ── provenance content ───────────────────────────────────────────────────────

def test_artifact_carries_every_required_provenance_field():
    _, governance, _, _, artifact = _run(policy=APPROVE_AND_DENY)
    assert artifact["schema_version"] == ARTIFACT_SCHEMA
    assert artifact["verification_id"].startswith("gsv-")

    verifier = artifact["verifier"]
    assert verifier["verifier_version"]
    assert "repository_commit" in verifier      # may be None outside a checkout
    assert verifier["python"]

    environment = artifact["environment"]
    for key in ("name", "version", "model_hash", "transition_relation_id"):
        assert environment[key], key
    assert artifact["governance"]["ruleset_hash"] == governance.configuration_hash

    assert artifact["initial_state_set"]
    assert artifact["action_space"]["definitions"]
    assert artifact["prohibited_states"]
    assert artifact["traversal"]["algorithm"] == "bfs"
    assert artifact["traversal"]["limits"]["max_states"]
    assert artifact["traversal"]["complete_enumeration"] is True
    assert artifact["finite_verification"]["verdict"]
    assert artifact["assumptions"] and artifact["limitations"]
    assert artifact["control_comparison"]["governed"]["graph"]["edges"]
    assert artifact["artifact_integrity"]["artifact_hash"]
    assert artifact["artifact_integrity"]["model_digest"]


def test_artifact_keeps_the_evidence_classes_separate():
    _, _, _, _, artifact = _run(policy=APPROVE_AND_DENY)
    # Finite-model result, kernel decisions and retained kernel evidence are
    # three different sections; none of them is an attestation.
    assert "finite_verification" in artifact
    assert "governance_decisions" in artifact
    assert "evidence_ledger" in artifact
    assert "attestation" not in artifact
    scope = artifact["finite_verification"]["scope"].lower()
    assert "not a claim about the production" in scope
    assert "universal" in scope


def test_verification_id_binds_the_escalation_policy():
    """A deny-only run and an approving run reach opposite verdicts; they must
    not share an identity."""
    _, _, denied_cmp, _, denied = _run()
    _, _, approved_cmp, _, approved = _run(policy=APPROVE_AND_DENY)
    assert denied["finite_verification"]["verdict"] != approved["finite_verification"]["verdict"]
    assert denied["verification_id"] != approved["verification_id"]
    # The MODEL is the same in both; only the run differs.
    assert denied["environment"]["model_hash"] == approved["environment"]["model_hash"]
    assert (denied["environment"]["transition_relation_id"]
            == approved["environment"]["transition_relation_id"])
    assert denied["traversal"]["escalation_outcomes_admitted"] == [ESCALATION_DENY]
    assert sorted(approved["traversal"]["escalation_outcomes_admitted"]) == sorted(
        [ESCALATION_DENY, ESCALATION_APPROVE])


# ── evidence retention ───────────────────────────────────────────────────────

def test_evidence_survives_the_branch_kernel_that_produced_it():
    _, _, comparison, ledger, artifact = _run(policy=APPROVE_AND_DENY)
    assert ledger.records, "no kernel evidence was retained"
    bindings = artifact["governance_decisions"]["edge_evidence_bindings"]
    assert bindings
    for record_hash in bindings.values():
        assert ledger.resolve(record_hash) is not None
    # Retained records are real kernel records, not verifier inventions.
    for retained in ledger.records.values():
        assert retained.record["engine_version"]
        assert retained.record["ruleset_hash"]
        assert retained.record["decision"] in {"PERMIT", "BLOCK", "ESCALATE"}


def test_branch_chains_are_kept_separate_not_spliced():
    _, _, _, ledger, artifact = _run(policy=APPROVE_AND_DENY)
    segments = ledger.chain_segments()
    assert len(segments) >= 2, "expected several branches"
    # Segments partition the retained records; nothing is concatenated into a
    # single chain, and every listed hash resolves.
    for hashes in segments.values():
        assert hashes
        for record_hash in hashes:
            assert ledger.resolve(record_hash) is not None
    note = artifact["evidence_ledger"]["retention_model"].lower()
    assert "not one chain" in note


def test_dangling_chain_linkage_is_declared_not_hidden():
    """Retained records are decisions; their predecessors are replayed prefix
    steps that are not retained. The artifact must say so rather than imply a
    verifiable chain."""
    _, _, _, ledger, artifact = _run(policy=APPROVE_AND_DENY)
    linkage = artifact["evidence_ledger"]["chain_linkage"].lower()
    assert "not a verifiable hash chain" in linkage
    assert "prev_retained=false" in linkage
    # And the per-record flag is present and honest.
    records = artifact["evidence_ledger"]["records"]
    assert records
    assert all("prev_retained" in r for r in records)
    assert any(r["prev_retained"] is False for r in records)


def test_graph_edges_trace_back_to_governance_decisions():
    _, _, comparison, _, artifact = _run(policy=APPROVE_AND_DENY)
    edges = artifact["control_comparison"]["governed"]["graph"]["edges"]
    bindings = artifact["governance_decisions"]["edge_evidence_bindings"]
    edge_ids = {e["edge_id"] for e in edges}
    assert bindings.keys() <= edge_ids
    for edge in edges:
        assert edge["governance_verdict"]
        assert edge["action_hash"], "every decided edge carries an action hash"
        assert edge["semantic_hash"], "every decided edge carries a transition hash"


def test_ledger_is_optional_and_absence_is_declared_not_faked():
    environment = approval_gated_privilege()
    governance = MorrisonKernelAdapter()          # no ledger
    limits = VerificationLimits()
    comparison = compare_control_and_governed(environment, governance, limits=limits)
    artifact = build_verification_artifact(
        environment, governance, comparison, algorithm="bfs", limits=limits)
    assert artifact["evidence_ledger"]["record_count"] == 0
    assert "no ledger" in artifact["evidence_ledger"]["retention_model"]


# ── integrity ────────────────────────────────────────────────────────────────

def test_untampered_artifact_validates():
    _, _, _, _, artifact = _run(policy=APPROVE_AND_DENY)
    result = validate_verification_artifact(artifact)
    assert result.valid, result.failures()


def test_timestamp_is_outside_the_digest():
    _, _, _, _, artifact = _run()
    before = artifact_digest(artifact)
    artifact["timestamp"] = "2099-01-01T00:00:00+00:00"
    assert artifact_digest(artifact) == before
    assert validate_verification_artifact(artifact).valid


def _fails(artifact, check: str) -> bool:
    result = validate_verification_artifact(artifact)
    return not result.valid and any(f["check"] == check for f in result.failures())


def test_tampered_verdict_is_rejected():
    _, _, _, _, artifact = _run(policy=APPROVE_AND_DENY)
    assert artifact["finite_verification"]["verdict"] == "UNSAFE_COUNTEREXAMPLE_FOUND"
    artifact["finite_verification"]["verdict"] = "SAFE_WITHIN_MODEL"
    assert _fails(artifact, "artifact_hash")
    assert _fails(artifact, "verdict_agrees_with_traversal")


def test_tampered_evidence_record_is_rejected():
    _, _, _, _, artifact = _run(policy=APPROVE_AND_DENY)
    artifact["evidence_ledger"]["records"][0]["record"]["reason"] = "edited after the fact"
    assert _fails(artifact, "retained_records_reseal")


def test_dropped_evidence_record_is_rejected():
    _, _, _, _, artifact = _run(policy=APPROVE_AND_DENY)
    artifact["evidence_ledger"]["records"].pop(0)
    assert _fails(artifact, "evidence_bindings_resolve")


def test_binding_to_a_nonexistent_edge_is_rejected():
    _, _, _, _, artifact = _run(policy=APPROVE_AND_DENY)
    bindings = artifact["governance_decisions"]["edge_evidence_bindings"]
    bindings["edge-does-not-exist"] = next(iter(bindings.values()))
    assert _fails(artifact, "bindings_reference_real_edges")


def test_understated_escalation_policy_is_rejected():
    """An artifact cannot hide that it enumerated approvals."""
    _, _, _, _, artifact = _run(policy=APPROVE_AND_DENY)
    artifact["traversal"]["escalation_outcomes_admitted"] = [ESCALATION_DENY]
    assert _fails(artifact, "escalation_admissibility_matches_graph")


def test_swapped_ruleset_hash_is_rejected():
    _, _, _, _, artifact = _run()
    artifact["governance"]["ruleset_hash"] = "0" * 64
    assert _fails(artifact, "verification_id_binds_policy")


def test_swapped_governance_section_is_rejected():
    """The declared ruleset must be the one the records were decided under."""
    _, _, _, _, artifact = _run(policy=APPROVE_AND_DENY)
    # Keep the digest consistent so only the cross-check can catch this.
    artifact["governance"]["engine_version"] = "some-other-engine"
    artifact["artifact_integrity"]["artifact_hash"] = artifact_digest(artifact)
    assert _fails(artifact, "governance_matches_evidence")


def test_declared_ruleset_matches_the_retained_records():
    _, governance, _, ledger, artifact = _run()
    assert artifact["governance"]["ruleset_hash"] == governance.configuration_hash
    for retained in ledger.records.values():
        assert retained.record["ruleset_hash"] == artifact["governance"]["ruleset_hash"]
        assert retained.record["engine_version"] == artifact["governance"]["engine_version"]


def test_forged_schema_version_is_rejected():
    _, _, _, _, artifact = _run()
    artifact["schema_version"] = "mrg.global-verification.v99"
    assert _fails(artifact, "schema_version")


# ── the fail-closed rule, at write time and at read time ─────────────────────

def test_incomplete_enumeration_cannot_be_written_as_a_safe_artifact():
    environment = secret_exfiltration()
    ledger = VerificationEvidenceLedger()
    governance = MorrisonKernelAdapter(ledger=ledger)
    limits = VerificationLimits(max_states=1, max_edges=1, max_depth=0)
    comparison = compare_control_and_governed(environment, governance, limits=limits)
    assert comparison.verdict == "INCONCLUSIVE"
    artifact = build_verification_artifact(
        environment, governance, comparison,
        algorithm="bfs", limits=limits, ledger=ledger)
    assert artifact["finite_verification"]["verdict"] == "INCONCLUSIVE"
    assert artifact["finite_verification"]["complete_enumeration"] is False
    assert validate_verification_artifact(artifact).valid


def test_builder_refuses_a_safe_verdict_on_an_incomplete_run():
    """Defence in depth: even a caller who forces the verdict cannot write it."""
    environment = secret_exfiltration()
    governance = MorrisonKernelAdapter()
    limits = VerificationLimits(max_states=1, max_edges=1, max_depth=0)
    comparison = compare_control_and_governed(environment, governance, limits=limits)
    comparison.verdict = "SAFE_WITHIN_MODEL"          # forced, not earned
    try:
        build_verification_artifact(environment, governance, comparison,
                                    algorithm="bfs", limits=limits)
    except ValueError as exc:
        assert "incomplete" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected the builder to refuse")


def test_hand_edited_safe_on_an_incomplete_artifact_is_rejected():
    environment = secret_exfiltration()
    governance = MorrisonKernelAdapter()
    limits = VerificationLimits(max_states=1, max_edges=1, max_depth=0)
    comparison = compare_control_and_governed(environment, governance, limits=limits)
    artifact = build_verification_artifact(environment, governance, comparison,
                                           algorithm="bfs", limits=limits)
    artifact["finite_verification"]["verdict"] = "SAFE_WITHIN_MODEL"
    assert _fails(artifact, "no_safe_from_incomplete")


def test_validator_states_what_it_cannot_check():
    _, _, _, _, artifact = _run()
    result = validate_verification_artifact(artifact)
    note = next(c for c in result.checks if c["check"] == "unverifiable_here")
    assert "signatures" in note["detail"].lower()
    assert "production environment" in note["detail"].lower()


def test_transition_relation_id_tracks_the_exercised_relation():
    """Two models with the same declarations but different reachable behaviour
    must not share a transition fingerprint."""
    _, _, wide, _, _ = _run(environment=secret_exfiltration())
    _, _, narrow, _, _ = _run(environment=approval_gated_privilege())
    assert transition_relation_id(wide.control) != transition_relation_id(narrow.control)
    # And it is stable for the same model across runs.
    _, _, again, _, _ = _run(environment=secret_exfiltration())
    assert transition_relation_id(wide.control) == transition_relation_id(again.control)
