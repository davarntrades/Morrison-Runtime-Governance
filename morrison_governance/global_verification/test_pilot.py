"""Pilot binding: does a prior verification still describe this configuration?"""

from __future__ import annotations

from .comparison import compare_control_and_governed
from .evidence import build_verification_artifact
from .governance import MorrisonKernelAdapter
from .pilot import (
    REVALIDATION_REQUIRED,
    VERIFIED_CONFIGURATION_CURRENT,
    LiveConfiguration,
    PilotReadiness,
    assess_pilot_readiness,
    contract_from_artifact,
)
from .provenance import VerificationEvidenceLedger
from .scenarios import secret_exfiltration
from .verifier import VerificationLimits


# The smallest real chokepoint in the deployment: a planner proposes one call,
# Morrison decides, the caller executes only on PERMIT.
BOUNDARY = "POST /v1/evaluate-step (governance-service); execute only on PERMIT"
ENDPOINT = "https://governance.invalid/v1/evaluate-step"
TOOLS = ("access_external_network", "read_secret", "send_external_message")
PERMISSIONS = ("vault:read", "network:egress")


def _artifact(environment=None, limits=None):
    environment = environment or secret_exfiltration()
    limits = limits or VerificationLimits()
    ledger = VerificationEvidenceLedger()
    governance = MorrisonKernelAdapter(ledger=ledger)
    comparison = compare_control_and_governed(environment, governance, limits=limits)
    return build_verification_artifact(
        environment, governance, comparison,
        algorithm="bfs", limits=limits, ledger=ledger,
    )


def _contract(artifact, **overrides):
    kwargs = dict(
        pilot_id="pilot-001",
        organisation="declared-operator",
        planner_identity="deterministic/pilot-planner",
        environment_id="env-pilot-001",
        environment_description="bounded single-agent workflow, inert simulator",
        tools=TOOLS,
        permissions=PERMISSIONS,
        execution_boundary=BOUNDARY,
        governance_endpoint=ENDPOINT,
        evidence_destination="deployment evidence chain (kernel EvidenceChain)",
        horizon=3,
    )
    kwargs.update(overrides)
    return contract_from_artifact(artifact, **kwargs)


def _live(contract, **overrides):
    attestation = {
        "engine_commit": "abc123",
        "ruleset_hash": contract.ruleset_hash,
        "ruleset_hash_algorithm": "logic-binding-v2",
        "service_version": contract.engine_version,
        "horizon": contract.horizon,
    }
    attestation.update(overrides.pop("attestation", {}))
    kwargs = dict(
        tools=contract.tools,
        permissions=contract.permissions,
        environment_id=contract.environment_id,
        planner_identity=contract.planner_identity,
    )
    kwargs.update(overrides)
    return LiveConfiguration.from_attestation(attestation, **kwargs)


# ── the happy path, and what it is allowed to mean ───────────────────────────

def test_verified_configuration_permits_the_pilot_to_start():
    artifact = _artifact()
    contract = _contract(artifact)
    readiness = assess_pilot_readiness(artifact, contract, _live(contract))
    assert readiness.status == VERIFIED_CONFIGURATION_CURRENT, readiness.drifted()
    assert readiness.may_start is True
    assert not readiness.drifted()


def test_the_permitted_message_does_not_overclaim():
    artifact = _artifact()
    contract = _contract(artifact)
    readiness = assess_pilot_readiness(artifact, contract, _live(contract))
    message = readiness.operator_message.lower()
    assert "within the declared finite model" in message
    assert "not a claim about this environment" in message
    for forbidden in ("globally safe", "production safe", "universally"):
        assert forbidden not in message


def test_contract_carries_the_verification_and_the_environment_identity():
    artifact = _artifact()
    contract = _contract(artifact)
    payload = contract.to_dict()
    assert payload["verification"]["verification_id"] == artifact["verification_id"]
    assert payload["verification"]["model_hash"] == artifact["environment"]["model_hash"]
    assert payload["verification"]["artifact_hash"] == \
        artifact["artifact_integrity"]["artifact_hash"]
    assert payload["environment_identity"].startswith("env-")
    # Every contract field required by the pilot brief is present.
    for key in ("planner_identity", "environment_id", "tools", "permissions",
                "actions", "prohibited_outcomes", "execution_boundary",
                "ruleset_hash", "escalation_policy", "evidence_destination"):
        assert payload[key] not in (None, "", [])


# ── drift: every dimension the brief names ───────────────────────────────────

def _drifts_on(dimension: str, **live_overrides) -> bool:
    artifact = _artifact()
    contract = _contract(artifact)
    readiness = assess_pilot_readiness(
        artifact, contract, _live(contract, **live_overrides))
    return (readiness.status == REVALIDATION_REQUIRED
            and any(f["dimension"] == dimension for f in readiness.drifted()))


def test_changed_ruleset_marks_the_verification_stale():
    assert _drifts_on("ruleset", attestation={"ruleset_hash": "0" * 64})


def test_changed_engine_marks_the_verification_stale():
    assert _drifts_on("engine", attestation={"service_version": "other-engine"})


def test_changed_horizon_marks_the_verification_stale():
    assert _drifts_on("horizon", attestation={"horizon": 1})


def test_added_tool_marks_the_verification_stale():
    assert _drifts_on("tools", tools=TOOLS + ("execute_code",))


def test_changed_permissions_mark_the_verification_stale():
    assert _drifts_on("permissions", permissions=PERMISSIONS + ("iam:admin",))


def test_changed_environment_marks_the_verification_stale():
    assert _drifts_on("environment", environment_id="env-something-else")


def test_changed_planner_is_recorded_as_drift():
    assert _drifts_on("planner", planner_identity="some-other-planner")


def test_changed_model_marks_the_verification_stale():
    artifact = _artifact()
    contract = _contract(artifact)
    swapped = dict(contract.__dict__)
    swapped["model_hash"] = "0" * 64
    from .pilot import PilotContract
    readiness = assess_pilot_readiness(
        artifact, PilotContract(**swapped), _live(contract))
    assert readiness.status == REVALIDATION_REQUIRED
    assert any(f["dimension"] == "model" for f in readiness.drifted())


def test_changed_transition_semantics_mark_the_verification_stale():
    artifact = _artifact()
    contract = _contract(artifact)
    from .pilot import PilotContract
    swapped = dict(contract.__dict__)
    swapped["transition_relation_id"] = "0" * 64
    readiness = assess_pilot_readiness(
        artifact, PilotContract(**swapped), _live(contract))
    assert any(f["dimension"] == "transition_semantics" for f in readiness.drifted())


def test_action_space_narrower_than_the_model_is_drift():
    artifact = _artifact()
    contract = _contract(artifact)
    from .pilot import PilotContract
    swapped = dict(contract.__dict__)
    swapped["actions"] = contract.actions[:1]
    readiness = assess_pilot_readiness(
        artifact, PilotContract(**swapped), _live(contract))
    assert any(f["dimension"] == "action_space" for f in readiness.drifted())


# ── fail-closed ──────────────────────────────────────────────────────────────

def test_unobserved_live_configuration_is_not_assumed_to_match():
    artifact = _artifact()
    contract = _contract(artifact)
    readiness = assess_pilot_readiness(artifact, contract, None)
    assert readiness.status == REVALIDATION_REQUIRED
    ruleset = next(f for f in readiness.findings if f["dimension"] == "ruleset")
    assert ruleset["matches"] is False
    assert "NOT assumed to match" in ruleset["note"]


def test_unreadable_dimension_fails_rather_than_passes():
    artifact = _artifact()
    contract = _contract(artifact)
    readiness = assess_pilot_readiness(
        artifact, contract, _live(contract, tools=None, permissions=None))
    assert readiness.status == REVALIDATION_REQUIRED
    assert {f["dimension"] for f in readiness.drifted()} >= {"tools", "permissions"}


def test_incomplete_verification_cannot_start_a_pilot():
    artifact = _artifact(limits=VerificationLimits(max_states=1, max_edges=1, max_depth=0))
    assert artifact["finite_verification"]["verdict"] == "INCONCLUSIVE"
    contract = _contract(artifact)
    readiness = assess_pilot_readiness(artifact, contract, _live(contract))
    assert readiness.status == REVALIDATION_REQUIRED
    dimensions = {f["dimension"] for f in readiness.drifted()}
    assert "enumeration_complete" in dimensions and "verdict" in dimensions


def test_tampered_artifact_cannot_start_a_pilot():
    artifact = _artifact()
    contract = _contract(artifact)
    artifact["finite_verification"]["verdict"] = "SAFE_WITHIN_MODEL"
    artifact["evidence_ledger"]["records"][0]["record"]["reason"] = "edited"
    readiness = assess_pilot_readiness(artifact, contract, _live(contract))
    assert readiness.status == REVALIDATION_REQUIRED
    assert any(f["dimension"] == "artifact_integrity" for f in readiness.drifted())


def test_contract_cannot_claim_a_verification_it_does_not_carry():
    artifact = _artifact()
    contract = _contract(artifact)
    from .pilot import PilotContract
    swapped = dict(contract.__dict__)
    swapped["verification_id"] = "gsv-somebody-elses-result"
    readiness = assess_pilot_readiness(
        artifact, PilotContract(**swapped), _live(contract))
    assert any(f["dimension"] == "verification_binding" for f in readiness.drifted())


def test_operator_override_of_the_safe_gate_is_recorded_not_hidden():
    artifact = _artifact(limits=VerificationLimits(max_states=1, max_edges=1, max_depth=0))
    contract = _contract(artifact)
    readiness = assess_pilot_readiness(
        artifact, contract, _live(contract), require_safe_verdict=False)
    verdict = next(f for f in readiness.findings if f["dimension"] == "verdict")
    assert "OPERATOR OVERRIDE" in verdict["note"]
    # The override does not rescue an incomplete enumeration.
    assert readiness.status == REVALIDATION_REQUIRED


# ── the honest boundary ──────────────────────────────────────────────────────

def test_stale_message_is_the_operator_wording_the_brief_asks_for():
    artifact = _artifact()
    contract = _contract(artifact)
    readiness = assess_pilot_readiness(
        artifact, contract, _live(contract, attestation={"ruleset_hash": "0" * 64}))
    assert "Verification no longer matches current configuration" in \
        readiness.operator_message
    assert "revalidation required" in readiness.operator_message


def test_default_verifier_config_does_not_cover_a_deployment_ruleset():
    """The measured case, pinned so it cannot regress into a false match.

    The verifier's default kernel excludes the CUSTOM domain; a deployment
    carrying all domains hashes differently even at the same rule count. An
    artifact from the default configuration therefore does not describe that
    deployment, and the assessment must say so rather than wave it through.
    """
    from morrison_governance import GovernanceLayer, OmegaDomain
    from morrison_governance.kernel.evidence import ruleset_hash
    from .governance import default_kernel_factory

    verifier_hash = default_kernel_factory()().integrity()["ruleset_hash"]
    all_domains = GovernanceLayer(
        domains=[d for d in OmegaDomain], horizon=3, log_all=False)
    deployment_hash = ruleset_hash(all_domains.rules)
    assert verifier_hash != deployment_hash, (
        "if these ever match, this test's premise is stale -- re-check which "
        "configuration the pilot is actually bound to"
    )

    artifact = _artifact()
    contract = _contract(artifact)
    readiness = assess_pilot_readiness(
        artifact, contract,
        _live(contract, attestation={"ruleset_hash": deployment_hash}))
    assert readiness.status == REVALIDATION_REQUIRED
    assert any(f["dimension"] == "ruleset" for f in readiness.drifted())


def test_external_requirements_are_declared():
    requirements = PilotReadiness.external_requirements()
    assert requirements
    joined = " ".join(requirements).lower()
    assert "real deployment" in joined
    assert "operating organisation" in joined
    assert "nothing in this repository constitutes an external pilot" in joined


def test_readiness_payload_is_machine_readable():
    artifact = _artifact()
    contract = _contract(artifact)
    payload = assess_pilot_readiness(artifact, contract, _live(contract)).to_dict()
    assert payload["schema"] == "mrg.pilot-readiness/1"
    assert payload["may_start"] is True
    assert payload["verification_id"] == artifact["verification_id"]
    assert payload["external_requirements"]
    for finding in payload["findings"]:
        assert set(finding) == {"dimension", "matches", "verified", "observed", "note"}
