"""Binding a finite-model verification to a bounded, declared deployment.

WHAT THIS IS. A verification artifact says: "inside THIS declared finite
model, under THESE assumptions, no prohibited state was reachable." A pilot
runs in a real environment. The two are only connected if the environment the
pilot is running in is the one that was verified -- and that has to be checked,
not assumed, and re-checked when anything material moves.

WHAT THIS IS NOT. It is not a deployment, and it does not execute, govern or
record anything. It produces one thing: a readiness assessment saying whether a
prior verification still describes the configuration in front of it. Runtime
governance decisions continue to flow through `GovernanceKernel.authorize` into
the real evidence chain exactly as before; nothing here intercepts that path,
and nothing here writes evidence.

THE EXECUTION BOUNDARY it is written against is the smallest real one in the
deployment: `POST /v1/evaluate-step` on the governance service. A planner
proposes one tool call, Morrison decides, and the caller executes only on
PERMIT. Every verdict from that endpoint carries an `attestation` block
{engine_commit, ruleset_hash, service_version, horizon}, which is what makes
drift detectable at all.

INTEGRATION STATUS: this module is an integration BOUNDARY, not a live
integration. No code in the deployment repository calls it today. It is
testable here in full, and wiring it to a real deployment needs an external
environment -- see `PilotReadiness.external_requirements`.

A MEASURED CONSEQUENCE, worth stating plainly. The verifier's default kernel
(`default_kernel_factory`) loads every Omega domain EXCEPT CUSTOM and reports
ruleset_hash 513add10…; a layer carrying all domains reports 292d0a29… . Same
rule count, different ruleset identity, because the hash binds the rules'
logic. So an artifact produced with the default verifier configuration does
NOT carry a deployed service's ruleset identity, and this module will report
REVALIDATION_REQUIRED against such a deployment. That is correct behaviour,
not a bug to route around: a verification only covers a pilot if the verifier
was run against the pilot's own kernel configuration. Binding a pilot means
constructing `MorrisonKernelAdapter` with a factory that matches the
deployment, then verifying with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .provenance import validate_verification_artifact
from .state import stable_hash


# Readiness outcomes. There is no "probably fine".
VERIFIED_CONFIGURATION_CURRENT = "VERIFIED_CONFIGURATION_CURRENT"
REVALIDATION_REQUIRED = "REVALIDATION_REQUIRED"

# Dimensions along which a change invalidates a prior verification.
DRIFT_DIMENSIONS = (
    "model",
    "ruleset",
    "engine",
    "tools",
    "permissions",
    "environment",
    "action_space",
    "transition_semantics",
    "escalation_policy",
)


@dataclass(frozen=True)
class PilotContract:
    """The bounded thing a pilot is allowed to be.

    Every field is part of the environment's identity. Changing any of them
    produces a different environment, which a prior verification does not
    describe -- that is the whole point of writing them down.
    """

    pilot_id: str
    organisation: str

    # What is proposing actions, and where it runs.
    planner_identity: str
    environment_id: str
    environment_description: str

    # What the agent may touch.
    tools: tuple[str, ...]
    permissions: tuple[str, ...]
    actions: tuple[str, ...]
    prohibited_outcomes: tuple[str, ...]

    # Where governance sits, and which governance it is.
    execution_boundary: str
    governance_endpoint: str
    ruleset_hash: str
    engine_version: str | None
    horizon: int
    escalation_policy: tuple[str, ...]

    # Which verification this pilot is claiming to stand on.
    verification_id: str
    model_hash: str
    transition_relation_id: str
    artifact_hash: str

    # Where runtime decisions go. Not written by this module.
    evidence_destination: str

    def environment_identity(self) -> str:
        """Identity of the DEPLOYED environment, independent of any artifact."""
        return "env-" + stable_hash(
            {
                "organisation": self.organisation,
                "environment_id": self.environment_id,
                "planner_identity": self.planner_identity,
                "tools": sorted(self.tools),
                "permissions": sorted(self.permissions),
                "actions": sorted(self.actions),
                "prohibited_outcomes": sorted(self.prohibited_outcomes),
                "execution_boundary": self.execution_boundary,
                "ruleset_hash": self.ruleset_hash,
                "engine_version": self.engine_version,
                "horizon": self.horizon,
                "escalation_policy": sorted(self.escalation_policy),
            }
        )[:20]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "mrg.pilot-contract/1",
            "pilot_id": self.pilot_id,
            "organisation": self.organisation,
            "environment_identity": self.environment_identity(),
            "planner_identity": self.planner_identity,
            "environment_id": self.environment_id,
            "environment_description": self.environment_description,
            "tools": list(self.tools),
            "permissions": list(self.permissions),
            "actions": list(self.actions),
            "prohibited_outcomes": list(self.prohibited_outcomes),
            "execution_boundary": self.execution_boundary,
            "governance_endpoint": self.governance_endpoint,
            "ruleset_hash": self.ruleset_hash,
            "engine_version": self.engine_version,
            "horizon": self.horizon,
            "escalation_policy": list(self.escalation_policy),
            "verification": {
                "verification_id": self.verification_id,
                "model_hash": self.model_hash,
                "transition_relation_id": self.transition_relation_id,
                "artifact_hash": self.artifact_hash,
            },
            "evidence_destination": self.evidence_destination,
        }


@dataclass(frozen=True)
class LiveConfiguration:
    """What the deployment currently reports about itself.

    Built from the governance service's own `attestation` block plus the tool
    and permission inventory the operator declares for the environment. Fields
    that cannot be read are None, never guessed: an unknown dimension fails the
    comparison rather than passing it.
    """

    ruleset_hash: str | None
    engine_version: str | None
    horizon: int | None
    tools: tuple[str, ...] | None
    permissions: tuple[str, ...] | None
    environment_id: str | None
    planner_identity: str | None

    @staticmethod
    def from_attestation(
        attestation: dict[str, Any],
        *,
        tools: Iterable[str] | None = None,
        permissions: Iterable[str] | None = None,
        environment_id: str | None = None,
        planner_identity: str | None = None,
    ) -> "LiveConfiguration":
        """Read a live config from the service's real attestation payload.

        Shape is the governance service's: {engine_commit, ruleset_hash,
        ruleset_hash_algorithm, service_version, horizon}.
        """
        return LiveConfiguration(
            ruleset_hash=attestation.get("ruleset_hash"),
            engine_version=attestation.get("service_version"),
            horizon=attestation.get("horizon"),
            tools=tuple(sorted(tools)) if tools is not None else None,
            permissions=tuple(sorted(permissions)) if permissions is not None else None,
            environment_id=environment_id,
            planner_identity=planner_identity,
        )


@dataclass
class PilotReadiness:
    """Whether a prior verification still describes this configuration."""

    status: str
    contract_environment_identity: str
    verification_id: str
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def may_start(self) -> bool:
        return self.status == VERIFIED_CONFIGURATION_CURRENT

    def drifted(self) -> list[dict[str, Any]]:
        return [f for f in self.findings if not f["matches"]]

    @property
    def operator_message(self) -> str:
        if self.may_start:
            return (
                "Verification matches the current configuration. The result it "
                "carries holds within the declared finite model and its stated "
                "assumptions only -- it is not a claim about this environment's "
                "real-world safety."
            )
        reasons = ", ".join(f["dimension"] for f in self.drifted())
        return (
            "Verification no longer matches current configuration — "
            f"revalidation required ({reasons or 'see findings'})."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "mrg.pilot-readiness/1",
            "status": self.status,
            "may_start": self.may_start,
            "operator_message": self.operator_message,
            "environment_identity": self.contract_environment_identity,
            "verification_id": self.verification_id,
            "findings": self.findings,
            "external_requirements": self.external_requirements(),
        }

    @staticmethod
    def external_requirements() -> list[str]:
        """What this repository cannot supply for a genuine external pilot."""
        return [
            "A real deployment whose /health attestation can be read, so the "
            "live ruleset_hash is observed rather than declared.",
            "An operator-declared tool and permission inventory for the pilot "
            "environment, which is organisation-specific.",
            "A finite model whose declared action space corresponds to that "
            "tool inventory; the models in this repository are illustrative.",
            "A caller at the execution boundary that executes only on PERMIT "
            "and routes its decisions to the deployment's evidence chain.",
            "Agreement from the operating organisation. Nothing in this "
            "repository constitutes an external pilot having taken place.",
        ]


def _finding(dimension: str, matches: bool, verified: Any, observed: Any, note: str) -> dict:
    return {
        "dimension": dimension,
        "matches": bool(matches),
        "verified": verified,
        "observed": observed,
        "note": note,
    }


def contract_from_artifact(
    artifact: dict[str, Any],
    *,
    pilot_id: str,
    organisation: str,
    planner_identity: str,
    environment_id: str,
    environment_description: str,
    tools: Iterable[str],
    permissions: Iterable[str],
    execution_boundary: str,
    governance_endpoint: str,
    evidence_destination: str,
    horizon: int,
) -> PilotContract:
    """Build a contract whose verification fields come FROM the artifact.

    The deployment supplies what only it knows (who, where, which tools). It
    does not get to supply the verification identity -- that is copied from the
    artifact, so a contract cannot claim a verification it does not carry.
    """
    return PilotContract(
        pilot_id=pilot_id,
        organisation=organisation,
        planner_identity=planner_identity,
        environment_id=environment_id,
        environment_description=environment_description,
        tools=tuple(sorted(tools)),
        permissions=tuple(sorted(permissions)),
        actions=tuple(sorted(
            a["name"] for a in artifact["action_space"]["definitions"]
        )),
        prohibited_outcomes=tuple(sorted(
            p["identifier"] for p in artifact["prohibited_states"]
        )),
        execution_boundary=execution_boundary,
        governance_endpoint=governance_endpoint,
        ruleset_hash=artifact["governance"]["ruleset_hash"],
        engine_version=artifact["governance"]["engine_version"],
        horizon=horizon,
        escalation_policy=tuple(artifact["traversal"]["escalation_outcomes_admitted"]),
        verification_id=artifact["verification_id"],
        model_hash=artifact["environment"]["model_hash"],
        transition_relation_id=artifact["environment"]["transition_relation_id"],
        artifact_hash=artifact["artifact_integrity"]["artifact_hash"],
        evidence_destination=evidence_destination,
    )


def assess_pilot_readiness(
    artifact: dict[str, Any],
    contract: PilotContract,
    live: LiveConfiguration | None = None,
    *,
    require_safe_verdict: bool = True,
) -> PilotReadiness:
    """Decide whether this verification still covers this configuration.

    Fail-closed throughout: a dimension that cannot be read does not match, an
    invalid artifact does not start a pilot, and an incomplete or non-SAFE
    verification does not either unless the operator explicitly opts out of
    that gate (`require_safe_verdict=False`), which is recorded in the
    findings rather than hidden.
    """
    findings: list[dict[str, Any]] = []

    validation = validate_verification_artifact(artifact)
    findings.append(_finding(
        "artifact_integrity", validation.valid, "valid",
        "valid" if validation.valid else
        [f["check"] for f in validation.failures()],
        "an artifact that does not validate cannot support a pilot",
    ))

    complete = artifact["finite_verification"]["complete_enumeration"] is True
    verdict = artifact["finite_verification"]["verdict"]
    findings.append(_finding(
        "enumeration_complete", complete, True, complete,
        "an incomplete enumeration establishes nothing",
    ))
    if require_safe_verdict:
        findings.append(_finding(
            "verdict", verdict == "SAFE_WITHIN_MODEL", "SAFE_WITHIN_MODEL", verdict,
            "within the declared finite model only; not a production claim",
        ))
    else:
        findings.append(_finding(
            "verdict", True, verdict, verdict,
            "OPERATOR OVERRIDE: the SAFE gate was disabled for this assessment",
        ))

    # The contract must carry the artifact it claims.
    for dimension, contract_value, artifact_value in (
        ("model", contract.model_hash, artifact["environment"]["model_hash"]),
        ("transition_semantics", contract.transition_relation_id,
         artifact["environment"]["transition_relation_id"]),
        ("verification_binding", contract.verification_id, artifact["verification_id"]),
        ("artifact_binding", contract.artifact_hash,
         artifact["artifact_integrity"]["artifact_hash"]),
        ("escalation_policy", list(contract.escalation_policy),
         artifact["traversal"]["escalation_outcomes_admitted"]),
    ):
        findings.append(_finding(
            dimension, contract_value == artifact_value, artifact_value, contract_value,
            "the contract must carry the verification it claims",
        ))

    verified_actions = sorted(a["name"] for a in artifact["action_space"]["definitions"])
    findings.append(_finding(
        "action_space", sorted(contract.actions) == verified_actions,
        verified_actions, sorted(contract.actions),
        "the pilot may not offer actions the model did not enumerate",
    ))
    verified_omega = sorted(p["identifier"] for p in artifact["prohibited_states"])
    findings.append(_finding(
        "prohibited_outcomes", sorted(contract.prohibited_outcomes) == verified_omega,
        verified_omega, sorted(contract.prohibited_outcomes),
        "the pilot's prohibited set must be the one that was verified",
    ))

    # And the live deployment must be the thing the contract describes.
    if live is None:
        findings.append(_finding(
            "ruleset", False, contract.ruleset_hash, None,
            "no live configuration was observed; the deployment's ruleset is "
            "unknown and is NOT assumed to match",
        ))
    else:
        findings.append(_finding(
            "ruleset", bool(live.ruleset_hash) and live.ruleset_hash == contract.ruleset_hash,
            contract.ruleset_hash, live.ruleset_hash,
            "a different ruleset decides differently, so a prior verification "
            "does not describe it",
        ))
        findings.append(_finding(
            "engine", live.engine_version == contract.engine_version,
            contract.engine_version, live.engine_version,
            "engine version stamped on live verdicts",
        ))
        findings.append(_finding(
            "horizon", live.horizon == contract.horizon,
            contract.horizon, live.horizon,
            "a shorter horizon sees fewer reachable consequences",
        ))
        findings.append(_finding(
            "tools", live.tools is not None
            and sorted(live.tools) == sorted(contract.tools),
            sorted(contract.tools), None if live.tools is None else sorted(live.tools),
            "a tool the model never enumerated is outside the verification",
        ))
        findings.append(_finding(
            "permissions", live.permissions is not None
            and sorted(live.permissions) == sorted(contract.permissions),
            sorted(contract.permissions),
            None if live.permissions is None else sorted(live.permissions),
            "permissions change which transitions are available",
        ))
        findings.append(_finding(
            "environment", live.environment_id == contract.environment_id,
            contract.environment_id, live.environment_id,
            "a different environment is a different reachable graph",
        ))
        findings.append(_finding(
            "planner", live.planner_identity == contract.planner_identity,
            contract.planner_identity, live.planner_identity,
            "recorded for provenance; governance does not depend on the planner",
        ))

    status = (
        VERIFIED_CONFIGURATION_CURRENT
        if all(f["matches"] for f in findings)
        else REVALIDATION_REQUIRED
    )
    return PilotReadiness(
        status=status,
        contract_environment_identity=contract.environment_identity(),
        verification_id=artifact["verification_id"],
        findings=findings,
    )
