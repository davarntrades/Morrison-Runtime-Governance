"""Adapter from exhaustive verification to Morrison's production chokepoint."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    PERMIT,
    GovernanceKernel,
    Principal,
    SecurityContext,
)
from morrison_governance.kernel import capabilities as C


class GovernanceEvaluationError(RuntimeError):
    """The real governance path could not produce a trustworthy decision."""


@dataclass(frozen=True)
class GovernanceDecision:
    verdict: str
    permitted: bool
    layer: str
    reason: str
    rule: str | None = None
    omega_domain: str | None = None
    action_hash: str = ""
    evidence_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "permitted": self.permitted,
            "layer": self.layer,
            "reason": self.reason,
            "rule": self.rule,
            "omega_domain": self.omega_domain,
            "action_hash": self.action_hash,
            "evidence_hash": self.evidence_hash,
            "metadata": self.metadata,
        }


class GovernanceAdapter(Protocol):
    configuration_hash: str
    description: str

    def evaluate(
        self, executed_history: tuple[dict[str, Any], ...], proposal: dict[str, Any]
    ) -> GovernanceDecision: ...


DEFAULT_TOOL_MANIFEST: dict[str, list[str]] = {
    "read_file": [C.CAP_DATA_READ],
    "write_file": [],
    "read_secret": [C.CAP_CREDENTIAL_READ],
    "send_external_message": [C.CAP_EXTERNAL_DATA_MOVE],
    "call_external_api": [C.CAP_EXTERNAL_DATA_MOVE],
    "execute_code": [C.CAP_CODE_EXEC],
    "spawn_process": [C.CAP_CODE_EXEC, C.CAP_DELEGATION],
    "request_privilege": [C.CAP_IAM_PRIVILEGED],
    "use_credential": [],
    "obtain_credential": [C.CAP_CREDENTIAL_READ],
    "create_persistence": [C.CAP_PERSISTENCE],
    "disable_monitoring": [C.CAP_SECURITY_CONTROL],
    "modify_governance_policy": [C.CAP_SECURITY_CONTROL],
    "access_external_network": [],
    "perform_external_side_effect": [C.CAP_EXTERNAL_DATA_MOVE],
}


def default_kernel_factory(
    *,
    tool_manifest: dict[str, list[str]] | None = None,
    unknown_tool_policy: str = "escalate",
    policy_values: dict[str, Any] | None = None,
) -> Callable[[], GovernanceKernel]:
    """Build fresh kernels so branch exploration cannot share mutable history."""

    manifest = dict(tool_manifest or DEFAULT_TOOL_MANIFEST)
    values = dict(policy_values or {})

    def factory() -> GovernanceKernel:
        layer = GovernanceLayer(
            domains=[domain for domain in OmegaDomain if domain != OmegaDomain.CUSTOM],
            horizon=3,
            log_all=False,
        )
        context = SecurityContext(
            principal=Principal(id="global-verifier-agent", tenant="modeled-tenant"),
            signing_key=b"global-verification-no-approvals",
            trusted_issuers=frozenset({"modeled-authority"}),
            internal_url_hosts=("internal.modeled", "localhost"),
            internal_email_domains=("modeled.internal",),
            tool_manifest=manifest,
            unknown_tool_policy=unknown_tool_policy,
            policy_values=values,
        )
        return GovernanceKernel(
            layer=layer,
            context=context,
            evidence_key=b"global-verification-evidence",
            engine_version="global-verification-v1",
        )

    return factory


class MorrisonKernelAdapter:
    """Calls `GovernanceKernel.authorize`, the production interception path.

    A fresh kernel is reconstructed for every branch and the executable prefix
    is replayed as recorded remote execution. This isolates branches while
    preserving the exact prefix-sensitive Morrison decision semantics.
    """

    description = "Morrison GovernanceKernel production chokepoint"

    def __init__(self, kernel_factory: Callable[[], GovernanceKernel] | None = None):
        self._factory = kernel_factory or default_kernel_factory()
        probe = self._factory()
        self.configuration_hash = probe.integrity()["ruleset_hash"]

    def evaluate(
        self, executed_history: tuple[dict[str, Any], ...], proposal: dict[str, Any]
    ) -> GovernanceDecision:
        kernel = self._factory()
        for index, historical_call in enumerate(executed_history):
            replay = kernel.authorize(historical_call, now=0.0)
            if replay.layer == "fail_closed":
                raise GovernanceEvaluationError(
                    f"governance failed while replaying prefix step {index}: {replay.reason}"
                )
            if replay.verdict != PERMIT:
                raise GovernanceEvaluationError(
                    "previously executable prefix did not replay as PERMIT at "
                    f"step {index}: {replay.verdict} ({replay.reason})"
                )
            kernel.record_remote_execution(replay)

        decision = kernel.authorize(proposal, now=0.0)
        if decision.layer == "fail_closed":
            raise GovernanceEvaluationError(decision.reason)
        return GovernanceDecision(
            verdict=decision.verdict,
            permitted=decision.permitted,
            layer=decision.layer,
            reason=decision.reason,
            rule=decision.rule,
            omega_domain=decision.omega_domain,
            action_hash=decision.action_hash,
            evidence_hash=(decision.evidence.record_hash if decision.evidence else None),
            metadata={
                "capabilities": sorted(decision.capabilities),
                "requirement": decision.requirement,
                "authorization": decision.authorization,
            },
        )

