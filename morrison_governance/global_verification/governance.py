"""Adapter from exhaustive verification to Morrison's production chokepoint."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel import (
    PERMIT,
    GovernanceKernel,
    Principal,
    SecurityContext,
)
from morrison_governance.kernel import capabilities as C
from morrison_governance.kernel.trust import ApprovalArtifact


class GovernanceEvaluationError(RuntimeError):
    """The real governance path could not produce a trustworthy decision."""


PERMIT_AUTHORIZATION = "permit"
ESCALATION_APPROVED_AUTHORIZATION = "escalation_approved"
AUTHORIZATIONS = (PERMIT_AUTHORIZATION, ESCALATION_APPROVED_AUTHORIZATION)


@dataclass(frozen=True)
class ExecutedStep:
    """One modeled step of an executable prefix, with the authority that carried it.

    A prefix step is not just "a call that happened". It is a call that happened
    *under a specific authority*, and replaying it has to reproduce that same
    authority or the branch is not the branch we think it is. `authorization`
    records which of the two admissible authorities applied:

    - `permit`              -- governance permitted the call outright;
    - `escalation_approved` -- governance escalated, and the model resolved the
                               escalation by presenting a verified approval
                               artifact bound to that exact action.

    Nothing here grants authority. It records which authority the verifier must
    reconstruct, so replay can fail closed when it cannot.
    """

    proposal: dict[str, Any]
    authorization: str = PERMIT_AUTHORIZATION

    def __post_init__(self) -> None:
        if self.authorization not in AUTHORIZATIONS:
            raise ValueError(f"unknown step authorization {self.authorization!r}")

    @property
    def approved_escalation(self) -> bool:
        return self.authorization == ESCALATION_APPROVED_AUTHORIZATION

    def to_dict(self) -> dict[str, Any]:
        return {"proposal": self.proposal, "authorization": self.authorization}


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
        self, executed_history: tuple[ExecutedStep, ...], proposal: dict[str, Any]
    ) -> GovernanceDecision: ...

    def approve_escalation(
        self,
        executed_history: tuple[ExecutedStep, ...],
        proposal: dict[str, Any],
        decision: GovernanceDecision,
    ) -> GovernanceDecision:
        """Resolve an ESCALATE by presenting a verified approval artifact.

        Optional. An adapter that cannot model an authorised resolution must not
        define this; the verifier then refuses to enumerate the approve branch
        rather than waving the proposal through.
        """
        ...


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
            # Each verification BRANCH is an independent hypothetical and the
            # verifier reconstructs a kernel per branch, replaying the prefix
            # itself. Branches must not inherit one another's governed history,
            # so each gets its own store. Nothing here executes.
            continuity_store=InMemoryContinuityStore(),
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

    def __init__(
        self,
        kernel_factory: Callable[[], GovernanceKernel] | None = None,
        *,
        approval_scope: str = "global-verification-modeled-approval",
    ):
        self._factory = kernel_factory or default_kernel_factory()
        self.approval_scope = approval_scope
        probe = self._factory()
        self.configuration_hash = probe.integrity()["ruleset_hash"]

    # ── prefix reconstruction ────────────────────────────────────────────
    def _replay_prefix(
        self, kernel: GovernanceKernel, executed_history: tuple[ExecutedStep, ...]
    ) -> None:
        """Re-establish the branch's governed history inside a fresh kernel.

        Every step must replay to the SAME authority it was executed under.
        A step recorded as `permit` that no longer permits, or a step recorded
        as `escalation_approved` that no longer escalates, means the branch is
        not reproducible — which is a verification failure, not something to
        paper over. Only a PERMIT decision is ever recorded as executed, so the
        kernel's own "only a PERMIT decision can be recorded as executed"
        invariant is preserved exactly.
        """
        for index, step in enumerate(executed_history):
            replay = kernel.authorize(step.proposal, now=0.0)
            if replay.layer == "fail_closed":
                raise GovernanceEvaluationError(
                    f"governance failed while replaying prefix step {index}: {replay.reason}"
                )
            if step.authorization == PERMIT_AUTHORIZATION:
                if replay.verdict != PERMIT:
                    raise GovernanceEvaluationError(
                        "previously executable prefix did not replay as PERMIT at "
                        f"step {index}: {replay.verdict} ({replay.reason})"
                    )
            else:
                # An approved escalation must still BE an escalation on replay.
                # If governance now permits it outright, or now blocks it, the
                # recorded approval no longer describes this step.
                if replay.verdict != "ESCALATE":
                    raise GovernanceEvaluationError(
                        "approved-escalation prefix step "
                        f"{index} no longer replays as ESCALATE: "
                        f"{replay.verdict} ({replay.reason})"
                    )
                replay = self._authorize_with_approval(
                    kernel, step.proposal, replay, index
                )
                if replay.layer == "fail_closed":
                    raise GovernanceEvaluationError(
                        f"governance failed approving prefix step {index}: {replay.reason}"
                    )
                if replay.verdict != PERMIT:
                    raise GovernanceEvaluationError(
                        f"approved escalation at prefix step {index} did not become "
                        f"PERMIT under a verified approval artifact: "
                        f"{replay.verdict} ({replay.reason})"
                    )
            kernel.record_remote_execution(replay, now=0.0)

    def _authorize_with_approval(
        self,
        kernel: GovernanceKernel,
        proposal: dict[str, Any],
        decision: Any,
        index: int,
    ) -> Any:
        """Present a genuinely signed approval bound to this exact action.

        This is the production approval mechanism, not a verifier override: the
        artifact is HMAC-signed with the deployment's approval key, issued by a
        trusted issuer, and bound to the decision's SEMANTIC hash, so it cannot
        authorise any other action. Governance is then re-run and is free to
        refuse anyway — an approval unlocks a capability requirement, it does
        not overrule Ω.
        """
        context = kernel.ctx
        if not context.signing_key:
            raise GovernanceEvaluationError(
                "cannot model an approved escalation: the modeled deployment has "
                "no approval signing key, so no approval could ever be verified"
            )
        issuers = sorted(context.trusted_issuers)
        if not issuers:
            raise GovernanceEvaluationError(
                "cannot model an approved escalation: the modeled deployment "
                "trusts no approval issuer"
            )
        if not decision.semantic_hash:
            raise GovernanceEvaluationError(
                "cannot model an approved escalation: the escalated decision "
                "carries no semantic hash to bind an approval to"
            )
        artifact = ApprovalArtifact(
            action_hash=decision.semantic_hash,
            issuer=issuers[0],
            scope=self.approval_scope,
            issued_at=0.0,
            # 0.0 disables the expiry check, keeping enumeration independent of
            # wall-clock time. Nonces stay unique per prefix position.
            expires_at=0.0,
            nonce=f"{self.approval_scope}-{index}-{decision.semantic_hash[:16]}",
        ).sign(context.signing_key)
        context.approvals = tuple(context.approvals) + (artifact,)
        return kernel.authorize(proposal, now=0.0)

    @staticmethod
    def _decision(decision: Any, *, escalation_approved: bool = False) -> GovernanceDecision:
        metadata: dict[str, Any] = {
            "capabilities": sorted(decision.capabilities),
            "requirement": decision.requirement,
            "authorization": decision.authorization,
        }
        if escalation_approved:
            metadata["escalation_approved"] = True
            metadata["approval_bound_action_hash"] = decision.semantic_hash
        return GovernanceDecision(
            verdict=decision.verdict,
            permitted=decision.permitted,
            layer=decision.layer,
            reason=decision.reason,
            rule=decision.rule,
            omega_domain=decision.omega_domain,
            action_hash=decision.action_hash,
            evidence_hash=(decision.evidence.record_hash if decision.evidence else None),
            metadata=metadata,
        )

    # ── the two enumerable outcomes ──────────────────────────────────────
    def evaluate(
        self, executed_history: tuple[ExecutedStep, ...], proposal: dict[str, Any]
    ) -> GovernanceDecision:
        kernel = self._factory()
        self._replay_prefix(kernel, executed_history)
        decision = kernel.authorize(proposal, now=0.0)
        if decision.layer == "fail_closed":
            raise GovernanceEvaluationError(decision.reason)
        return self._decision(decision)

    def approve_escalation(
        self,
        executed_history: tuple[ExecutedStep, ...],
        proposal: dict[str, Any],
        decision: GovernanceDecision,
    ) -> GovernanceDecision:
        """Return the decision governance reaches once approval IS presented.

        The verifier calls this to enumerate the approve side of an escalation.
        The result is whatever the real kernel says with a verified approval in
        hand: usually PERMIT, but a BLOCK here is meaningful and is honoured —
        it means the escalation was not approvable into execution at all.
        """
        if decision.verdict != "ESCALATE":
            raise GovernanceEvaluationError(
                f"approve_escalation requires an ESCALATE decision, got {decision.verdict}"
            )
        kernel = self._factory()
        self._replay_prefix(kernel, executed_history)
        live = kernel.authorize(proposal, now=0.0)
        if live.layer == "fail_closed":
            raise GovernanceEvaluationError(live.reason)
        if live.verdict != "ESCALATE":
            raise GovernanceEvaluationError(
                "escalation resolution is not reproducible: re-evaluating the "
                f"same proposal on the same prefix returned {live.verdict}"
            )
        approved = self._authorize_with_approval(
            kernel, proposal, live, len(executed_history)
        )
        if approved.layer == "fail_closed":
            raise GovernanceEvaluationError(approved.reason)
        return self._decision(approved, escalation_approved=True)
