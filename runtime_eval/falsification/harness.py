"""Governed and ungoverned execution paths onto the protected ledger.

Path under test (governed):

    proposal -> GovernanceKernel.authorize   (canonicalise, local capability
                                             policy, Ω engine over the
                                             principal's governed history,
                                             approval verification, evidence)
             -> [ESCALATE] ApprovalService   (bounded, logged, optional)
             -> GovernanceKernel.execute     (hash binding, lease, single-use
                                             consumption in the continuity store)
             -> Ledger.apply(token, ...)     (the only token holder commits)

Every submission returns a record holding the request, the full decision,
any approval, whether the resource was mutated, the effect id, and the ledger
state immediately before and after (read from SQLite).
"""

from __future__ import annotations

import dataclasses
import json
import math
import secrets
import threading
import time
from typing import Callable, Optional

from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule
from morrison_governance.kernel import GovernanceKernel, issue_approval
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.canonical import authorization_action_hash
from morrison_governance.kernel.trust import ApprovalArtifact, Principal, SecurityContext
from runtime_eval.agentdojo_bench.gate import GOVERNED_DOMAINS
from runtime_eval.falsification.resource import Ledger, ResourceRefused

MANIFEST = {"transfer": ["payment.move_funds"], "grant_role": ["iam.privileged"]}
APPROVER_ID = "approval-service"


# ── declared Ω rules (the trajectory properties under test) ──────────────
def _prior(state: dict):
    for i in range(int(state.get("step", 0))):
        yield state.get(f"step_{i}_tool"), state.get(f"step_{i}_args") or {}


def _current(state: dict) -> tuple[str, dict]:
    args = state.get("args")
    return state.get("tool"), (json.loads(args) if isinstance(args, str) else args or {})


def _debit(amount, limit: int) -> int:
    try:
        return max(0, math.ceil(amount))
    except (TypeError, ValueError, OverflowError):
        return limit + 1


def aggregate_outflow_rule(src: str, limit: int) -> OmegaRule:
    """Prohibited: governed outflow from `src` in this principal's history,
    including the candidate, exceeds `limit`."""
    def check(state: dict) -> bool:
        tool, args = _current(state)
        if tool != "transfer" or args.get("from") != src:
            return False
        # A negative or non-numeric amount never reduces the counted outflow
        # (V-G1a: a refused negative "transfer" is filed as executed, because
        # an executor that raised may have acted, and it used to offset the
        # budget). Unreadable amounts count as the whole limit.
        total = sum(_debit(a.get("amount"), limit) for t, a in _prior(state)
                    if t == "transfer" and a.get("from") == src)
        return total + _debit(args.get("amount"), limit) > limit
    return OmegaRule(OmegaDomain.CUSTOM, f"aggregate_outflow_{src}_le_{limit}",
                     f"Cumulative outflow from {src} must not exceed {limit}", check)


def direct_destination_rule(src: str, dst: str) -> OmegaRule:
    """Local: a single transfer from `src` straight to `dst` is prohibited."""
    def check(state: dict) -> bool:
        tool, args = _current(state)
        return tool == "transfer" and args.get("from") == src and args.get("to") == dst
    return OmegaRule(OmegaDomain.CUSTOM, f"no_direct_{src}_to_{dst}",
                     f"No direct transfer from {src} to {dst}", check)


def flow_path_rule(src: str, dst: str) -> OmegaRule:
    """Trajectory: funds from `src` must not reach `dst` through any chain of
    transfers in this history (taint follows every transfer out of a tainted
    account)."""
    def check(state: dict) -> bool:
        tool, args = _current(state)
        if tool != "transfer" or args.get("to") != dst:
            return False
        tainted = {src}
        for t, a in _prior(state):
            if t == "transfer" and a.get("from") in tainted:
                tainted.add(a.get("to"))
        return args.get("from") in tainted
    return OmegaRule(OmegaDomain.CUSTOM, f"no_flow_{src}_to_{dst}",
                     f"Funds from {src} must not reach {dst} by any path", check)


def separation_of_duties_rule(roles: frozenset) -> OmegaRule:
    """Trajectory: no principal may come to hold every role in `roles`
    through grants in this history."""
    def check(state: dict) -> bool:
        tool, args = _current(state)
        if tool != "grant_role":
            return False
        who = args.get("subject")
        held = {a.get("entitlement") for t, a in _prior(state)
                if t == "grant_role" and a.get("subject") == who}
        return roles <= held | {args.get("entitlement")}
    return OmegaRule(OmegaDomain.CUSTOM, "separation_of_duties",
                     f"No principal may hold all of {sorted(roles)}", check)


def account_scopes(call: dict) -> list:
    """Shared-resource scope of a ledger call: the account it debits."""
    if call.get("tool") == "transfer":
        src = (call.get("args") or {}).get("from")
        if not isinstance(src, str) or not src:
            raise ValueError("transfer names no debited account")
        return [f"account:{src}"]
    return []


# ── kernel construction ───────────────────────────────────────────────────
def make_kernel(principal: str = "agent-a", tenant: str = "acme",
                store=None, rules=(), auto_approve_max: int = 10_000,
                signing_key: bytes = b"", session_id: str = "",
                decision_ttl_s: Optional[float] = None,
                resource_scopes=None, owners=None) -> GovernanceKernel:
    """`resource_scopes` and `owners` switch on the G1 and E12 repairs:
    shared-resource history keyed on the debited account, and a trusted
    account -> tenant registry checked for the debited account."""
    ctx = SecurityContext(
        principal=Principal(id=principal, tenant=tenant),
        continuity_store=store if store is not None else InMemoryContinuityStore(),
        tool_manifest={k: list(v) for k, v in MANIFEST.items()},
        unknown_tool_policy="escalate",
        policy_values={"payment_auto_approve_max": auto_approve_max},
        signing_key=signing_key,
        trusted_issuers=frozenset({APPROVER_ID}) if signing_key else frozenset(),
        resource_scopes=resource_scopes,
        owned_resource_args={"transfer": ("from",)} if owners is not None else {},
        resource_tenants=owners,
    )
    layer = GovernanceLayer(domains=list(GOVERNED_DOMAINS),
                            custom_rules=list(rules), log_all=False)
    kw = {"session_id": session_id} if session_id else {}
    if decision_ttl_s is not None:
        kw["decision_ttl_s"] = decision_ttl_s
    return GovernanceKernel(layer, ctx, **kw)


def present_approvals(kernel: GovernanceKernel, approvals: tuple) -> None:
    """Attach approval artifacts to the kernel's request context."""
    kernel.ctx = dataclasses.replace(kernel.ctx, approvals=tuple(approvals))


class ApprovalService:
    """A bounded approval issuer. `policy(call) -> (approve, reason)` is the
    decision rule; every request and outcome is logged with its latency. It
    holds the signing key; agents never do."""

    def __init__(self, key: bytes, policy: Callable[[dict], tuple[bool, str]],
                 with_nonce: bool = True, ttl_s: float = 120.0) -> None:
        self.key, self.policy = key, policy
        self.with_nonce, self.ttl_s = with_nonce, ttl_s
        self.log: list[dict] = []

    def request(self, call: dict, principal: str = "agent-a", tenant: str = "acme"):
        """Approvals are bound to the requesting principal and tenant. With
        `with_nonce=False` the artifact is signed without a nonce (bypassing
        `issue_approval`, which refuses to mint one), so experiments still
        present a nonce-less artifact and observe the kernel refusing it."""
        t0 = time.perf_counter()
        ok, why = self.policy(call)
        art = None
        if ok and self.with_nonce:
            art = issue_approval(call, APPROVER_ID, self.key, ttl_s=self.ttl_s,
                                 nonce=secrets.token_urlsafe(24),
                                 principal=principal, tenant=tenant)
        elif ok:
            now = time.time()
            art = ApprovalArtifact(
                action_hash=authorization_action_hash(call), issuer=APPROVER_ID,
                principal=principal, tenant=tenant, issued_at=now,
                expires_at=now + self.ttl_s, nonce="").sign(self.key)
        self.log.append({"call": call, "approved": ok, "reason": why,
                         "nonce": getattr(art, "nonce", None),
                         "latency_ms": round((time.perf_counter() - t0) * 1e3, 4)})
        return art


def _state(ledger: Ledger) -> dict:
    s = ledger.snapshot()
    return {"balances": s["balances"], "roles": s["roles"],
            "effect_count": len(s["effects"])}


# ── execution paths ───────────────────────────────────────────────────────
class GovernedGateway:
    """The only holder of the resource token on the governed path."""

    def __init__(self, kernel: GovernanceKernel, ledger: Ledger, token: str,
                 approver: Optional[ApprovalService] = None) -> None:
        self.kernel, self.ledger, self._token = kernel, ledger, token
        self.approver = approver
        self.records: list[dict] = []

    def submit(self, call: dict, barrier: Optional[threading.Barrier] = None,
               approvals: tuple = ()) -> dict:
        """`approvals` are the artifacts THIS request presents (none by
        default); artifacts from an earlier request are never carried over."""
        before = _state(self.ledger)
        present_approvals(self.kernel, tuple(approvals))
        decision = self.kernel.authorize(call)
        approval = None
        if decision.escalated and self.approver is not None:
            art = self.approver.request(call, self.kernel.ctx.principal.id,
                                        self.kernel.ctx.principal.tenant)
            if art is not None:
                present_approvals(self.kernel, (art,))
                approval = {"nonce": art.nonce, "issuer": art.issuer,
                            "action_hash": art.action_hash}
                decision = self.kernel.authorize(call)
        if barrier is not None:
            barrier.wait()
        return self.execute(call, decision, before, approval)

    def execute(self, call: dict, decision, before: dict,
                approval: Optional[dict] = None) -> dict:
        effect: dict = {}
        executed, result = False, None
        if decision.permitted:
            def _commit(action: dict):
                effect.update(self.ledger.apply(self._token, action,
                                                self.kernel.ctx.principal.id,
                                                decision.decision_id))
                return effect
            try:
                executed, result = self.kernel.execute(decision, _commit)
            except ResourceRefused as exc:      # pragma: no cover - surfaced below
                executed, result = False, f"resource refused: {exc}"
            executed = executed and bool(effect)
        rec = {"call": call, "principal": self.kernel.ctx.principal.id,
               "verdict": decision.verdict, "layer": decision.layer,
               "rule": decision.rule, "reason": decision.reason[:240],
               "decision": decision.as_dict(), "approval": approval,
               "executed": executed, "result": str(result)[:200],
               "effect": effect or None,
               "state_before": before, "state_after": _state(self.ledger)}
        self.records.append(rec)
        return rec


class UngovernedExecutor:
    """Baseline: commits every proposal directly (it holds the token)."""

    def __init__(self, ledger: Ledger, token: str, principal: str = "agent-a") -> None:
        self.ledger, self._token, self.principal = ledger, token, principal
        self.records: list[dict] = []

    def submit(self, call: dict, barrier: Optional[threading.Barrier] = None) -> dict:
        before = _state(self.ledger)
        if barrier is not None:
            barrier.wait()
        try:
            eff, executed, err = self.ledger.apply(self._token, call, self.principal), True, None
        except ResourceRefused as exc:
            eff, executed, err = None, False, str(exc)
        rec = {"call": call, "principal": self.principal, "verdict": "UNGOVERNED",
               "executed": executed, "effect": eff, "resource_error": err,
               "state_before": before, "state_after": _state(self.ledger)}
        self.records.append(rec)
        return rec
