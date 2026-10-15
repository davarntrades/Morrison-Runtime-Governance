"""Trusted governance core: a configured, unmodified Morrison GovernanceKernel.

Everything that decides here is Morrison:

  * `GovernanceKernel.authorize`     final ALLOW / BLOCK / ESCALATE, trajectory
                                     reservation, hash-chained evidence
  * the Ω engine + envelope rules    local and global admissibility
  * capability policy                payment-class operations need a verified
                                     approval above `payment_auto_approve_max`
  * `issue_approval`                 human finance approval, bound to the exact
                                     canonical action
  * `GovernanceKernel.mint_lease`    Ed25519 execution lease for the Stripe
                                     executor, registered in the shared
                                     single-use `SQLiteLeaseStore`
  * `GovernanceKernel.release`       atomic cancellation of an unredeemed lease

This module adds configuration and a stateless local-only evaluation used
for DISPLAY (`GovernanceLayer.evaluate` with the local rules only); the kernel
decision is the only one that can produce an execution lease.
"""

from __future__ import annotations

import copy
import json
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from morrison_governance import GovernanceLayer
from morrison_governance.kernel import (
    BLOCK, ESCALATE, PERMIT, GovernanceKernel, Principal, SecurityContext,
    SQLiteLeaseStore, issue_approval,
)
from morrison_governance.kernel import capabilities as C
from morrison_governance.kernel.continuity import (
    EXECUTED, EXPORTED, FileContinuityStore,
)
from morrison_governance.kernel.gate import RESOURCE_NAMESPACE

from collection_agent import envelope as E

AGENT_PRINCIPAL = "resurrection-tech-collection-agent"
TENANT = "resurrection-tech"
FINANCE_APPROVER = "resurrection-tech-finance"

# Per-invoice amount above which a human finance approval artifact is
# required (kernel capability policy, server-owned). £1,000.00.
AUTO_APPROVE_MAX_MINOR = 100_000

VERDICT_LABEL = {PERMIT: "ALLOW", BLOCK: "BLOCK", ESCALATE: "ESCALATE"}


@dataclass
class Outcome:
    """What the governance service returns for one proposal."""
    verdict: str                    # ALLOW / BLOCK / ESCALATE (kernel)
    local: dict
    global_: dict
    decision: dict
    lease: Optional[str]
    operation_id: str

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "local": self.local,
                "global": self.global_, "decision": self.decision,
                "lease": self.lease, "operation_id": self.operation_id}


class CollectionGovernor:
    """Holds the kernel, the trusted envelope and the lease signer."""

    def __init__(self, terms: dict, state_dir: Path,
                 lease_signer: Callable[[bytes], bytes],
                 observed_state: Callable[[], dict],
                 approval_key: Optional[bytes] = None):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.terms = copy.deepcopy(terms)
        self.observed_state = observed_state
        self.approval_key = approval_key or secrets.token_bytes(32)
        self._approvals: list = []
        self._leases: dict[str, Any] = {}      # operation_id -> exported decision
        self._lock = threading.Lock()
        self.lease_store = SQLiteLeaseStore(self.state_dir / "leases.sqlite")

        self.ctx = SecurityContext(
            principal=Principal(id=AGENT_PRINCIPAL, tenant=TENANT),
            signing_key=self.approval_key,
            trusted_issuers=frozenset({FINANCE_APPROVER}),
            tool_manifest={E.TOOL: [C.CAP_PAYMENT]},
            unknown_tool_policy="block",
            reject_untrusted_authority_claims=True,
            policy_values={"payment_auto_approve_max": AUTO_APPROVE_MAX_MINOR},
            continuity_store=FileContinuityStore(
                str(self.state_dir / "continuity.jsonl")),
            # Collection history must not age out: a ceiling that forgets
            # invoices after an hour is not a ceiling. 0 = lifetime.
            continuity_window_s=0.0,
            continuity_policy="block",
            resource_scopes=E.resource_scopes,
            lease_signer=lease_signer,
            lease_store=self.lease_store,
        )
        self._apply_terms()
        self.kernel = GovernanceKernel(
            layer=GovernanceLayer(custom_rules=E.envelope_rules(),
                                  admissibility_checks=[]),
            context=self.ctx, engine_version="morrison-kernel+financial-aoe-1",
            session_id="collection-agent-session")
        # Display-only local evaluation: same rules, no history.
        self.local_layer = GovernanceLayer(custom_rules=E.local_rules(),
                                           admissibility_checks=[],
                                           log_all=False)

    # ── trusted state ────────────────────────────────────────
    def _apply_terms(self) -> None:
        digest = E.agreements_digest(self.terms["customers"],
                                     self.terms["company_stripe_account"])
        self.ctx.policy_values = {**self.ctx.policy_values,
                                  "collection_terms_digest": digest}

    def envelope_snapshot(self) -> dict:
        """Authoritative envelope for one decision: terms + observed state."""
        observed = self.observed_state()      # raises -> caller fails closed
        return {
            "company_stripe_account": self.terms["company_stripe_account"],
            "customers": copy.deepcopy(self.terms["customers"]),
            "dispatched_operations": self._dispatched_operations(),
            "voided_operations": sorted(observed.get("voided_operations", [])),
            "observed_collections": observed.get("observed_collections", {}),
        }

    def _dispatched_operations(self) -> list:
        """Operations Morrison let through: EXPORTED (lease issued) or
        EXECUTED entries in the kernel's persistent governed history, own and
        shared. Read from the ledger, not process memory, so a restart does
        not forget them."""
        k = self.kernel
        rows = list(k.ledger)
        try:
            for key in {f"{RESOURCE_NAMESPACE}/collection:{c}" for c in self.terms["customers"]}:
                rows += list(k.store.entries(key))
        except Exception:                            # noqa: BLE001
            pass
        return sorted({(r.action.get("args") or {}).get("operation_id")
                       for r in rows
                       if getattr(r, "state", "") in (EXPORTED, EXECUTED)
                       and r.action.get("tool") == E.TOOL} - {None})

    def public_terms(self, customer: str) -> Optional[dict]:
        """What the agent may read: the commercial terms, not the secrets."""
        cust = self.terms["customers"].get(customer)
        if cust is None:
            return None
        return {"customer": customer, "name": cust.get("name"),
                "stripe_customer": cust.get("stripe_customer"),
                "agreement": copy.deepcopy(cust.get("agreement")),
                "company_stripe_account": self.terms["company_stripe_account"]}

    def update_agreement(self, customer: str, changes: dict) -> dict:
        """Operator change to commercial terms.

        The new terms digest changes the kernel's live ruleset hash, voiding
        undispatched decisions. Leases already exported to the executor are
        not covered by that check, so they are cancelled here through
        `GovernanceKernel.release`, which arbitrates with the lease registry:
        a lease that was already redeemed cannot be cancelled and stays in
        the trajectory as an effect that happened.
        """
        with self._lock:
            agr = self.terms["customers"][customer]["agreement"]
            agr.update(changes)
            agr["version"] = int(agr.get("version", 0)) + 1
            self._apply_terms()
            cancelled, redeemed = [], []
            for op, dec in list(self._leases.items()):
                if dec.action["args"].get("customer") != customer:
                    continue
                if self.kernel.release(dec):
                    cancelled.append(op)
                    self._leases.pop(op, None)
                else:
                    redeemed.append(op)
            return {"agreement": copy.deepcopy(agr), "cancelled_leases": cancelled,
                    "already_redeemed": redeemed}

    # ── decisions ────────────────────────────────────────────
    def local_view(self, call: dict, env: dict) -> dict:
        # GovernanceLayer.evaluate(tool_call, trusted_facts=...); pylint
        # mis-infers the bound method.
        res = self.local_layer.evaluate(  # pylint: disable=unexpected-keyword-arg
            call, trusted_facts={E.FACT: env})
        reason = None if res.permitted else E.local_violation(
            _eval_state(call, env))
        return {"verdict": "ALLOW" if res.permitted else "BLOCK",
                "rule": (res.metadata or {}).get("rule"),
                "reason": reason or res.reason}

    def propose(self, call: dict, lease_ttl_s: float = 60.0) -> Outcome:
        call = copy.deepcopy(call)
        env_error = ""
        op = str((call.get("args") or {}).get("operation_id", ""))
        try:
            env = self.envelope_snapshot()
        except Exception as e:                       # noqa: BLE001
            env = None
            env_error = f"{type(e).__name__}: {e}"
        # The kernel reads trusted facts inside its own lock. With no
        # observed state it receives no envelope and the rules fail closed.
        self.ctx.trusted_facts = {E.FACT: env} if env is not None else {}
        local = (self.local_view(call, env) if env is not None else
                 {"verdict": "BLOCK", "rule": E.LOCAL_RULE,
                  "reason": f"collection state unavailable ({env_error})"})
        decision = self.kernel.authorize(call)
        verdict = VERDICT_LABEL[decision.verdict]
        global_ = {"verdict": verdict, "layer": decision.layer,
                   "rule": decision.rule, "reason": decision.reason}
        if decision.rule == E.GLOBAL_RULE and env is not None:
            global_["reason"] = E.global_violation(
                _eval_state(call, env, self._prefix_for(call))) or decision.reason
        if decision.rule == E.LOCAL_RULE:
            global_["note"] = "refused by a local rule before any global limit applied"
        lease = None
        if decision.permitted:
            with self._lock:
                token = self.kernel.mint_lease(decision, ttl_s=lease_ttl_s)
                self._leases[op] = decision
            lease = token.encode()
        return Outcome(verdict=verdict, local=local, global_=global_,
                       decision=_decision_record(decision), lease=lease,
                       operation_id=op)

    def _prefix_for(self, call: dict) -> list:
        """The kernel's governed prefix, for a human-readable global reason.
        Display only; reads kernel internals and never decides."""
        k = self.kernel
        try:
            keys = k._scope_keys(call)  # pylint: disable=protected-access
            return k._shared_history(keys) + k.executed_history  # pylint: disable=protected-access
        except Exception:                            # noqa: BLE001
            return k.executed_history

    def approve(self, call: dict, ttl_s: float = 600.0) -> dict:
        """Finance approver signs an approval bound to this exact action."""
        art = issue_approval(call, issuer=FINANCE_APPROVER, key=self.approval_key,
                             ttl_s=ttl_s, principal=AGENT_PRINCIPAL, tenant=TENANT)
        with self._lock:
            self._approvals.append(art)
            self.ctx.approvals = tuple(self._approvals)
        return {"issuer": art.issuer, "bound_action_hash": art.action_hash,
                "expires_at": art.expires_at}

    def evidence(self) -> dict:
        return {"integrity": self.kernel.integrity(),
                "records": [json.loads(r.to_json())
                            for r in self.kernel.chain.records]}


def _eval_state(call: dict, env: dict, prefix: Optional[list] = None):
    """Rebuild the evaluation state the engine sees for the candidate, to
    render a precise reason string. Display only; never decides."""
    from morrison_governance.kernel.canonical import canonicalize
    from morrison_governance.trajectory import TrajectoryExtractor
    clean = canonicalize(call)
    steps = list(prefix or []) + [clean]
    ex = TrajectoryExtractor(context={E.FACT: env})
    traj = ex.from_plan(steps) if len(steps) > 1 else ex.from_dict(steps[0])
    return traj.states[-1].to_eval_dict()


def _decision_record(d) -> dict:
    return {
        "verdict": VERDICT_LABEL[d.verdict], "kernel_verdict": d.verdict,
        "layer": d.layer, "rule": d.rule, "reason": d.reason,
        "requirement": d.requirement, "capabilities": sorted(d.capabilities),
        "authorization": d.authorization, "action_hash": d.action_hash,
        "decision_id": d.decision_id, "ruleset_hash": d.ruleset_hash,
        "trajectory_hash": d.trajectory_hash,
        "evidence_hash": d.evidence.record_hash if d.evidence else None,
        "issued_at": d.issued_at, "expires_at": d.expires_at,
        "continuity_scope": d.continuity_scope,
        "decision_time_ms": round(d.decision_time_ms, 3),
    }
