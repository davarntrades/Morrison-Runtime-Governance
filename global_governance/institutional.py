"""Human override / institutional governance — legitimacy layer.

Two asymmetric override powers, audited immutably:

  - A human / institution may ALWAYS add a BLOCK (a veto). More
    restriction needs no special authority.
  - A human / institution may permit something the governance layer
    BLOCKED only with an explicit, scoped, signed Authorization. Without
    a matching authorization, the governance BLOCK stands. This makes
    every override-to-permit accountable and traceable.

Every decision (and every override) is appended to a hash chain so the
institutional record is tamper-evident.

Bounded honesty: this implements the *mechanism* (scoped signed
authorizations + tamper-evident audit). Real political / ethical
legitimacy — who may sign, under what mandate — is a socio-technical /
institutional question outside the code. This layer makes the
mechanism auditable; it does not confer legitimacy."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer


@dataclass
class Authorization:
    """A scoped, signed permission to override a governance BLOCK.
    `scope` matches against the proposed tool (or "*"). `signed_by`
    is the accountable signer. `token` is an opaque credential string
    (verification of real signatures is out of scope here)."""
    scope: str
    signed_by: str
    token: str
    reason: str = ""

    def matches(self, plan: list) -> bool:
        if self.scope == "*":
            return True
        tools = {str(s.get("tool", "")) for s in plan}
        return self.scope in tools


@dataclass
class InstitutionalResult:
    permitted: bool
    base_verdict: str
    overridden: bool
    override_kind: Optional[str]        # "veto_block" | "authorized_permit" | None
    signed_by: Optional[str]
    audit_digest: str
    reason: str = ""

    def as_dict(self) -> dict:
        return {"permitted": self.permitted, "base_verdict": self.base_verdict,
                "overridden": self.overridden,
                "override_kind": self.override_kind,
                "signed_by": self.signed_by,
                "audit_digest": self.audit_digest, "reason": self.reason}


class InstitutionalGovernance:
    def __init__(self, governance: GovernanceLayer):
        self.governance = governance
        self._chain = "GENESIS"
        self.audit_log: list = []

    def _append_audit(self, record: dict) -> str:
        payload = json.dumps({"prev": self._chain, "record": record},
                             sort_keys=True)
        self._chain = hashlib.sha256(payload.encode()).hexdigest()[:16]
        self.audit_log.append({**record, "digest": self._chain})
        return self._chain

    def evaluate(self, plan: list,
                 authorizations: tuple = (),
                 institutional_veto: bool = False) -> InstitutionalResult:
        base = (self.governance.evaluate_plan(plan) if len(plan) > 1
                else self.governance.evaluate(plan[0]))
        base_verdict = base.verdict.value

        # 1. veto: a human can always make it MORE restrictive
        if institutional_veto:
            digest = self._append_audit(
                {"action": "veto_block", "base": base_verdict,
                 "plan_tools": [s.get("tool") for s in plan]})
            return InstitutionalResult(
                permitted=False, base_verdict=base_verdict, overridden=True,
                override_kind="veto_block", signed_by=None,
                audit_digest=digest, reason="institutional veto")

        # 2. governance permitted → permitted (record it)
        if base.permitted:
            digest = self._append_audit(
                {"action": "permit", "base": base_verdict,
                 "plan_tools": [s.get("tool") for s in plan]})
            return InstitutionalResult(
                permitted=True, base_verdict=base_verdict, overridden=False,
                override_kind=None, signed_by=None, audit_digest=digest,
                reason=base.reason)

        # 3. governance BLOCKED → permitted only with a matching signed auth
        for auth in authorizations:
            if auth.matches(plan):
                digest = self._append_audit(
                    {"action": "authorized_permit", "base": base_verdict,
                     "signed_by": auth.signed_by, "scope": auth.scope,
                     "auth_reason": auth.reason,
                     "plan_tools": [s.get("tool") for s in plan]})
                return InstitutionalResult(
                    permitted=True, base_verdict=base_verdict,
                    overridden=True, override_kind="authorized_permit",
                    signed_by=auth.signed_by, audit_digest=digest,
                    reason=(f"authorized permit by {auth.signed_by} "
                            f"(scope={auth.scope})"))

        # 4. no authorization → governance BLOCK stands
        digest = self._append_audit(
            {"action": "block_upheld", "base": base_verdict,
             "plan_tools": [s.get("tool") for s in plan]})
        return InstitutionalResult(
            permitted=False, base_verdict=base_verdict, overridden=False,
            override_kind=None, signed_by=None, audit_digest=digest,
            reason=base.reason)
