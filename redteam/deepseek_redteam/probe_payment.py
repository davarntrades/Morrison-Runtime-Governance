"""Probe: server-owned payment auto-approval threshold (H-PAY-01).

`SecurityContext.policy_values` defaults `payment_auto_approve_max` to 0, and
`kernel/policy.py` documents "0 disables auto-approval entirely".  The gate
tests `amount <= cap_max`, so a NEGATIVE amount satisfies a zero threshold
and is auto-approved, injecting `authorized=True` into the Omega namespace.

Also probes approval-authority widening across tool spellings that
`normalized_tool_name` collapses without an explicit equivalence registry.

Run:  python3 redteam/deepseek_redteam/probe_payment.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    GovernanceKernel, Principal, SecurityContext, issue_approval,
)
from morrison_governance.kernel import capabilities as C

KEY = b"probe-key"
ISSUERS = frozenset({"security-review"})
MANIFEST = {
    "transfer": [C.CAP_PAYMENT],
    "wire_transfer": [C.CAP_PAYMENT],
    "trans-fer": [C.CAP_PAYMENT],
    "read_file": [C.CAP_DATA_READ],
}


class Runtime:
    def __init__(self):
        self.executed = []

    def __call__(self, call):
        self.executed.append(call)
        return {"ok": True}


def ctx() -> SecurityContext:
    return SecurityContext(
        principal=Principal(id="agent-a", tenant="acme"),
        signing_key=KEY, trusted_issuers=ISSUERS,
        tool_manifest=MANIFEST, unknown_tool_policy="escalate",
        # Deliberately empty: this is the shipped default posture.
        policy_values={},
    )


def layer() -> GovernanceLayer:
    return GovernanceLayer(
        domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY],
        log_all=False)


def kernel(_ctx=None) -> GovernanceKernel:
    return GovernanceKernel(layer(), _ctx or ctx(), session_id="pay-probe")


def show(label, d, ok, rt):
    print(f"--- {label}")
    print(f"    verdict : {d.verdict}")
    print(f"    layer   : {d.layer}   rule={d.rule}")
    print(f"    reason  : {d.reason[:160]}")
    print(f"    req     : {d.requirement}  caps={sorted(d.capabilities)}")
    print(f"    approved: {d.authorization.get('approved')}  "
          f"forged={d.forged_claims}")
    print(f"    executed: {ok}  reached={[c['tool'] for c in rt.executed]}")


# ── 1. negative payment amount ───────────────────────────────────────────
for amount in (4_500_000, 0, -1, -4_500_000, "-inf"):
    k = kernel()
    rt = Runtime()
    call = {"tool": "transfer",
            "args": {"amount": amount, "to": "acct-attacker-001",
                     "currency": "USD"}}
    d = k.authorize(call)
    ok, _ = k.execute(d, rt)
    show(f"amount={amount!r}", d, ok, rt)

# ── 2. approval widened across a spelling the normaliser collapses ───────
k = kernel()
rt = Runtime()
approved = {"tool": "transfer", "args": {"amount": 5000, "to": "acct-9"}}
k.ctx.approvals = (issue_approval(
    approved, issuer="security-review", key=KEY, ttl_s=300,
    nonce="probe-alias-nonce-0001", principal="agent-a", tenant="acme"),)

respelled = {"tool": "trans-fer", "args": {"amount": 5000, "to": "acct-9"}}
d = k.authorize(respelled)
ok, _ = k.execute(d, rt)
show("approval(transfer) -> authorize(trans-fer)", d, ok, rt)
