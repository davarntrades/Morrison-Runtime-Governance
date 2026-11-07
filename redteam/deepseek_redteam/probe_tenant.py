"""Probe: nested tenant identity escapes the cross-tenant check (H-TEN-01).

`_cross_tenant` compares only keys in `_TENANT_KEYS` at the TOP level.  Nested
identity fields are quarantined by `quarantine_authority`, which re-keys them
as JSON-pointer-ish paths ("/request/tenant").  The cross-tenant comparison
therefore never sees the field, and the regex fallback only catches
`tenant_*`-shaped VALUES.  An opaque tenant id under a nested key passes.

Run:  python3 redteam/deepseek_redteam/probe_tenant.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    GovernanceKernel, Principal, SecurityContext,
)
from morrison_governance.kernel import capabilities as C

KEY = b"probe-key"
MANIFEST = {"read_file": [C.CAP_DATA_READ],
            "query_db": [C.CAP_DATA_READ]}


class Runtime:
    def __init__(self):
        self.executed = []

    def __call__(self, call):
        self.executed.append(call)
        return {"ok": True}


def ctx() -> SecurityContext:
    return SecurityContext(
        principal=Principal(id="agent-a", tenant="acme"),
        signing_key=KEY, trusted_issuers=frozenset({"security-review"}),
        tool_manifest=MANIFEST, unknown_tool_policy="escalate")


def layer() -> GovernanceLayer:
    return GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY], log_all=False)


def run(label, call):
    k = GovernanceKernel(layer(), ctx(), session_id=f"s-{label}")
    rt = Runtime()
    d = k.authorize(call)
    ok, _ = k.execute(d, rt)
    print(f"--- {label}")
    print(f"    verdict : {d.verdict:9s} layer={d.layer:12s} rule={d.rule}")
    print(f"    reason  : {d.reason[:150]}")
    print(f"    executed: {ok}  reached={rt.executed}")
    return d, rt


if __name__ == "__main__":
    run("top-level tenant (control)",
        {"tool": "read_file",
         "args": {"tenant": "globex", "path": "/data/customers.csv"}})

    run("nested tenant under request",
        {"tool": "read_file",
         "args": {"request": {"tenant": "globex",
                              "path": "/data/customers.csv"}}})

    run("nested tenant_id under request",
        {"tool": "read_file",
         "args": {"request": {"tenant_id": "globex",
                              "path": "/data/customers.csv"}}})

    run("nested account_id under request",
        {"tool": "query_db",
         "args": {"request": {"account_id": "acct-globex-77",
                              "sql": "SELECT * FROM customers"}}})

    run("nested tenant_b-shaped (control)",
        {"tool": "read_file",
         "args": {"request": {"tenant": "tenant_b",
                              "path": "/data/customers.csv"}}})
