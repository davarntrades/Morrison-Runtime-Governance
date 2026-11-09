"""Probe: sealed decision evidence does not bind the action it authorises.

H-EVID-01
---------
`_authorize_locked` seals the decision record with:

    action_hash=ahash,          # hash of `proposed`
    proposed=clean,             # the action AFTER quarantine removed fields

For any action carrying a quarantined field, `action_hash` is the hash of an
action whose content is NOT the `proposed` field of the record. `verify()` still
returns True, because the record hash covers the inconsistent pair. So the
chain is "intact" while the only human-readable action in it is a different
action from the one that was authorised and executed.

The intent record (`_record_intent`) DOES carry the full action, so the payload
is somewhere in the chain — but the decision record, which is what an auditor
reads to see what was permitted, shows the cleaned proposal.

Run:  python3 redteam/deepseek_redteam/probe_evidence.py
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
from morrison_governance.kernel.canonical import action_hash

KEY = b"probe-key"
MANIFEST = {"apply_config": []}


class Runtime:
    def __call__(self, call):
        return {"ok": True}


def ctx() -> SecurityContext:
    return SecurityContext(
        principal=Principal(id="agent-a", tenant="acme"),
        signing_key=KEY, trusted_issuers=frozenset({"security-review"}),
        tool_manifest=MANIFEST, unknown_tool_policy="escalate")


def layer() -> GovernanceLayer:
    return GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY], log_all=False)


if __name__ == "__main__":
    call = {"tool": "apply_config",
            "args": {"policy": {"audit_logging": False,
                                "note": "this payload executed"}}}
    k = GovernanceKernel(layer(), ctx(), session_id="evid-probe")
    d = k.authorize(call)
    ok, _ = k.execute(d, Runtime())

    rec = d.evidence
    print(f"verdict          : {d.verdict}  executed={ok}")
    print(f"executed action  : {d.action}")
    print(f"decision hash    : {d.action_hash}")
    print(f"record.action_hash: {rec.action_hash}")
    print(f"record.proposed  : {rec.proposed}")
    print(f"hash(record.proposed) == record.action_hash ? "
          f"{action_hash(rec.proposed) == rec.action_hash}")
    print(f"record.proposed == executed action ? "
          f"{rec.proposed == d.action}")
    print(f"chain integrity  : {k.integrity()}")
    print()
    print("Decision records (what an auditor reads):")
    for r in k.chain.records:
        print(f"  seq={r.seq} layer={r.layer:22s} decision={r.decision:8s} "
              f"executed={r.executed} proposed={r.proposed}")
