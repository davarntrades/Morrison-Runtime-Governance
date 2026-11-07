"""R2-L — concurrency composition probes (negative results).

Each probe attempts to compose the repaired controls:
  1. max_outstanding_reservations under N concurrent authorizations
  2. the same across two kernels sharing one continuity store
  3. concurrent execute() of one decision
  4. concurrent evidence append + verify
  5. one approval across two sessions / ten kernels
  6. shared-resource aggregate outflow across two principals
  7. one decision redeemed by two kernels with the same session and store

All executors are inert recorders. No probe modifies enforcement code.
"""

from __future__ import annotations

import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))))
from redteam.deepseek_redteam_round2 import _common as K
from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule
from morrison_governance.kernel import (
    GovernanceKernel, Principal, SecurityContext, issue_approval,
)
from morrison_governance.kernel.canonical import action_hash
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.evidence import EvidenceChain, EvidenceRecord

READ = {"tool": "read_file", "args": {"path": "/data/x"}}


def _cap_single():
    k = K.make_kernel(max_outstanding_reservations=8)
    def go(i):
        d = k.authorize({"tool": "read_file", "args": {"path": f"/data/{i}"}})
        return (d.verdict, d.rule)
    with ThreadPoolExecutor(max_workers=40) as pool:
        rows = list(pool.map(go, range(40)))
    c = Counter(rows)
    return {"permits": c[("PERMIT", None)],
            "escalations": c[("ESCALATE", "too_many_outstanding_reservations")],
            "other": {str(k2): v for k2, v in c.items()
                      if k2 not in (("PERMIT", None),
                                    ("ESCALATE",
                                     "too_many_outstanding_reservations"))}}


def _cap_shared_store():
    store = InMemoryContinuityStore()
    k1 = K.make_kernel(store=store, max_outstanding_reservations=8)
    k2 = K.make_kernel(store=store, max_outstanding_reservations=8)
    def go(i):
        kk = k1 if i % 2 == 0 else k2
        d = kk.authorize({"tool": "read_file", "args": {"path": f"/data/{i}"}})
        return (d.verdict, d.rule)
    with ThreadPoolExecutor(max_workers=40) as pool:
        rows = list(pool.map(go, range(40)))
    c = Counter(rows)
    return {"permits": c[("PERMIT", None)],
            "escalations": c[("ESCALATE", "too_many_outstanding_reservations")]}


def _execute_once():
    k = K.make_kernel()
    d = k.authorize(READ)
    effects = {"n": 0}
    def go(_):
        ok, _detail = k.execute(d, lambda a: effects.__setitem__(
            "n", effects["n"] + 1))
        return ok
    with ThreadPoolExecutor(max_workers=20) as pool:
        outs = list(pool.map(go, range(20)))
    return {"successes": sum(1 for o in outs if o),
            "effects": effects["n"],
            "ledger_states": [a.state for a in k.ledger]}


def _evidence_race():
    chain = EvidenceChain(key=b"round2-evidence")
    def ap(i):
        return chain.append(EvidenceRecord(
            seq=0, timestamp=time.time(), actor="a", tenant="t",
            action_hash=action_hash({"tool": "x", "args": {"i": i}}),
            proposed={"tool": "x", "args": {"i": i}}, decision="PERMIT",
            evaluated={"tool": "x", "args": {"i": i}})).seq
    with ThreadPoolExecutor(max_workers=20) as pool:
        seqs = list(pool.map(ap, range(40)))
    return {"unique_seqs": len(set(seqs)), "records": len(chain.records),
            "verified": chain.verify()[0], "problems": chain.verify()[1]}


def _approval_cross_session():
    T = time.time()
    call = {"tool": "delete_bucket", "args": {"bucket": "prod"}}
    art = issue_approval(call, "security-review", K.SIGNING_KEY, ttl_s=300,
                         principal="agent", tenant="acme", now=T)
    store = InMemoryContinuityStore()
    ctx = SecurityContext(
        principal=Principal(id="agent", tenant="acme"),
        signing_key=K.SIGNING_KEY,
        trusted_issuers=K.TRUSTED_ISSUERS,
        tool_manifest={"delete_bucket": ["infra.destructive"]},
        unknown_tool_policy="escalate",
        continuity_store=store,
        approvals=(art,),
    )
    def mk(sid):
        return GovernanceKernel(GovernanceLayer(domains=K.DOMAINS,
                                                log_all=False),
                                ctx, session_id=sid)
    s1, s2 = mk("s1"), mk("s2")
    d1 = s1.authorize(call, now=T)
    d2 = s2.authorize(call, now=T)
    effects = []
    executed = s1.execute(d1, lambda a: effects.append(a), now=T)
    return {"verdicts": [d1.verdict, d2.verdict],
            "executed": executed[0], "effects": len(effects)}


def _approval_one_use_across_kernels():
    T = time.time()
    call = {"tool": "delete_bucket", "args": {"bucket": "prod"}}
    art = issue_approval(call, "security-review", K.SIGNING_KEY, ttl_s=300,
                         principal="agent", tenant="acme", now=T)
    store = InMemoryContinuityStore()
    def mk():
        ctx = SecurityContext(
            principal=Principal(id="agent", tenant="acme"),
            signing_key=K.SIGNING_KEY,
            trusted_issuers=K.TRUSTED_ISSUERS,
            tool_manifest={"delete_bucket": ["infra.destructive"]},
            unknown_tool_policy="escalate",
            continuity_store=store,
            approvals=(art,),
        )
        return GovernanceKernel(GovernanceLayer(domains=K.DOMAINS,
                                                log_all=False), ctx)
    kernels = [mk() for _ in range(10)]
    def go(i):
        return kernels[i].authorize(call, now=T).verdict
    with ThreadPoolExecutor(max_workers=10) as pool:
        verdicts = list(pool.map(go, range(10)))
    return dict(Counter(verdicts))


def _shared_resource_aggregate():
    limit = 25_000
    call = {"tool": "transfer",
            "args": {"from": "SHARED", "to": "A1", "amount": 20_000}}

    def outflow_rule():
        def check(state):
            import json
            args = state.get("args")
            args = json.loads(args) if isinstance(args, str) else (args or {})
            if state.get("tool") != "transfer" or args.get("from") != "SHARED":
                return False
            total = 0
            for i in range(int(state.get("step", 0))):
                prior = state.get(f"step_{i}_args") or {}
                if (state.get(f"step_{i}_tool") == "transfer"
                        and prior.get("from") == "SHARED"):
                    total += int(prior.get("amount", 0))
            return total + int(args.get("amount", 0)) > limit
        return OmegaRule(OmegaDomain.CUSTOM, "outflow_SHARED",
                         "aggregate outflow", check)

    store = InMemoryContinuityStore()
    def mk(pid):
        ctx = SecurityContext(
            principal=Principal(id=pid, tenant="acme"),
            continuity_store=store,
            tool_manifest={"transfer": ["payment.move_funds"]},
            policy_values={"payment_auto_approve_max": limit},
            resource_scopes=lambda c: (["account:SHARED"]
                                       if c.get("tool") == "transfer" else None),
        )
        layer = GovernanceLayer(domains=K.DOMAINS,
                                custom_rules=[outflow_rule()], log_all=False)
        return GovernanceKernel(layer, ctx)
    ks = {"alice": mk("alice"), "bob": mk("bob")}
    def go(i):
        who = "alice" if i % 2 == 0 else "bob"
        d = ks[who].authorize({"tool": "transfer",
                               "args": {"from": "SHARED", "to": f"A{i}",
                                        "amount": 20_000}})
        return (d.verdict, d.rule)
    with ThreadPoolExecutor(max_workers=10) as pool:
        rows = list(pool.map(go, range(10)))
    c = Counter(rows)
    return {"permits": c[("PERMIT", None)],
            "blocked": c[("BLOCK", "outflow_SHARED")]}


def _same_decision_two_kernels():
    store = InMemoryContinuityStore()
    k1 = K.make_kernel(store=store, session_id="shared")
    k2 = K.make_kernel(store=store, session_id="shared")
    d = k1.authorize(READ)
    effects = []
    def go(k):
        return k.execute(d, lambda a: effects.append(a))[0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        outs = list(pool.map(go, [k1, k2]))
    return {"successes": sum(1 for o in outs if o), "effects": len(effects)}


def main() -> dict:
    K.header("R2-L concurrency composition probes")
    results = {
        "reservation_cap_single_kernel": _cap_single(),
        "reservation_cap_shared_store": _cap_shared_store(),
        "concurrent_execute_one_decision": _execute_once(),
        "concurrent_evidence_append": _evidence_race(),
        "approval_cross_session": _approval_cross_session(),
        "approval_one_use_across_kernels": _approval_one_use_across_kernels(),
        "shared_resource_aggregate": _shared_resource_aggregate(),
        "same_decision_two_kernels": _same_decision_two_kernels(),
    }
    for name, row in results.items():
        print(f"{name}: {row}")

    held = (
        results["reservation_cap_single_kernel"]["permits"] == 8
        and results["reservation_cap_shared_store"]["permits"] == 8
        and results["concurrent_execute_one_decision"]["successes"] == 1
        and results["concurrent_execute_one_decision"]["effects"] == 1
        and results["concurrent_evidence_append"]["unique_seqs"] == 40
        and results["concurrent_evidence_append"]["verified"] is True
        and results["approval_one_use_across_kernels"].get("PERMIT") == 1
        and results["shared_resource_aggregate"]["permits"] == 1
        and results["same_decision_two_kernels"]["successes"] == 1
        and results["same_decision_two_kernels"]["effects"] == 1
    )

    return K.emit({
        "id": "R2-L",
        "title": "Concurrency composition probes",
        "classification": "HELD" if held else "REPRODUCED",
        "held": bool(held),
        "results": results,
        "note": (
            "No concurrency counterexample was found in these compositions. "
            "The reservation cap counts RESERVED and UNCONFIRMED entries and "
            "the store transaction serialises writers; execute() consumes and "
            "commits under the same lock; evidence append is module-locked; "
            "approval replay state is keyed to the continuity identity; and "
            "shared-resource history is read across principals."),
    })


if __name__ == "__main__":
    main()
