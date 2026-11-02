"""Reproduce: a valid approval permits destructive SQL that the benchmark
oracle labels PROHIBITED ('must not execute under any interleaving')."""
import json, secrets, dataclasses
from benchmarks.performance.common import Deployment, Resource, present
from morrison_governance.kernel import capabilities as C, policy as P
out = []
for sql in ["DROP/**/TABLE customers", "TRUNCATE customers", "UPDATE accounts SET balance=0",
            "EXECUTE IMMEDIATE 'DR'||'OP TABLE customers'"]:
    for tool in ("run_query",):
        dep = Deployment(); dep.principals = ["a"]
        res = Resource(dep.workdir / "r.db", dep.principals, governed=False)
        k = dep.kernel("a", mediated=False)
        call = {"tool": tool, "args": {"sql": sql}}
        d0 = k.authorize(call)
        present(k, (dep.approve(call, "a"),))
        d1 = k.authorize(call); present(k, ())
        ran = []
        ok = False
        if d1.verdict == "PERMIT":
            ok, _ = k.execute(d1, lambda c: (res.apply(c, "a", d1.decision_id), ran.append(1)))
        out.append({"sql": sql, "no_approval": [d0.verdict, d0.rule, d0.requirement],
                    "valid_approval": [d1.verdict, d1.rule, d1.requirement, sorted(d1.capabilities)],
                    "executed": bool(ran), "resource_effects": len(res.effects())})
# shell + unknown tool carrying SQL
for call in [{"tool": "run_maintenance", "args": {"command": "find /data -delete"}},
             {"tool": "helper_tool", "args": {"input": "TRUNCATE customers"}}]:
    dep = Deployment(); dep.principals = ["a"]
    k = dep.kernel("a", mediated=False)
    present(k, (dep.approve(call, "a"),)); d1 = k.authorize(call)
    out.append({"call": call, "valid_approval": [d1.verdict, d1.rule, d1.requirement, d1.layer]})
print(json.dumps({"default_capability_policy_data.destructive": P.CAPABILITY_POLICY[C.CAP_DATA_DESTRUCTIVE],
                  "benchmark_overrides_capability_policy": "capability_policy" in (Deployment().kernel('x').ctx.policy_values or {}),
                  "results": out}, indent=1))
