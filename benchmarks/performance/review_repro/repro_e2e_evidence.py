"""Reproduce: e2e durable evidence omits execution outcomes and does not recompute."""
import json, sys, collections
from benchmarks.performance.common import Deployment, Resource
from benchmarks.performance import e2e
from morrison_governance.kernel.attestation import recompute_chain
out = {}
for arm in ("inprocess", "mediated"):
    for workers in (1, 4):
        dep = Deployment(); dep.principals = [f"w{w}s{s}" for w in range(workers) for s in range(40 // workers // e2e.SESSION + 1)]
        res = Resource(dep.workdir / "r.db", dep.principals, governed=(arm == "mediated"), verifier=dep.verifier)
        ev = dep.workdir / "evidence.jsonl"
        r = e2e.run(arm, 40, workers, dep, res, ev)
        lines = ev.read_text().splitlines()
        recs = [json.loads(l) for l in lines]
        v = recompute_chain(ev.read_text())
        out[f"{arm}-{workers}"] = {
            "persisted_records": len(recs), "resource_effects": len(res.effects()),
            "records_executed_true": sum(bool(x.get("executed")) for x in recs),
            "layers": dict(collections.Counter(x["layer"] for x in recs)),
            "distinct_actors": len({x["actor"] for x in recs}),
            "recompute_ok": v.ok, "recompute_problems": len(v.problems), "first_problems": v.problems[:3]}
print(json.dumps(out, indent=1))
