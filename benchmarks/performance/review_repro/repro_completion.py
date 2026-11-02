"""Reproduce the legitimate-completion accounting (session load + e2e)."""
import json, collections, gzip, sys
from pathlib import Path
from benchmarks.performance import e2e
from benchmarks.performance.common import Deployment, Resource
R = Path("benchmarks/performance/results")
out = {"frozen": {}, "rerun_reasons": {}}
# 1. Frozen raw data: legitimate incl. special cases vs. the published denominator
for f in sorted(R.glob("load-*-raw.json.gz")):
    raw = json.load(gzip.open(f))
    for lvl, recs in raw.items():
        L = [r for r in recs if r["expected"] == "legitimate"]
        Lp = [r for r in L if not r["special"]]
        out["frozen"][f"{f.name}:{lvl}"] = {
            "published_denominator": len(Lp), "published_executed": sum(r["executed"] for r in Lp),
            "all_legit": len(L), "all_legit_executed": sum(r["executed"] for r in L),
            "pct_all": round(100 * sum(r["executed"] for r in L) / len(L), 1),
            "not_executed_kinds": dict(collections.Counter(r["kind"] for r in L if not r["executed"]))}
d = json.load(open(R / "e2e.json"))
for r in d["results"]:
    if r["arm"] == "ungoverned": continue
    per = r["ops"] // r["workers"]
    legit = r["workers"] * sum(1 for i in range(per) if i % 10 != 9)
    out["frozen"][f"e2e:{r['arm']}:{r['workers']}"] = {"legit": legit, "effects": r["resource_effects"],
        "pct": round(100 * r["resource_effects"] / legit, 1)}
# 2. Re-run e2e (in-process, 1 worker, 200 ops) and record WHY legitimate proposals were refused
dep = Deployment(); dep.principals = [f"w0s{s}" for s in range(200 // e2e.SESSION + 1)]
res = Resource(dep.workdir / "r.db", dep.principals, governed=False)
reasons = collections.Counter(); kernel = None
for i in range(200):
    p = f"w0s{i // e2e.SESSION}"
    if i % e2e.SESSION == 0: kernel = dep.kernel(p, mediated=False)
    if i % 10 == 9: call = e2e._prohibited(p, i)
    else: call = e2e._calls(p, i)
    dd = kernel.authorize(call)
    if dd.verdict == "PERMIT":
        kernel.execute(dd, lambda c: res.apply(c, p, dd.decision_id))
    elif i % 10 != 9:
        reasons[(call["tool"], i % e2e.SESSION, dd.verdict, dd.layer, dd.rule, dd.reason[:110])] += 1
out["rerun_reasons"]["e2e_inprocess_1w_200ops"] = [list(k) + [v] for k, v in reasons.most_common()]
# 3. Session workload: why is the legitimate double_execute case refused?
from benchmarks.performance.load import run_worker
from benchmarks.performance.common import all_principals
dep = Deployment(); dep.principals = all_principals(1, "session")
res = Resource(dep.workdir / "r2.db", dep.principals, governed=False)
recs = run_worker(dep, res, 0, "inprocess", None, "session")
out["rerun_reasons"]["session_double_execute"] = [ (r["kind"], r["verdict"], r.get("layer"), r.get("rule")) for r in recs if r["kind"] in ("double_execute", "policy_change_between_eval_and_exec")]
k = dep.kernel("p0", mediated=False)
print(json.dumps(out, indent=1, default=str))
