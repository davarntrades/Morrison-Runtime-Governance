"""Phase 5: end-to-end execution-boundary benchmark (PRE-PRODUCTION, local).

Path measured, per proposal:

  proposal -> GovernanceKernel.authorize (authority, local + global
  admissibility, verdict, sealed evidence) -> [PERMIT] kernel.mint_lease
  (Ed25519 sign + shared lease registry) -> Resource.apply: LeaseVerifier
  verify + atomic redemption -> SQLite transaction commit
  -> durable evidence append (fsync)

  ungoverned: the SAME Resource.apply business logic and SQLite database,
  with no kernel and no lease check.

  inprocess: authorize -> kernel.execute(decision, Resource.apply) - the
  kernel's own boundary, no lease (the in-process deployment).

This is a local, single-host, pre-production measurement: SQLite on local
disk, keys in process memory, no network hop to a gateway. It is NOT a
production end-to-end figure.

Evidence persistence. The frozen results (results/e2e.json) appended only
each DECISION record, from every kernel, into one shared file: no execution
intent or outcome was ever persisted, and the file could not be recomputed as
a chain (independent review, finding B). Each kernel now persists its whole
chain write-ahead through `JsonlEvidenceSink` (one fsynced file per chain), so
the evidence cost is inside the measured path, and after each arm the chain
files are recomputed and joined to the resource's effects by decision id.
Legitimate completion is reported with every legitimate proposal in the
denominator (finding C).
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from collections import Counter

from benchmarks.performance.common import (
    POLICIES, Deployment, Resource, environment, percentiles, set_results_dir,
    write_json,
)
from morrison_governance.kernel.attestation import reconcile_execution_evidence
from morrison_governance.kernel.evidence import JsonlEvidenceSink


class TimedSink:
    """JsonlEvidenceSink that also records how long each durable write took."""

    def __init__(self, path, samples: list) -> None:
        self.inner, self.samples = JsonlEvidenceSink(path), samples

    def __call__(self, rec) -> None:
        t0 = time.perf_counter_ns()
        self.inner(rec)
        self.samples.append(time.perf_counter_ns() - t0)

SESSION = 8           # proposals per principal before a new principal (bounded history)


def _calls(p: str, i: int):
    j = i % 4
    if j == 0:
        return {"tool": "read_doc", "args": {"id": f"pub-{i}"}}
    if j == 1:
        return {"tool": "run_query", "args": {"sql": f"SELECT name FROM vendors WHERE id = {i}"}}
    if j == 2:
        return {"tool": "send_email", "args": {"to": "ops@acme.example", "body": f"Report {i}."}}
    return {"tool": "transfer", "args": {"from": f"OPS-{p}", "to": f"VENDOR-{i}", "amount": 100}}


def _prohibited(p: str, i: int):
    return {"tool": "transfer", "args": {"from": f"OPS-{p}", "to": "EXT-BLOCKED", "amount": 100}} \
        if i % 2 else {"tool": "run_query", "args": {"sql": "TRUNCATE customers"}}


def run(arm: str, n_ops: int, workers: int, dep: Deployment, res: Resource,
        evidence_dir) -> dict:
    lat = {k: [] for k in ("verdict", "mint", "verify_commit", "commit",
                           "evidence_record_fsync", "total_commit", "total_refusal")}
    errors = []
    outcomes: list[dict] = []
    sinks: list = []
    lock = threading.Lock()
    per_worker = n_ops // workers
    if arm != "ungoverned":
        evidence_dir.mkdir(parents=True, exist_ok=True)

    def worker(w):
        kernel = None
        local = {k: [] for k in lat}
        mine: list[dict] = []
        for i in range(per_worker):
            p = f"w{w}s{i // SESSION}"
            if arm != "ungoverned" and (i % SESSION == 0):
                sink = TimedSink(evidence_dir / f"{p}.jsonl", local["evidence_record_fsync"])
                with lock:
                    sinks.append(sink)
                kernel = dep.kernel(p, mediated=(arm == "mediated"), evidence_sink=sink)
            prohibited = (i % 10 == 9)
            call = _prohibited(p, i) if prohibited else _calls(p, i)
            row = {"legitimate": not prohibited, "tool": call["tool"], "position": i % SESSION,
                   "verdict": None, "decision_id": None, "error": None}
            mine.append(row)
            try:
                t0 = time.perf_counter_ns()
                if arm == "ungoverned":
                    res.apply(call, p)
                    t1 = time.perf_counter_ns()
                    local["commit"].append(t1 - t0)
                    local["total_commit"].append(t1 - t0)
                    row["verdict"] = "UNGOVERNED"
                    continue
                d = kernel.authorize(call)
                t1 = time.perf_counter_ns()
                local["verdict"].append(t1 - t0)
                row.update(verdict=d.verdict, decision_id=d.decision_id, layer=d.layer,
                           rule=d.rule, reason=d.reason[:120])
                if d.verdict != "PERMIT":
                    local["total_refusal"].append(t1 - t0)
                    continue
                if arm == "mediated":
                    lease = kernel.mint_lease(d)
                    token = lease.encode()
                    t2 = time.perf_counter_ns()
                    res.apply(call, p, d.decision_id, token)
                    t3 = time.perf_counter_ns()
                    local["mint"].append(t2 - t1)
                    local["verify_commit"].append(t3 - t2)
                else:
                    ok, out = kernel.execute(d, lambda req: res.apply(req, p, d.decision_id))
                    if not ok:
                        raise RuntimeError(str(out))
                    t3 = time.perf_counter_ns()
                    local["commit"].append(t3 - t1)
                local["total_commit"].append(t3 - t0)
            except Exception as exc:  # noqa: BLE001
                row["error"] = f"{type(exc).__name__}: {exc}"[:200]
                errors.append(row["error"])
        with lock:
            for k, v in local.items():
                lat[k].extend(v)
            outcomes.extend(mine)

    t0 = time.perf_counter()
    ths = [threading.Thread(target=worker, args=(w,)) for w in range(workers)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    wall = time.perf_counter() - t0
    for sink in sinks:
        sink.inner.close()
    effects = res.effects()
    effect_ids = Counter(e["decision_id"] for e in effects)
    if arm == "ungoverned":
        executed = [r for r in outcomes]       # every proposal is applied
        evidence = None
    else:
        executed = [r for r in outcomes if r["decision_id"] and effect_ids.get(r["decision_id"])]
        chains = [f.read_text() for f in sorted(evidence_dir.glob("*.jsonl"))]
        rec = reconcile_execution_evidence(chains, effects, mediated=(arm == "mediated"))
        evidence = {"ok": rec["ok"], "chain_files": len(chains), "counts": rec["counts"],
                    "problem_count": len(rec["problems"]), "problems": rec["problems"][:20]}
    done = {id(r) for r in executed}
    legit = [r for r in outcomes if r["legitimate"]]
    proh = [r for r in outcomes if not r["legitimate"]]

    def pct(a, b):
        return round(100.0 * a / b, 3) if b else None
    accounting = {
        "legitimate_total": len(legit),
        "legitimate_authorized": sum(r["verdict"] in ("PERMIT", "UNGOVERNED") for r in legit),
        "legitimate_executed": sum(id(r) in done for r in legit),
        "legitimate_executed_pct": pct(sum(id(r) in done for r in legit), len(legit)),
        "prohibited_total": len(proh),
        "prohibited_executed": sum(id(r) in done for r in proh),
        "legitimate_not_executed": [list(k) + [v] for k, v in Counter(
            (r["tool"], r["position"], r["verdict"], r.get("layer"), r.get("rule"),
             r.get("reason")) for r in legit if id(r) not in done).most_common()],
    }
    return {"arm": arm, "workers": workers, "ops": per_worker * workers, "wall_s": wall,
            "throughput_per_s": per_worker * workers / wall,
            "latency": {k: percentiles(v) for k, v in lat.items() if v},
            "errors": len(errors), "error_examples": errors[:5],
            "accounting": accounting, "evidence": evidence}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ops", type=int, default=2000)
    ap.add_argument("--levels", default="1,4,16,64")
    ap.add_argument("--policy", choices=POLICIES, default="default")
    ap.add_argument("--out", help="results directory (the frozen results/ is refused)")
    a = ap.parse_args(argv)
    if a.out:
        set_results_dir(a.out)
    out = []
    for workers in [int(x) for x in a.levels.split(",")]:
        for arm in ("ungoverned", "inprocess", "mediated"):
            dep = Deployment(policy=a.policy)
            dep.principals = [f"w{w}s{s}" for w in range(workers)
                              for s in range(a.ops // workers // SESSION + 1)]
            res = Resource(dep.workdir / "resource.db", dep.principals,
                           governed=(arm == "mediated"), verifier=dep.verifier)
            r = run(arm, a.ops, workers, dep, res, dep.workdir / "evidence")
            r["resource_effects"] = len(res.effects())
            out.append(r)
            tot = r["latency"].get("total_commit", {})
            print(json.dumps({"arm": arm, "workers": workers,
                              "throughput": round(r["throughput_per_s"], 1),
                              "commit_p50_us": round(tot.get("p50_us", 0), 1),
                              "commit_p99_us": round(tot.get("p99_us", 0), 1),
                              "legit_executed_pct": r["accounting"]["legitimate_executed_pct"],
                              "prohibited_executed": r["accounting"]["prohibited_executed"],
                              "evidence_ok": (r["evidence"] or {}).get("ok"),
                              "errors": r["errors"]}), flush=True)
    write_json("e2e.json", {"environment": environment(), "session_length": SESSION,
                            "policy": a.policy,
                            "label": "PRE-PRODUCTION local boundary (SQLite, in-process keys)",
                            "results": out})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
