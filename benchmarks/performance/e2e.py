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

"Evidence persistence" is measured as appending the decision's sealed
evidence record to a JSONL file with fsync, which is what a deployment
would add; the kernel's own evidence chain is in memory (its cost is the
`evidence_sealing` stage inside authorize).
"""

from __future__ import annotations

import argparse
import json
import os
import threading
import time

from benchmarks.performance.common import (
    Deployment, Resource, environment, percentiles, write_json,
)

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
        evidence_path) -> dict:
    lat = {k: [] for k in ("verdict", "mint", "verify_commit", "commit", "evidence",
                           "total_commit", "total_refusal")}
    errors = []
    lock = threading.Lock()
    per_worker = n_ops // workers

    def worker(w):
        kernel = None
        evf = open(evidence_path, "a") if arm != "ungoverned" else None
        local = {k: [] for k in lat}
        for i in range(per_worker):
            p = f"w{w}s{i // SESSION}"
            if arm != "ungoverned" and (i % SESSION == 0):
                kernel = dep.kernel(p, mediated=(arm == "mediated"))
            prohibited = (i % 10 == 9)
            call = _prohibited(p, i) if prohibited else _calls(p, i)
            try:
                t0 = time.perf_counter_ns()
                if arm == "ungoverned":
                    res.apply(call, p)
                    t1 = time.perf_counter_ns()
                    local["commit"].append(t1 - t0)
                    local["total_commit"].append(t1 - t0)
                    continue
                d = kernel.authorize(call)
                t1 = time.perf_counter_ns()
                local["verdict"].append(t1 - t0)
                if d.verdict != "PERMIT":
                    rec = d.evidence.to_json() if d.evidence is not None else "{}"
                    te = time.perf_counter_ns()
                    evf.write(rec + "\n")
                    evf.flush()
                    os.fsync(evf.fileno())
                    t2 = time.perf_counter_ns()
                    local["evidence"].append(t2 - te)
                    local["total_refusal"].append(t2 - t0)
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
                rec = d.evidence.to_json() if d.evidence is not None else "{}"
                te = time.perf_counter_ns()
                evf.write(rec + "\n")
                evf.flush()
                os.fsync(evf.fileno())
                t4 = time.perf_counter_ns()
                local["evidence"].append(t4 - te)
                local["total_commit"].append(t4 - t0)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {exc}"[:200])
        if evf:
            evf.close()
        with lock:
            for k, v in local.items():
                lat[k].extend(v)

    t0 = time.perf_counter()
    ths = [threading.Thread(target=worker, args=(w,)) for w in range(workers)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    wall = time.perf_counter() - t0
    return {"arm": arm, "workers": workers, "ops": per_worker * workers, "wall_s": wall,
            "throughput_per_s": per_worker * workers / wall,
            "latency": {k: percentiles(v) for k, v in lat.items() if v},
            "errors": len(errors), "error_examples": errors[:5]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ops", type=int, default=2000)
    ap.add_argument("--levels", default="1,4,16,64")
    a = ap.parse_args(argv)
    out = []
    for workers in [int(x) for x in a.levels.split(",")]:
        for arm in ("ungoverned", "inprocess", "mediated"):
            dep = Deployment()
            dep.principals = [f"w{w}s{s}" for w in range(workers)
                              for s in range(a.ops // workers // SESSION + 1)]
            res = Resource(dep.workdir / "resource.db", dep.principals,
                           governed=(arm == "mediated"), verifier=dep.verifier)
            r = run(arm, a.ops, workers, dep, res, dep.workdir / "evidence.jsonl")
            r["resource_effects"] = len(res.effects())
            out.append(r)
            tot = r["latency"].get("total_commit", {})
            print(json.dumps({"arm": arm, "workers": workers,
                              "throughput": round(r["throughput_per_s"], 1),
                              "commit_p50_us": round(tot.get("p50_us", 0), 1),
                              "commit_p99_us": round(tot.get("p99_us", 0), 1),
                              "errors": r["errors"]}), flush=True)
    write_json("e2e.json", {"environment": environment(), "session_length": SESSION,
                            "label": "PRE-PRODUCTION local boundary (SQLite, in-process keys)",
                            "results": out})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
