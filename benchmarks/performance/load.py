"""Concurrency + adversarial-safety-under-load harness (phases 3, 4, 5).

Each worker owns one kernel (its own principal) and runs the labelled script
from `common.cases_for`. Workers share the continuity store, the lease
registry and the resource, so cross-agent limits and replay are exercised for
real. Two execution modes:

  inprocess  authorize -> kernel.execute(decision, executor) -> SQLite commit.
             The kernel's execute() is the boundary.
  mediated   authorize -> kernel.mint_lease -> Resource verifies and redeems
             the Ed25519 lease in the shared registry -> SQLite commit.

Two parallelism models, reported separately because CPython's GIL makes them
different experiments:

  threads    N threads in one process: concurrent, NOT parallel for Python
             bytecode (GIL). Contention on locks and SQLite is real.
  processes  N processes (fork): genuinely parallel up to the CPU count.
             Cross-process continuity uses FileContinuityStore (flock).

Every outcome is read back from the resource database, never inferred from
a verdict.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import random
import resource as rlimit
import threading
import time
import traceback
from collections import Counter
from pathlib import Path

from benchmarks.performance.common import (
    LEGITIMATE, LIMIT_BOUND, PROHIBITED, SHARED, SHARED_AMOUNT, SHARED_LIMIT,
    Deployment, Resource, cases_for, environment, percentiles, present, write_json,
)


def _rss_mb() -> float:
    try:
        with open("/proc/self/statm") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 2**20
    except OSError:
        return float("nan")


def run_worker(dep: Deployment, res: Resource, index: int, mode: str,
               barrier=None, session: str = "isolated") -> list[dict]:
    """Run one worker's script; return one record per case."""
    kernels: dict = {}
    out = []
    held_approval = None
    for case in cases_for(dep, index, session):
        principal = case.principal
        if principal not in kernels:
            kernels[principal] = dep.kernel(principal, mediated=(mode == "mediated"))
        kernel = kernels[principal]
        rec = {"kind": case.kind, "expected": case.expected, "family": case.family,
               "special": case.special, "principal": principal, "verdict": None,
               "executed": False, "error": None, "refused_at": None}
        approvals = case.approvals
        if case.special == "replay":
            approvals = (held_approval,) if held_approval is not None else ()
        if case.kind == "shared_limit_transfer" and barrier is not None:
            try:
                barrier.wait(timeout=120)
            except threading.BrokenBarrierError:
                pass
        try:
            present(kernel, approvals)
            t0 = time.perf_counter_ns()
            d = kernel.authorize(case.call)
            t1 = time.perf_counter_ns()
            present(kernel, ())
            if case.kind == "approved_large_transfer":
                held_approval = case.approvals[0]
            rec.update(verdict=d.verdict, layer=d.layer, rule=d.rule,
                       verdict_ns=t1 - t0,
                       stages_ms=dict(d.stage_timings_ms),
                       evidence=bool(d.evidence is not None),
                       decision_id=d.decision_id)
            if d.verdict != "PERMIT":
                rec["refused_at"] = "kernel"
                rec["refusal_total_ns"] = t1 - t0
                out.append(rec)
                continue
            if case.special == "policy_change":
                # State changes between evaluation and execution: the payment
                # auto-approval limit is withdrawn after this PERMIT was issued.
                import dataclasses
                kernel.ctx = dataclasses.replace(
                    kernel.ctx, policy_values={"payment_auto_approve_max": 0})
                kernel.refresh_ruleset()
            t2 = time.perf_counter_ns()
            if mode == "mediated":
                try:
                    lease = kernel.mint_lease(d)
                except ValueError as exc:
                    rec.update(refused_at="kernel_boundary", boundary_reason=str(exc)[:160])
                    out.append(rec)
                    continue
                token = lease.encode()
                t3 = time.perf_counter_ns()
                attempts = 2 if case.special == "double_execute" else 1
                results = []

                def attempt():
                    try:
                        res.apply(case.call, principal, d.decision_id, token)
                        results.append(True)
                    except PermissionError as exc:
                        results.append(str(exc)[:160])
                ths = [threading.Thread(target=attempt) for _ in range(attempts)]
                for th in ths:
                    th.start()
                for th in ths:
                    th.join()
                t4 = time.perf_counter_ns()
                rec["executed"] = any(r is True for r in results)
                rec["commit_successes"] = sum(r is True for r in results)
                rec.update(boundary_mint_ns=t3 - t2, boundary_commit_ns=t4 - t3,
                           total_ns=t4 - t0)
                if not rec["executed"]:
                    rec["refused_at"] = "resource"
                    rec["boundary_reason"] = next(r for r in results if r is not True)
            else:
                commits = []

                def run(req):
                    res.apply(req, principal, d.decision_id)
                    commits.append(1)
                    return "ok"
                attempts = 2 if case.special == "double_execute" else 1
                oks = []

                def attempt():
                    ok, why = kernel.execute(d, run)
                    oks.append(ok if ok else str(why)[:160])
                ths = [threading.Thread(target=attempt) for _ in range(attempts)]
                for th in ths:
                    th.start()
                for th in ths:
                    th.join()
                t4 = time.perf_counter_ns()
                rec["executed"] = len(commits) > 0
                rec["commit_successes"] = len(commits)
                rec.update(boundary_commit_ns=t4 - t2, total_ns=t4 - t0)
                if not rec["executed"]:
                    rec["refused_at"] = "kernel_execute"
                    rec["boundary_reason"] = next((o for o in oks if o is not True), "")
        except Exception as exc:  # noqa: BLE001 - errors are results
            rec["error"] = f"{type(exc).__name__}: {exc}"[:240]
            rec["trace"] = traceback.format_exc()[-800:]
        out.append(rec)
    from morrison_governance.kernel.attestation import recompute_chain
    chains = {}
    for name, k in kernels.items():
        try:
            chains[name] = recompute_chain(k.chain.to_jsonl()).ok
        except Exception as exc:  # noqa: BLE001
            chains[name] = f"error: {exc}"
        # Evidence must name the decision: every executed decision has an
        # execution record in its kernel's chain.
    for rec in out:
        rec["evidence_chain_ok"] = chains.get(rec["principal"])
    return out


def _thread_level(n: int, mode: str, dep: Deployment, res: Resource,
                  session: str) -> list[dict]:
    barrier = threading.Barrier(n)
    results: list[list[dict]] = [[] for _ in range(n)]

    def target(i):
        results[i] = run_worker(dep, res, i, mode, barrier, session)
    ths = [threading.Thread(target=target, args=(i,)) for i in range(n)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    return [r for rs in results for r in rs]


def _proc_target(args):
    dep, res_path, index, mode, session, barrier, q = args
    res = Resource(res_path, dep.principals, governed=(mode == "mediated"),
                   verifier=dep.verifier)
    q.put(run_worker(dep, res, index, mode, barrier, session))


def _process_level(n: int, mode: str, dep: Deployment, res_path: Path,
                   session: str) -> list[dict]:
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    barrier = ctx.Barrier(n)
    procs = [ctx.Process(target=_proc_target,
                         args=((dep, res_path, i, mode, session, barrier, q),))
             for i in range(n)]
    for p in procs:
        p.start()
    out = []
    for _ in procs:
        out.extend(q.get(timeout=3600))
    for p in procs:
        p.join()
    return out


def summarise(records: list[dict], res: Resource, n: int, wall_s: float,
              cpu_s: float, rss_mb: float, model: str, mode: str) -> dict:
    by_exp = Counter(r["expected"] for r in records)
    plain = [r for r in records if not r["special"]]
    proh = [r for r in records if r["expected"] == PROHIBITED]
    proh_plain = [r for r in proh if not r["special"]]
    legit = [r for r in plain if r["expected"] == LEGITIMATE]
    shared = [r for r in records if r["expected"] == LIMIT_BOUND]
    effects = res.effects()
    dup = Counter(e["decision_id"] for e in effects if e["decision_id"])
    executed_ids = {r.get("decision_id") for r in records if r["executed"]}
    effect_ids = {e["decision_id"] for e in effects}
    outflow = res.shared_outflow()
    verdict_ns = [r["verdict_ns"] for r in records if "verdict_ns" in r]
    total_ns = [r["total_ns"] for r in records if "total_ns" in r]
    refusal_ns = [r["refusal_total_ns"] for r in records if "refusal_total_ns" in r]
    outside = []
    for r in records:
        if "verdict_ns" in r and r.get("stages_ms"):
            outside.append(max(0, r["verdict_ns"] - int(sum(r["stages_ms"].values()) * 1e6)))
    v = Counter(r["verdict"] for r in proh_plain)
    expected_shared_commits = min(SHARED_LIMIT // SHARED_AMOUNT, len(shared))
    return {
        "model": model, "mode": mode, "workers": n, "proposals": len(records),
        "wall_s": wall_s, "throughput_per_s": len(records) / wall_s if wall_s else None,
        "cpu_utilisation_pct": 100.0 * cpu_s / wall_s if wall_s else None,
        "rss_mb": rss_mb,
        "verdict_latency": percentiles(verdict_ns),
        "proposal_to_commit_latency": percentiles(total_ns),
        "proposal_to_refusal_latency": percentiles(refusal_ns),
        "outside_kernel_stages_latency": percentiles(outside),
        "by_expected": dict(by_exp),
        "prohibited": {
            "total": len(proh),
            "proposal_level_total": len(proh_plain),
            "block": v.get("BLOCK", 0), "escalate": v.get("ESCALATE", 0),
            "permit": v.get("PERMIT", 0),
            "blocking_rate_pct": 100.0 * v.get("BLOCK", 0) / len(proh_plain) if proh_plain else None,
            "not_permitted_rate_pct": 100.0 * (len(proh_plain) - v.get("PERMIT", 0)) / len(proh_plain)
            if proh_plain else None,
            "incorrectly_permitted_kinds": sorted({r["kind"] for r in proh_plain if r["verdict"] == "PERMIT"}),
            "executed": sum(r["executed"] for r in proh),
            "executed_kinds": sorted({r["kind"] for r in proh if r["executed"]}),
        },
        "legitimate": {
            "total": len(legit),
            "permitted": sum(r["verdict"] == "PERMIT" for r in legit),
            "executed": sum(r["executed"] for r in legit),
            "blocked": sum(r["verdict"] == "BLOCK" for r in legit),
            "escalated": sum(r["verdict"] == "ESCALATE" for r in legit),
            "blocked_or_escalated_kinds": dict(Counter(r["kind"] for r in legit
                                                       if r["verdict"] != "PERMIT")),
        },
        "shared_limit": {
            "proposals": len(shared), "permitted": sum(r["verdict"] == "PERMIT" for r in shared),
            "committed": sum(r["executed"] for r in shared),
            "expected_commits_if_live": expected_shared_commits,
            "outflow": outflow, "limit": SHARED_LIMIT,
            "invariant_holds": outflow <= SHARED_LIMIT,
        },
        "duplicates": {
            "double_execute_cases": sum(r["special"] == "double_execute" for r in records),
            "double_execute_commit_successes_gt1": sum(
                r.get("commit_successes", 0) > 1 for r in records),
            "duplicate_decision_ids_in_resource": sum(c > 1 for c in dup.values()),
        },
        "consistency": {
            "effects": len(effects),
            "effects_without_executed_record": len(effect_ids - executed_ids),
            "executed_without_effect": len(executed_ids - effect_ids),
            "evidence_missing": sum(1 for r in records if r["verdict"] and not r.get("evidence")),
            "evidence_chain_failures": sum(1 for r in records if r.get("evidence_chain_ok") is not True),
        },
        "errors": dict(Counter((r["error"] or "").split(":")[0] for r in records if r["error"])),
        "error_rate_pct": 100.0 * sum(1 for r in records if r["error"]) / len(records),
        "special": {
            "replay_executed": sum(r["executed"] for r in records if r["special"] == "replay"),
            "policy_change_executed": sum(r["executed"] for r in records
                                          if r["special"] == "policy_change"),
            "policy_change_permitted_at_eval": sum(r["verdict"] == "PERMIT" for r in records
                                                   if r["special"] == "policy_change"),
        },
    }


def run_level(n: int, model: str, mode: str, store: str = "memory",
              session: str = "isolated") -> tuple[dict, list]:
    from benchmarks.performance.common import all_principals
    from morrison_governance.kernel.continuity import FileContinuityStore
    dep = Deployment()
    dep.principals = all_principals(n, session)
    if model == "processes" or store == "file":
        dep.store = FileContinuityStore(str(dep.workdir / "continuity.jsonl"))
    res_path = dep.workdir / "resource.db"
    res = Resource(res_path, dep.principals, governed=(mode == "mediated"),
                   verifier=dep.verifier)
    r0 = rlimit.getrusage(rlimit.RUSAGE_SELF)
    c0 = rlimit.getrusage(rlimit.RUSAGE_CHILDREN)
    t0 = time.perf_counter()
    if model == "threads":
        recs = _thread_level(n, mode, dep, res, session)
    else:
        recs = _process_level(n, mode, dep, res_path, session)
    wall = time.perf_counter() - t0
    r1 = rlimit.getrusage(rlimit.RUSAGE_SELF)
    c1 = rlimit.getrusage(rlimit.RUSAGE_CHILDREN)
    cpu = (r1.ru_utime - r0.ru_utime + r1.ru_stime - r0.ru_stime
           + c1.ru_utime - c0.ru_utime + c1.ru_stime - c0.ru_stime)
    peak_self = rlimit.getrusage(rlimit.RUSAGE_SELF).ru_maxrss / 1024
    peak_child = rlimit.getrusage(rlimit.RUSAGE_CHILDREN).ru_maxrss / 1024
    summary = summarise(recs, res, n, wall, cpu, _rss_mb(), model, mode)
    summary["peak_rss_mb_self"] = peak_self
    summary["peak_rss_mb_largest_child"] = peak_child
    summary["session"] = session
    summary["store"] = "file" if (model == "processes" or store == "file") else "memory"
    return summary, recs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=("threads", "processes"), default="threads")
    ap.add_argument("--mode", choices=("inprocess", "mediated"), default="inprocess")
    ap.add_argument("--levels", default="1,2,4,8,16,32,64,128,256")
    ap.add_argument("--store", choices=("memory", "file"), default="memory")
    ap.add_argument("--session", choices=("isolated", "session"), default="isolated")
    ap.add_argument("--tag", default="")
    a = ap.parse_args(argv)
    levels = [int(x) for x in a.levels.split(",")]
    tag = a.tag or f"{a.model}-{a.mode}-{a.session}"
    summaries, raw = [], {}
    for n in levels:
        s, recs = run_level(n, a.model, a.mode, a.store, a.session)
        summaries.append(s)
        raw[str(n)] = recs
        # Written after EVERY level: a later level that is killed (OOM at
        # 1,024 threads in the first run) must not take earlier ones with it.
        write_json(f"load-{tag}.json", {"environment": environment(), "summaries": summaries})
        write_json(f"load-{tag}-raw.json", raw)
        print(json.dumps({k: s[k] for k in ("workers", "wall_s", "throughput_per_s")}
                         | {"verdict_p99_us": s["verdict_latency"].get("p99_us"),
                            "prohibited_executed": s["prohibited"]["executed"],
                            "incorrectly_permitted": s["prohibited"]["incorrectly_permitted_kinds"],
                            "shared_outflow": s["shared_limit"]["outflow"],
                            "errors": s["errors"]}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
