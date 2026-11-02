"""Phase 2: kernel latency, measured operation by operation.

Operations (all on the real kernel objects, nothing stubbed):

  local        capability + destination classification, capability-policy
               requirement, and the Ω engine over the candidate ALONE
               (single-step A_safe/V2/V3/V4 with no history)
  global[H]    the Ω engine over the governed prefix: H prior steps + the
               candidate (trajectory rules, taint, aggregate limits). The
               engine re-checks every state, so this includes per-state local
               checks; the engine does not separate the two.
  combined[H]  local classification + global[H] - the decision work minus
               authority and evidence
  authority    approval verification bound to the exact authorization hash
               (HMAC, principal/tenant/expiry/nonce checks)
  lease_mint / lease_verify
               Ed25519 sign / verify+redeem of an execution lease (the
               resource-side authority check)
  full[H]      GovernanceKernel.authorize(reserve=False) at history H:
               every stage, verdict and the sealed evidence record
  full_commit  authorize(reserve=True) + execute() with the execution record
               (fresh principal per sample, history 0)

Each trial runs in a fresh subprocess (independent interpreter state) with a
warm-up phase; samples are per-call perf_counter_ns. GC stays enabled
(realistic). Cold start is measured separately in fresh processes.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import subprocess
import sys
import time

from benchmarks.performance.common import (
    ROOT, Deployment, environment, percentiles, present, write_json,
)

CALLS = [
    {"tool": "read_doc", "args": {"id": "pub-1"}},
    {"tool": "run_query", "args": {"sql": "SELECT name FROM vendors WHERE id = 7"}},
    {"tool": "send_email", "args": {"to": "ops@acme.example", "body": "Report ready."}},
    {"tool": "transfer", "args": {"from": "OPS-lat", "to": "VENDOR-1", "amount": 1200}},
]
HISTORIES = (0, 8, 32, 128)
SWEEP = (0, 1, 2, 4, 8, 16, 32, 64, 128, 256)
TARGET_S = 6.0          # time budget per operation per trial
WARMUP = 50


def _history(i):
    return {"tool": "read_doc", "args": {"id": f"h-{i}"}}


def _measure(fn, budget_s=TARGET_S, max_n=5000, min_n=150):
    for _ in range(WARMUP):
        fn()
    t = time.perf_counter_ns()
    for _ in range(20):
        fn()
    est = (time.perf_counter_ns() - t) / 20 / 1e9
    n = int(max(min_n, min(max_n, budget_s / max(est, 1e-7))))
    out, errors = [], 0
    for i in range(n):
        t0 = time.perf_counter_ns()
        try:
            fn()
        except Exception:  # noqa: BLE001
            errors += 1
        out.append(time.perf_counter_ns() - t0)
    return out, errors


def trial() -> dict:
    from morrison_governance.kernel import capabilities as C
    from morrison_governance.kernel import policy as P
    from morrison_governance.kernel.canonical import authorization_action_hash, canonicalize
    from morrison_governance.kernel.destinations import classify_destination
    from morrison_governance.trajectory import TrajectoryExtractor

    dep = Deployment()
    dep.principals = ["lat", "lat-auth"] + [f"fc{i}" for i in range(2000)]
    k = dep.kernel("lat", mediated=False)
    layer, ctx = k.layer, k.ctx
    trusted = {"destination_external": False, "destination_internal": True}
    ops: dict = {}
    rr = {"i": 0}

    def nxt():
        rr["i"] += 1
        return canonicalize(CALLS[rr["i"] % len(CALLS)])

    def local():
        call = nxt()
        caps = C.classify(call, ctx.tool_manifest)
        classify_destination(call, ctx.internal_url_hosts, ctx.internal_email_domains)
        P.requirement_for(caps)
        layer.evaluate_trajectory(TrajectoryExtractor(context=trusted).from_dict(call))
    ops["local"] = _measure(local)

    for H in HISTORIES:
        prefix = [_history(i) for i in range(H)]

        def glob(prefix=prefix):
            plan = prefix + [nxt()]
            ex = TrajectoryExtractor(context=trusted)
            layer.evaluate_trajectory(ex.from_plan(plan) if len(plan) > 1 else ex.from_dict(plan[0]))

        def comb(prefix=prefix):
            call = nxt()
            caps = C.classify(call, ctx.tool_manifest)
            classify_destination(call, ctx.internal_url_hosts, ctx.internal_email_domains)
            P.requirement_for(caps)
            plan = prefix + [call]
            ex = TrajectoryExtractor(context=trusted)
            layer.evaluate_trajectory(ex.from_plan(plan) if len(plan) > 1 else ex.from_dict(plan[0]))
        ops[f"global[H={H}]"] = _measure(glob)
        ops[f"combined[H={H}]"] = _measure(comb)

    # authority: exact-action approval verification
    big = {"tool": "transfer", "args": {"from": "OPS-lat-auth", "to": "VENDOR-9", "amount": 6500}}
    appr = dep.approve(big, "lat-auth")
    ka = dep.kernel("lat-auth", mediated=False)
    present(ka, (appr,))
    auth_hash = authorization_action_hash(canonicalize(big), ka.ctx.authorization_equivalences)

    def authority():
        a = authorization_action_hash(canonicalize(big), ka.ctx.authorization_equivalences)
        ok, _ = ka.ctx.verified_approval(a, None)
        assert ok is not None
    assert auth_hash
    ops["authority"] = _measure(authority)

    # Ed25519 lease mint / verify (resource-side authority)
    km = dep.kernel("lat-lease", mediated=True)
    from morrison_governance._ed25519_test_signer import sign
    from morrison_governance.kernel.ed25519 import verify
    msg = b"x" * 400

    def mint():
        sign(dep.lease_seed, msg)
    sig = sign(dep.lease_seed, msg)
    from morrison_governance._ed25519_test_signer import public_key
    pk = public_key(dep.lease_seed)

    def ver():
        assert verify(pk, msg, sig)
    ops["lease_mint(ed25519 sign)"] = _measure(mint, budget_s=3, min_n=100)
    ops["lease_verify(ed25519 verify)"] = _measure(ver, budget_s=3, min_n=100)
    del km

    # full kernel decision at fixed history (preview: does not grow history)
    stages: dict = {}
    for H in HISTORIES:
        kh = dep.kernel(f"hist{H}", mediated=False)
        for i in range(H):
            d = kh.authorize(_history(i))
            kh.execute(d, lambda c: "ok")
        acc = []

        def full(kh=kh, acc=acc):
            d = kh.authorize(CALLS[rr["i"] % 3], reserve=False)
            rr["i"] += 1
            assert d.evidence is not None
            acc.append(d.stage_timings_ms)
        ops[f"full[H={H}]"] = _measure(full)
        keys = sorted({s for a in acc for s in a})
        stages[f"full[H={H}]"] = {s: statistics.fmean(a.get(s, 0.0) for a in acc) for s in keys}

    # full decision + execution record, fresh principal each time (history 0)
    counter = {"i": 0}

    def full_commit():
        counter["i"] += 1
        kf = dep.kernel(f"fc{counter['i']}", mediated=False)
        t0 = time.perf_counter_ns()
        d = kf.authorize(CALLS[0])
        ok, _ = kf.execute(d, lambda c: "ok")
        assert ok
        return time.perf_counter_ns() - t0
    samples = []
    for _ in range(WARMUP):
        full_commit()
    for _ in range(1500):
        samples.append(full_commit())
    ops["full_commit[H=0]"] = (samples, 0)

    # warm session: authorize + execute on a reused kernel, history 0..7,
    # separating first-call-per-session cost from steady per-call cost
    warm = []
    for j in range(250):
        kw = dep.kernel(f"fw{j}", mediated=False)
        kw.authorize(CALLS[0], reserve=False)          # first-call costs, untimed
        for i in range(8):
            t0 = time.perf_counter_ns()
            d = kw.authorize({"tool": "read_doc", "args": {"id": f"w{i}"}})
            ok, _ = kw.execute(d, lambda c: "ok")
            warm.append(time.perf_counter_ns() - t0)
            assert ok
    ops["full_commit_warm[H=0..7]"] = (warm, 0)

    # history sweep for the full decision (fewer samples)
    sweep = {}
    ks = dep.kernel("sweep", mediated=False)
    done = 0
    for H in SWEEP:
        while done < H:
            d = ks.authorize(_history(done))
            ks.execute(d, lambda c: "ok")
            done += 1

        def f():
            ks.authorize(CALLS[0], reserve=False)
        sweep[str(H)] = _measure(f, budget_s=2.5, min_n=40, max_n=2000)[0]
    return {"ops": {k: {"samples_ns": v[0], "errors": v[1]} for k, v in ops.items()},
            "stages_ms": stages, "sweep_ns": sweep, "gc_enabled": gc.isenabled()}


COLD = r"""
import time, sys
t0 = time.perf_counter_ns()
sys.path.insert(0, {root!r})
from benchmarks.performance.common import Deployment
t1 = time.perf_counter_ns()
dep = Deployment(); dep.principals = ["c"]
k = dep.kernel("c", mediated=False)
t2 = time.perf_counter_ns()
d = k.authorize({{"tool": "read_doc", "args": {{"id": "pub-1"}}}})
t3 = time.perf_counter_ns()
d2 = k.authorize({{"tool": "read_doc", "args": {{"id": "pub-2"}}}}, reserve=False)
t4 = time.perf_counter_ns()
print(t1 - t0, t2 - t1, t3 - t2, t4 - t3)
"""


def cold(n: int) -> dict:
    rows = []
    for _ in range(n):
        out = subprocess.run([sys.executable, "-c", COLD.format(root=str(ROOT))],
                             capture_output=True, text=True, cwd=ROOT, check=True)
        rows.append([int(x) for x in out.stdout.split()])
    cols = ("import_ns", "kernel_construct_ns", "first_authorize_ns", "second_authorize_ns")
    return {c: percentiles([r[i] for r in rows]) for i, c in enumerate(cols)} | {
        "raw": [dict(zip(cols, r)) for r in rows]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--cold", type=int, default=15)
    ap.add_argument("--trial", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.trial:
        print(json.dumps(trial()))
        return 0
    trials = []
    for t in range(a.trials):
        out = subprocess.run([sys.executable, "-m", "benchmarks.performance.latency", "--trial"],
                             capture_output=True, text=True, cwd=ROOT, check=True)
        trials.append(json.loads(out.stdout))
        print(f"trial {t + 1}/{a.trials} done", flush=True)
    summary = {}
    for op in trials[0]["ops"]:
        pooled = [x for tr in trials for x in tr["ops"][op]["samples_ns"]]
        per = [percentiles(tr["ops"][op]["samples_ns"]) for tr in trials]
        total_s = sum(sum(tr["ops"][op]["samples_ns"]) for tr in trials) / 1e9
        summary[op] = {
            "pooled": percentiles(pooled),
            "per_trial_p50_us": [p["p50_us"] for p in per],
            "per_trial_p99_us": [p["p99_us"] for p in per],
            "evaluations_per_s_single_thread": len(pooled) / total_s if total_s else None,
            "errors": sum(tr["ops"][op]["errors"] for tr in trials),
        }
    sweep = {H: percentiles([x for tr in trials for x in tr["sweep_ns"][H]])
             for H in trials[0]["sweep_ns"]}
    stages = {op: {s: statistics.fmean(tr["stages_ms"][op][s] for tr in trials)
                   for s in trials[0]["stages_ms"][op]} for op in trials[0]["stages_ms"]}
    result = {"environment": environment(), "trials": a.trials, "summary": summary,
              "history_sweep_full_decision": sweep, "stage_means_ms": stages,
              "cold_start": cold(a.cold),
              "gc_enabled": trials[0]["gc_enabled"]}
    write_json("latency.json", result)
    write_json("latency-raw.json", {"trials": [{"ops": {k: v["samples_ns"] for k, v in tr["ops"].items()},
                                                 "sweep_ns": tr["sweep_ns"]} for tr in trials]})
    for op, s in summary.items():
        p = s["pooled"]
        print(f"{op:32s} n={p['n']:6d} p50={p['p50_us']:9.1f}us p95={p['p95_us']:9.1f}us "
              f"p99={p['p99_us']:9.1f}us max={p['max_us']:9.1f}us")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
