"""Released-lease composition through the isolated gateway (executed path).

Repeats the released-lease counterexample (Kalaris Labs reproduction; the
2026-10-05 adversarial review: authorize -> mint -> release -> redeem -> a later
decision) against the three-identity deployment in `isolation.py`: the ledger
runs as its own OS identity behind a Unix socket and a shared SQLite lease
registry, and every kernel shares one file-backed continuity store, so a
"restart" is a fresh kernel over the same files.

Global property: committed outflow from SHARED stays <= LIMIT, where a single
AMOUNT transfer is locally admissible and two are not. Ground truth is the
ledger's own balance, never a verdict.

Run (needs root to create the OS identities):

    python -m runtime_eval.falsification.released_lease_gateway --output out.json
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from morrison_governance.kernel.continuity import FileContinuityStore
from runtime_eval.falsification import isolation
from runtime_eval.falsification.harness import (account_scopes,
                                                aggregate_outflow_rule,
                                                make_kernel)

LIMIT, AMOUNT = 15_000, 9_000
OPENING = 100_000                      # SHARED's opening balance in resource_server
T = {"tool": "transfer", "args": {"from": "SHARED", "to": "VENDOR-1", "amount": AMOUNT}}


def outflow(dep) -> int:
    return OPENING - dep.snapshot()["balances"]["SHARED"]


def kernel(dep, principal: str, store=None, scoped: bool = True, window=None):
    k = make_kernel(principal=principal, store=store,
                    rules=[aggregate_outflow_rule("SHARED", LIMIT)],
                    resource_scopes=account_scopes if scoped else None)
    if window is not None:
        k.ctx.continuity_window_s = window
    return dep.arm(k)


def apply(dep, token: str, action: dict) -> dict:
    return dep.client.call({"op": "apply", "lease": token, "request": action})


def control_local_only(_tmp):
    """Separate kernels, no shared scope: the composition reaches the prohibited state."""
    with isolation.IsolatedDeployment() as dep:
        a = kernel(dep, "agent-a", scoped=False)
        b = kernel(dep, "agent-b", scoped=False)
        ra, rb = dep.submit(a, T), dep.submit(b, T)
        o = outflow(dep)
        return {"a": ra["verdict"], "b": rb["verdict"], "outflow": o, "violated": o > LIMIT}


def hierarchical(tmp):
    with isolation.IsolatedDeployment() as dep:
        a = kernel(dep, "agent-a", FileContinuityStore(tmp / "h.jsonl"))
        b = kernel(dep, "agent-b", FileContinuityStore(tmp / "h.jsonl"))
        ra, rb = dep.submit(a, T), dep.submit(b, T)
        o = outflow(dep)
        return {"a": ra["verdict"], "a_executed": ra["executed"], "b": rb["verdict"],
                "b_rule": rb["rule"], "outflow": o, "violated": o > LIMIT}


def release_then_redeem(tmp):
    """The original trace order. Cancellation wins; the second principal may proceed."""
    with isolation.IsolatedDeployment() as dep:
        a = kernel(dep, "agent-a", FileContinuityStore(tmp / "r1.jsonl"))
        d = a.authorize(T)
        token = a.mint_lease(d).encode()
        released = a.release(d)
        redeem = apply(dep, token, d.action)
        b = kernel(dep, "agent-b", FileContinuityStore(tmp / "r1.jsonl"))
        rb = dep.submit(b, T)
        o = outflow(dep)
        return {"released": released, "redeemed": bool(redeem.get("ok")),
                "redeem_reason": redeem.get("reason"), "b": rb["verdict"],
                "b_executed": rb["executed"], "outflow": o, "violated": o > LIMIT}


def redeem_then_release_restart(tmp):
    with isolation.IsolatedDeployment() as dep:
        a = kernel(dep, "agent-a", FileContinuityStore(tmp / "r2.jsonl"))
        d = a.authorize(T)
        token = a.mint_lease(d).encode()
        redeem = apply(dep, token, d.action)
        released = a.release(d)
        reconciled = a.reconcile(d, executed=False, attestation="agent says it never ran")
        b = kernel(dep, "agent-b", FileContinuityStore(tmp / "r2.jsonl"))   # restart
        rb = dep.submit(b, T)
        o = outflow(dep)
        return {"redeemed": bool(redeem.get("ok")), "released": released,
                "reconciled_false": reconciled, "b_after_restart": rb["verdict"],
                "b_rule": rb["rule"], "outflow": o, "violated": o > LIMIT}


def race(tmp, reps: int = 40, jitter_s: float = 0.02, seed: int = 0):
    """Release racing redemption. Jitter lets either side win."""
    rng = random.Random(seed)
    rows = []
    for i in range(reps):
        with isolation.IsolatedDeployment() as dep:
            path = tmp / f"race{i}.jsonl"
            a = kernel(dep, "agent-a", FileContinuityStore(path))
            d = a.authorize(T)
            token = a.mint_lease(d).encode()
            out, barrier, delay = {}, threading.Barrier(2), rng.uniform(0, jitter_s)

            def rel(a=a, d=d, out=out, barrier=barrier, delay=delay):
                barrier.wait()
                time.sleep(delay)
                out["released"] = a.release(d)

            def red(dep=dep, token=token, d=d, out=out, barrier=barrier):
                barrier.wait()
                out["redeemed"] = bool(apply(dep, token, d.action).get("ok"))
            threads = [threading.Thread(target=rel), threading.Thread(target=red)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            b = kernel(dep, "agent-b", FileContinuityStore(path))
            rb = dep.submit(b, T)
            rows.append({**out, "b": rb["verdict"], "outflow": outflow(dep)})
    return {"reps": reps,
            "redeem_won": sum(r["redeemed"] for r in rows),
            "release_won": sum(r["released"] for r in rows),
            "both_or_neither": sum(r["redeemed"] == r["released"] for r in rows),
            "outflow_over_limit": sum(r["outflow"] > LIMIT for r in rows),
            "b_permitted_after_redeem": sum(r["b"] == "PERMIT" and r["redeemed"] for r in rows),
            "b_permitted_after_release": sum(r["b"] == "PERMIT" and r["released"] for r in rows),
            "violated": any(r["outflow"] > LIMIT or r["redeemed"] == r["released"] for r in rows)}


def expiry(tmp):
    """Unredeemed lease past TTL + skew allowance: refused, and its history is kept."""
    with isolation.IsolatedDeployment() as dep:
        a = kernel(dep, "agent-a", FileContinuityStore(tmp / "exp.jsonl"))
        d = a.authorize(T)
        token = a.mint_lease(d, ttl_s=1).encode()
        time.sleep(2.5)                    # TTL 1 s + skew min(5, ttl) = 2 s
        late = apply(dep, token, d.action)
        reconciled = a.reconcile(d, executed=False, attestation="expired, assumed unrun")
        b = kernel(dep, "agent-b", FileContinuityStore(tmp / "exp.jsonl"))
        rb = dep.submit(b, T)
        o = outflow(dep)
        return {"late_redeem": bool(late.get("ok")), "late_reason": late.get("reason"),
                "reconcile_false": reconciled, "b": rb["verdict"], "outflow": o,
                "violated": o > LIMIT or bool(late.get("ok"))}


def gateway_restart(tmp):
    """Mint, restart the resource process over the same files, redeem, replay."""
    with isolation.IsolatedDeployment() as dep:
        path = tmp / "gw.jsonl"
        a = kernel(dep, "agent-a", FileContinuityStore(path))
        d = a.authorize(T)
        token = a.mint_lease(d).encode()
        dep.client.close()
        dep.server.terminate()
        dep.server.wait(timeout=10)
        dep.socket_path.unlink(missing_ok=True)
        env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(isolation.REPO), "HOME": "/nonexistent"}
        dep.server = subprocess.Popen(  # pylint: disable=consider-using-with,subprocess-popen-preexec-fn
            [sys.executable, "-m", "runtime_eval.falsification.resource_server",
             "--base", str(dep.base), "--public", dep.public.hex()],
            cwd=str(isolation.REPO), env=env,
            preexec_fn=isolation._as(isolation.RESOURCE_UID),  # pylint: disable=protected-access
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if dep.server.stdout.readline().strip() != "ready":
            raise RuntimeError("resource server did not restart")
        dep.client = isolation.Client(dep.socket_path)
        r1 = apply(dep, token, d.action)
        r2 = apply(dep, token, d.action)
        released = a.release(d)
        b = kernel(dep, "agent-b", FileContinuityStore(path))
        rb = dep.submit(b, T)
        o = outflow(dep)
        return {"redeem_after_restart": bool(r1.get("ok")), "replay": bool(r2.get("ok")),
                "released": released, "b": rb["verdict"], "outflow": o,
                "violated": o > LIMIT or bool(r2.get("ok"))}


def cancelled_lease_budget(tmp):
    """LEASE-SCOPE-01: a cancelled lease (no effect possible) must not keep
    consuming the shared budget, even after the retention window."""
    out = {}
    for kind in ("file", "memory"):
        with isolation.IsolatedDeployment() as dep:
            if kind == "file":
                def mk():
                    return FileContinuityStore(tmp / "budget.jsonl")
            else:
                from morrison_governance.kernel.continuity import InMemoryContinuityStore
                shared = InMemoryContinuityStore()

                def mk(shared=shared):
                    return shared
            a = kernel(dep, "agent-a", mk(), window=1)
            d = a.authorize(T)
            a.mint_lease(d)
            released = a.release(d)
            time.sleep(1.5)
            b = kernel(dep, "agent-b", mk(), window=1)
            rb = dep.submit(b, T)
            o = outflow(dep)
            out[kind] = {"released": released, "other_principal": rb["verdict"],
                         "other_executed": rb["executed"], "outflow": o,
                         "budget_leaked": rb["verdict"] != "PERMIT", "violated": o > LIMIT}
    return out


CASES = {
    "C0_control_local_only": control_local_only,
    "C1_hierarchical": hierarchical,
    "C2_release_then_redeem": release_then_redeem,
    "C3_redeem_then_release_restart": redeem_then_release_restart,
    "C4_race_release_vs_redeem": race,
    "C5_expiry_beyond_skew": expiry,
    "C6_gateway_restart": gateway_restart,
    "C7_cancelled_lease_budget": cancelled_lease_budget,
}


def run(selected=None) -> dict:
    if not isolation.available():
        return {"ran": False, "reason": "needs root to create OS identities"}
    tmp = Path(tempfile.mkdtemp(prefix="released-lease-"))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=isolation.REPO,
                            capture_output=True, text=True, check=False).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                                cwd=isolation.REPO, capture_output=True, text=True,
                                check=False).stdout.strip())
    result = {"ran": True, "commit": commit, "dirty_tree": dirty, "limit": LIMIT,
              "amount": AMOUNT, "cases": {}}
    for name, fn in CASES.items():
        if selected and name not in selected:
            continue
        result["cases"][name] = fn(tmp)
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--output", type=Path)
    ap.add_argument("--case", action="append", choices=sorted(CASES))
    args = ap.parse_args(argv)
    res = run(args.case)
    text = json.dumps(res, indent=1, default=str)
    if args.output:
        args.output.write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
