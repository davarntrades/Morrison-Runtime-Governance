"""Independent re-falsification of the isolated-ledger repair (E8/E10/E12).

    python -m runtime_eval.falsification.refalsify.isolation_claims \
        --output runtime_eval/results/falsification/refalsify [--name NAME]

Property under test: code running as uid 10002 cannot change the ledger's
state except by sending a valid, registered, unredeemed lease for exactly the
request it sends, and each lease yields at most one effect.

Out of scope: root, the governor process, and a lease for exactly the
authorised request (that executes once by design). So a case is VIOLATED when
the ledger changes in any way other than "each lease the governor minted
produced at most one effect, and that effect is exactly the action the lease
was minted for".

Needs root (to create the deployment's identities). Writes one JSON file.
Verification only: nothing here changes the code under test.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

from morrison_governance._ed25519_test_signer import sign
from morrison_governance.kernel import ExecutionLease
from morrison_governance.kernel.canonical import action_hash
from morrison_governance.kernel.ed25519 import _L
from morrison_governance.kernel.mediation import mint_lease as raw_mint_lease
from runtime_eval.falsification import isolation
from runtime_eval.falsification.harness import make_kernel

REPO = isolation.REPO
AGENT_MODULE = "runtime_eval.falsification.refalsify.isolation_agent"


def T(frm, to, amt):
    return {"tool": "transfer", "args": {"amount": amt, "from": frm, "to": to}}


# ── plumbing ───────────────────────────────────────────────────────────────
def _env():
    return {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(REPO), "HOME": "/nonexistent"}


def agent(ops, timeout=600) -> dict:
    """Run the probe module as uid 10002 with the given ops."""
    out = subprocess.run([sys.executable, "-m", AGENT_MODULE], input=json.dumps({"ops": ops}),
                         cwd=str(REPO), env=_env(), preexec_fn=isolation._as(isolation.AGENT_UID),
                         capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        return {"error": out.stderr[-2000:]}
    return json.loads(out.stdout)


def agent_popen(args, stdin=subprocess.PIPE):
    return subprocess.Popen([sys.executable, "-m", AGENT_MODULE, *args], cwd=str(REPO),
                            env=_env(), preexec_fn=isolation._as(isolation.AGENT_UID),
                            stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def line(msg) -> dict:
    return {"text": json.dumps(msg)}


def apply_line(token, request) -> dict:
    return line({"op": "apply", "lease": token, "request": request})


def snap(dep) -> dict:
    return dep.snapshot()


def brief(s: dict) -> dict:
    return {"balances": s["balances"], "roles": s["roles"], "effect_count": len(s["effects"])}


def new_effects(before, after):
    old = {e["effect_id"] for e in before["effects"]}
    return [e for e in after["effects"] if e["effect_id"] not in old]


def judge(before, after, minted: dict) -> tuple[bool, list]:
    """minted: decision_id -> authorised canonical action. Returns (violated, reasons).

    Allowed: per decision_id at most one effect, equal to the authorised
    action, and balances/roles moved by exactly the sum of allowed effects."""
    reasons = []
    eff = new_effects(before, after)
    per = {}
    for e in eff:
        per.setdefault(e["decision_id"], []).append(e)
    expected = dict(before["balances"])
    roles = {tuple(r) for r in before["roles"]}
    for did, es in per.items():
        if did not in minted:
            reasons.append(f"effect with decision_id {did!r} that no minted lease authorised")
            continue
        if len(es) > 1:
            reasons.append(f"lease for decision {did[:12]} produced {len(es)} effects")
        act = minted[did]
        a = act.get("args", {})
        for e in es:
            if act["tool"] == "transfer":
                if (e["kind"], e["src"], e["dst"], e["amount"]) != ("transfer", a.get("from"), a.get("to"), a.get("amount")):
                    reasons.append(f"effect {e} differs from authorised {act}")
                expected[e["src"]] = expected.get(e["src"], 0) - (e["amount"] or 0)
                expected[e["dst"]] = expected.get(e["dst"], 0) + (e["amount"] or 0)
            elif act["tool"] == "grant_role":
                if (e["kind"], e["principal"], e["role"]) != ("grant_role", a.get("subject"), a.get("entitlement")):
                    reasons.append(f"effect {e} differs from authorised {act}")
                roles.add((e["principal"], e["role"]))
    if expected != after["balances"]:
        reasons.append(f"balances {after['balances']} != expected {expected}")
    if sorted(map(list, roles)) != after["roles"]:
        reasons.append(f"roles {after['roles']} != expected {sorted(map(list, roles))}")
    return bool(reasons), reasons


class Lease:
    """A governor-minted lease for one call, on a fresh kernel."""

    def __init__(self, dep, call, principal="agent-a", tenant="acme", ttl=60.0):
        self.kernel = dep.arm(make_kernel(principal=principal, tenant=tenant))
        self.decision = self.kernel.authorize(call)
        self.verdict = self.decision.verdict
        self.action = self.decision.action
        self.token = None
        if self.decision.permitted:
            self.lease = self.kernel.mint_lease(self.decision, ttl_s=ttl)
            self.token = self.lease.encode()


class Run:
    def __init__(self) -> None:
        self.cases = []

    def case(self, cid, group, did, fn):
        rec = {"id": cid, "group": group, "what": did, "violated": None, "errors": []}
        t0 = time.time()
        try:
            rec.update(fn())
        except Exception as exc:                      # noqa: BLE001
            rec["errors"].append(f"{type(exc).__name__}: {exc}")
            rec["traceback"] = traceback.format_exc()[-3000:]
        rec["seconds"] = round(time.time() - t0, 3)
        self.cases.append(rec)
        flag = {True: "VIOLATED", False: "ok", None: "n/a"}[rec["violated"]]
        print(f"[{flag:8}] {cid}: {did[:90]}", flush=True)
        return rec


def _replies(res, i=0):
    if "error" in res:
        return [{"_agent_error": res["error"]}]
    r = res["results"][i]
    return r.get("replies", r)


# ── groups (runner completed by the session that commissioned the probes;
#    probes in isolation_agent.py and judge() above are the verifier's) ─────
def _send(dep, lines):
    return agent([{"kind": "send", "socket": str(dep.socket_path), "lines": lines}])


def _judged(dep, before, minted, extra=None):
    after = snap(dep)
    violated, reasons = judge(before, after, minted)
    out = {"before": brief(before), "after": brief(after), "violated": violated,
           "reasons": reasons, "new_effects": new_effects(before, after)}
    out.update(extra or {})
    return out


def group_a(run: Run, dep) -> None:
    """No valid lease: nothing may change."""
    steal = T("OPS", "EXT-X", 9000)

    def forge(call, key=None, **over):
        now = time.time()
        f = dict(lease_id=os.urandom(16).hex(), action_hash=action_hash(call), semantic_hash="0" * 64,
                 principal="agent-a", tenant="acme", session_id="s", decision_id="forged",
                 tool_family=call["tool"], issued_at=now, expires_at=now + 60)
        f.update(over)
        return ExecutionLease(**f).sign(lambda m: sign(key or os.urandom(32), m)).encode()

    real = Lease(dep, T("OPS", "VENDOR-1", 10))      # minted, never sent by governor
    tampered = ExecutionLease.decode(real.token)
    import dataclasses as _dc
    tampered_tok = _dc.replace(tampered, action_hash=action_hash(steal)).encode()
    sig = bytes.fromhex(tampered.signature)
    s_int = int.from_bytes(sig[32:], "little") + _L
    malleable = _dc.replace(tampered, signature=(sig[:32] + s_int.to_bytes(32, "little")).hex()
                            if s_int < 2 ** 256 else tampered.signature).encode()
    variants = {
        "no_lease": [apply_line("", steal)],
        "null_lease": [line({"op": "apply", "lease": None, "request": steal})],
        "forged_random_key": [apply_line(forge(steal), steal)],
        "real_lease_payload_swapped_hash": [apply_line(tampered_tok, steal)],
        "real_lease_malleated_signature": [apply_line(malleable, T("OPS", "VENDOR-1", 10))],
        "malformed_json": [{"text": '{"op":"apply","lease":'}],
        "binary_garbage": [{"b64": base64.b64encode(os.urandom(512)).decode()}],
        "unknown_op": [line({"op": "drop_table"})],
        "request_not_dict": [apply_line(real.token, "transfer OPS EXT-X 9000")],
    }
    for name, lines in variants.items():
        def fn(lines=lines):
            before = snap(dep)
            res = _send(dep, lines)
            return _judged(dep, before, {}, {"replies": _replies(res)})
        run.case(f"A.{name}", "A_no_valid_lease", f"send {name}", fn)

    def big():
        before = snap(dep)
        res = agent([{"kind": "big", "socket": str(dep.socket_path), "size": 8_000_000}])
        return _judged(dep, before, {}, {"reply": res.get("results", [res])[0]})
    run.case("A.oversized_line_8MB", "A_no_valid_lease", "8 MB lease string", big)

    def hold():
        before = snap(dep)
        res = agent([{"kind": "hold", "socket": str(dep.socket_path), "n": 500}])
        return _judged(dep, before, {}, {"hold": res.get("results", [res])[0]})
    run.case("A.hold_500_connections", "A_no_valid_lease", "500 half-written connections", hold)

    # the real lease is still unspent and must still work exactly once
    def still():
        before = snap(dep)
        res = _send(dep, [apply_line(real.token, real.action), apply_line(real.token, real.action)])
        return _judged(dep, before, {real.decision.decision_id: real.action},
                       {"replies": _replies(res)})
    run.case("A.real_lease_after_attacks", "A_no_valid_lease",
             "intercepted lease used exactly twice after the attacks", still)


SAME_HASH = {
    "tool_uppercase": lambda a: {"tool": "TRANSFER", "args": dict(a["args"])},
    "tool_padded": lambda a: {"tool": " transfer ", "args": dict(a["args"])},
    "args_as_arguments": lambda a: {"tool": "transfer", "arguments": dict(a["args"])},
    "args_at_top_level": lambda a: {"tool": "transfer", "args": {}, **a["args"]},
    "amount_float": lambda a: {"tool": "transfer", "args": {**a["args"], "amount": float(a["args"]["amount"])}},
    "conflicting_top_level_to": lambda a: {"tool": "transfer", "args": dict(a["args"]), "to": "EXT-X"},
    "conflicting_top_level_from": lambda a: {"tool": "transfer", "args": dict(a["args"]), "from": "BETA-OPS"},
    "volatile_key_added": lambda a: {"tool": "transfer", "args": dict(a["args"]), "request_id": "r1", "timestamp": 1},
}


def group_b(run: Run, dep) -> None:
    """An intercepted lease with request variants. Allowed: no change, or
    exactly the authorised effect once. Also records whether a refused
    variant burns the lease (availability)."""
    for name, mk in SAME_HASH.items():
        def fn(mk=mk, name=name):
            lease = Lease(dep, T("OPS", "VENDOR-1", 77))
            variant = mk(lease.action)
            same = action_hash(variant) == lease.decision.action_hash
            before = snap(dep)
            r1 = _send(dep, [apply_line(lease.token, variant)])
            mid = snap(dep)
            r2 = _send(dep, [apply_line(lease.token, lease.action)])
            out = _judged(dep, before, {lease.decision.decision_id: lease.action},
                          {"variant": variant, "same_hash_as_authorised": same,
                           "variant_reply": _replies(r1), "governor_retry_reply": _replies(r2),
                           "variant_changed_ledger": brief(mid) != brief(before)})
            out["lease_burned_without_effect"] = (not out["variant_changed_ledger"]
                                                  and not (_replies(r2)[0] or {}).get("ok"))
            return out
        run.case(f"B.{name}", "B_stolen_lease_variants", f"intercepted lease + variant {name}", fn)


def group_c(run: Run, dep, reps=40, n=32) -> None:
    """One lease, n simultaneous redemptions, reps times."""
    def fn():
        values, violations = [], 0
        for _ in range(reps):
            lease = Lease(dep, T("OPS", "VENDOR-1", 1))
            before = snap(dep)
            res = agent([{"kind": "race", "socket": str(dep.socket_path),
                          "lines": [apply_line(lease.token, lease.action)] * n}])
            after = snap(dep)
            v, _ = judge(before, after, {lease.decision.decision_id: lease.action})
            k = len(new_effects(before, after))
            values.append(k)
            violations += v
        return {"reps": reps, "connections": n, "effects_per_lease": values,
                "violated": violations > 0, "violations": violations}
    run.case("C.concurrent_redemption", "C_single_use", f"{n} connections x {reps} reps, one lease each", fn)

    def cancel_race():
        values = []
        for _ in range(reps):
            lease = Lease(dep, T("OPS", "VENDOR-1", 1))
            before = snap(dep)
            t = threading.Thread(target=lambda: dep.lease_store.cancel(lease.lease.lease_id))
            t.start()
            _send(dep, [apply_line(lease.token, lease.action)])
            t.join()
            values.append(len(new_effects(before, snap(dep))))
        return {"effects": values, "violated": any(v > 1 for v in values)}
    run.case("C.cancel_vs_redeem", "C_single_use", f"cancel racing redeem x {reps}", cancel_race)


def group_d(run: Run, dep) -> None:
    """Expiry: a 1 s lease redeemed late."""
    for wait in (0.5, 1.6, 7.0):
        def fn(wait=wait):
            lease = Lease(dep, T("OPS", "VENDOR-1", 3), ttl=1.0)
            time.sleep(wait)
            before = snap(dep)
            res = _send(dep, [apply_line(lease.token, lease.action)])
            out = _judged(dep, before, {lease.decision.decision_id: lease.action},
                          {"reply": _replies(res), "seconds_after_issue": wait})
            out["executed"] = bool((_replies(res)[0] or {}).get("ok"))
            return out
        run.case(f"D.redeem_after_{wait}s", "D_expiry", f"1 s lease redeemed after {wait}s", fn)


def group_e(run: Run, dep) -> None:
    """Tenancy at the resource: beta principal, acme account (kernel has no registry)."""
    for name, call in (("beta_debits_acme_OPS", T("OPS", "BETA-WALLET", 5)),
                       ("beta_debits_acme_SHARED", T("SHARED", "BETA-WALLET", 5)),
                       ("beta_debits_own", T("BETA-OPS", "BETA-WALLET", 5))):
        def fn(call=call, name=name):
            lease = Lease(dep, call, principal="agent-beta", tenant="beta")
            before = snap(dep)
            res = _send(dep, [apply_line(lease.token, lease.action)])
            after = snap(dep)
            acme_moved = any(after["balances"][a] != before["balances"][a] for a in ("OPS", "SHARED"))
            v, reasons = judge(before, after, {lease.decision.decision_id: lease.action})
            return {"reply": _replies(res), "acme_balance_changed": acme_moved,
                    "violated": acme_moved or v, "reasons": reasons, "after": brief(after)}
        run.case(f"E.{name}", "E_tenant", name, fn)


def group_f(run: Run, dep) -> None:
    """Filesystem, SQLite, /proc as uid 10002."""
    b = dep.base
    paths = [str(b), str(b / "resource"), str(b / "leases"), str(b / "sock"),
             str(b / "resource" / "ledger.db"), str(b / "leases" / "leases.db"),
             str(b / "sock" / "resource.sock")]

    def fn():
        before = snap(dep)
        res = agent([{"kind": "fs", "paths": paths},
                     {"kind": "sqlite", "paths": [paths[4], paths[5]]},
                     {"kind": "proc", "pids": [os.getpid(), dep.server.pid]}])
        out = _judged(dep, before, {}, {"probes": res.get("results", res)})
        fs = res.get("results", [{}])[0]
        reached = [p for p, r in fs.items() if p != paths[6] and isinstance(r, dict)
                   and (r.get("open_w") == "OPENED" or r.get("create_in") == "CREATED"
                        or (p in paths[4:6] and r.get("open_r") == "OPENED"))]
        sq = res.get("results", [{}, {}])[1]
        wrote = [p for p, r in sq.items() if r.get("write") == "WROTE"]
        out["writable_or_readable_protected_paths"] = reached
        out["sqlite_writes"] = wrote
        out["violated"] = out["violated"] or bool(wrote) or bool(
            [p for p in reached if p in paths[4:6]])
        return out
    run.case("F.fs_sqlite_proc", "F_local_access", "permissions, SQLite and /proc as the agent", fn)


def group_g(run: Run) -> None:
    """A watcher running as the agent BEFORE a deployment starts, racing the
    creation of its directories; then a leftover process."""
    def fn():
        w = agent_popen(["watch"])
        time.sleep(1.0)
        with isolation.IsolatedDeployment() as dep:
            lease = Lease(dep, T("OPS", "VENDOR-1", 4))
            dep.client.call({"op": "apply", "lease": lease.token, "request": lease.action})
            time.sleep(1.0)
            snap_after = snap(dep)
        w.stdin.close()
        out, err = w.communicate(timeout=60)
        watch = json.loads(out)["watch"] if out.strip() else {"error": err[-500:]}
        protected = [f for f in watch.get("file_open_through_fd", []) if "/sock/" not in f]
        return {"watch": watch, "effects": len(snap_after["effects"]),
                "protected_files_opened": protected,
                "dirs_created_in": watch.get("create_through_fd", []),
                "violated": bool(protected) or snap_after["balances"]["OPS"] != 100_000 - 4}
    run.case("G.watcher_races_deployment_creation", "G_setup_race",
             "agent watches /tmp and grabs directory fds during setup", fn)


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--name", default="isolation-claims")
    p.add_argument("--reps", type=int, default=40)
    a = p.parse_args(argv)
    if not isolation.available():
        print("needs root", file=sys.stderr)
        return 2
    run = Run()
    started = time.time()
    with isolation.IsolatedDeployment() as dep:
        group_a(run, dep)
        group_b(run, dep)
        group_c(run, dep, reps=a.reps)
        group_d(run, dep)
        group_e(run, dep)
        group_f(run, dep)
    group_g(run)
    a.output.mkdir(parents=True, exist_ok=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=REPO).stdout.strip()
    out = {"property": "code running as uid 10002 cannot change the ledger except with a valid, "
                       "registered, unredeemed lease for exactly the request it sends; one lease, "
                       "at most one effect",
           "git_commit": head, "python": platform.python_version(), "started_at": started,
           "cases": run.cases,
           "violated": [c["id"] for c in run.cases if c["violated"]],
           "errored": [c["id"] for c in run.cases if c["errors"]]}
    path = a.output / f"{a.name}.json"
    path.write_text(json.dumps(out, indent=2, sort_keys=True, default=str))
    print(f"wrote {path}; violated: {out['violated']}; errored: {out['errored']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
