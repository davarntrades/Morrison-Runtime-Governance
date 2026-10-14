"""Independent re-falsification of the G1, E12 and E10 kernel repairs (9bb466a).

    python -m runtime_eval.falsification.refalsify.kernel_claims \
        --output runtime_eval/results/falsification/refalsify [--tag run1]

Verification only: nothing here changes the kernel or the harness. Every case
builds its own SQLite ledger (the source of truth for effects) and its own
continuity store under <output>/work-<tag>/, which is deleted at the end
unless --keep-work is given.

Each case records: id, property, label, configuration, what was done, ledger
state before/after, the measured quantities, whether the property was
violated, and errors. Labels:

  within_config        the stated configuration of the property holds
  precondition_not_met a precondition of the stated configuration is broken
                       on purpose (separate stores, scopes missing, ...)
  outside_property     a path the property statement does not cover; recorded
                       as an observation, never counted as a violation

G1 primary measure is `Ledger.outflow("SHARED")` (sum of committed transfer
amounts whose src is SHARED). Two secondary measures are reported but never
change the primary verdict: gross positive debits from SHARED, and the drop
in SHARED's balance.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import json
import multiprocessing as mp
import os
import platform
import secrets
import shutil
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Optional

from morrison_governance.kernel import gate as gate_mod
from morrison_governance.kernel.continuity import (FileContinuityStore,
                                                   InMemoryContinuityStore)
from runtime_eval.falsification.harness import (ApprovalService,
                                                GovernedGateway,
                                                account_scopes,
                                                aggregate_outflow_rule,
                                                make_kernel)
from runtime_eval.falsification.resource import Ledger

LIMIT = 25_000
SRC = "SHARED"
OWNERS = {"SHARED": "acme", "OPS": "acme", "ACME-2": "acme",
          "BETA-OPS": "beta", "BETA-2": "beta"}
INITIAL = {"SHARED": ("acme", 1_000_000), "OPS": ("acme", 100_000),
           "ACME-2": ("acme", 100_000), "BETA-OPS": ("beta", 100_000),
           "BETA-2": ("beta", 100_000)}
ACME_ACCOUNTS = tuple(k for k, v in OWNERS.items() if v == "acme")
APPROVAL_KEY = b"refalsify-approval-key-synthetic"

WORK: Path = Path(".")
CASES: list[dict] = []


# ── helpers ───────────────────────────────────────────────────────────────
def T(src, dst, amount, **extra) -> dict:
    args = {"from": src, "to": dst, "amount": amount}
    args.update(extra)
    return {"tool": "transfer", "args": args}


def _err(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"[:300]


class Env:
    """One fresh ledger + one continuity store for a case."""

    def __init__(self, name: str, store_kind: str = "memory",
                 accounts: Optional[dict] = None) -> None:
        d = WORK / f"{name}-{secrets.token_hex(4)}"
        d.mkdir(parents=True, exist_ok=True)
        self.dir = d
        self.token = secrets.token_hex(16)
        self.ledger_path = d / "ledger.db"
        self.ledger = Ledger(self.ledger_path, self.token,
                             accounts if accounts is not None else INITIAL)
        self.store_path = str(d / "continuity.jsonl")
        self.store_kind = store_kind
        self.store = (FileContinuityStore(self.store_path, fsync=False)
                      if store_kind == "file" else InMemoryContinuityStore())
        self.initial_balance = dict(self.ledger.snapshot()["balances"])

    def kernel(self, principal: str, tenant: str = "acme", store=None,
               rules=None, scopes=account_scopes, owners=None,
               signing_key: bytes = b"", decision_ttl_s=None, session_id=""):
        return make_kernel(
            principal=principal, tenant=tenant,
            store=self.store if store is None else store,
            rules=[aggregate_outflow_rule(SRC, LIMIT)] if rules is None else rules,
            resource_scopes=scopes, owners=owners, signing_key=signing_key,
            decision_ttl_s=decision_ttl_s, session_id=session_id)

    def gateway(self, kernel, approver=None) -> GovernedGateway:
        return GovernedGateway(kernel, self.ledger, self.token, approver)

    def commit_fn(self, kernel, decision) -> Callable[[dict], dict]:
        def run(action):
            return self.ledger.apply(self.token, action,
                                     kernel.ctx.principal.id,
                                     decision.decision_id)
        return run

    def state(self) -> dict:
        s = self.ledger.snapshot()
        return {"balances": s["balances"], "effect_count": len(s["effects"])}

    def measures(self) -> dict:
        s = self.ledger.snapshot()
        gross = sum(e["amount"] for e in s["effects"]
                    if e["kind"] == "transfer" and e["src"] == SRC
                    and e["amount"] > 0)
        return {"ledger_outflow_SHARED": self.ledger.outflow(SRC),
                "gross_positive_debits_SHARED": gross,
                "balance_drop_SHARED": (self.initial_balance.get(SRC, 0)
                                        - s["balances"].get(SRC, 0))}

    def acme_debits_by(self, tenant_principals: set) -> list:
        """Effects by the given principals that lowered an acme account."""
        s = self.ledger.snapshot()
        out = []
        for e in s["effects"]:
            if e["kind"] != "transfer" or e["principal"] not in tenant_principals:
                continue
            if e["src"] in ACME_ACCOUNTS and e["amount"] > 0:
                out.append({**e, "debited": e["src"]})
            if e["dst"] in ACME_ACCOUNTS and e["amount"] < 0:
                out.append({**e, "debited": e["dst"]})
        return out


def record(cid: str, prop: str, label: str, configuration: str, done: str,
           before: Any, after: Any, violated: bool, measures: Any = None,
           errors: Optional[list] = None, repeats: Optional[list] = None,
           note: str = "", secondary: Optional[dict] = None) -> dict:
    rec = {"id": cid, "property": prop, "label": label,
           "configuration": configuration, "what_was_done": done,
           "ledger_before": before, "ledger_after": after,
           "violated": bool(violated), "measures": measures,
           "secondary_measure_violations": secondary or {},
           "errors": errors or [], "note": note}
    if repeats is not None:
        rec["repeats"] = repeats
        rec["repeat_count"] = len(repeats)
        rec["repeats_violated"] = sum(1 for r in repeats if r.get("violated"))
    CASES.append(rec)
    flag = "VIOLATED" if violated else "ok"
    print(f"  [{flag:8}] {cid} ({label})", flush=True)
    return rec


def run_case(fn: Callable[[], None]) -> None:
    try:
        fn()
    except Exception as e:                       # noqa: BLE001
        record(fn.__name__, "harness", "harness_error", "", fn.__doc__ or "",
               None, None, False, errors=[_err(e), traceback.format_exc()[-1500:]])


def g1_eval(env: Env) -> tuple[dict, bool, dict]:
    m = env.measures()
    secondary = {"gross_positive_debits_exceed_limit":
                 m["gross_positive_debits_SHARED"] > LIMIT,
                 "balance_drop_exceeds_limit": m["balance_drop_SHARED"] > LIMIT}
    return m, m["ledger_outflow_SHARED"] > LIMIT, secondary


CFG_G1 = ("shared continuity store, every kernel resource_scopes=account_scopes "
          "and aggregate_outflow_rule('SHARED', 25000)")
CFG_E12 = "owners=OWNERS registry (owned_resource_args={'transfer': ('from',)})"
CFG_E10 = "GovernanceKernel.execute with fault injection"


# ══════════════════════════════════════════════════════════════════════════
# G1
# ══════════════════════════════════════════════════════════════════════════
def g1_sequential_many_principals():
    """50 distinct principals each try 3 transfers of 1000 from SHARED."""
    env = Env("g1seq")
    before = env.state()
    errs = []
    for i in range(50):
        g = env.gateway(env.kernel(f"p{i:02d}"))
        for j in range(3):
            try:
                g.submit(T(SRC, f"D{i}-{j}", 1000))
            except Exception as e:                   # noqa: BLE001
                errs.append(_err(e))
    m, v, sec = g1_eval(env)
    record("G1-01-sequential-50-principals", "G1", "within_config",
           CFG_G1 + "; InMemoryContinuityStore",
           "50 principals x 3 sequential transfers of 1000 (150000 requested)",
           before, env.state(), v, m, errs, secondary=sec)


def g1_amount_types():
    """Amounts as float / string / bool / huge / NaN / inf / exotic strings."""
    variants = [
        ("float-non-integer", [12500.7, 12500.7, 12500.7]),
        ("float-integer", [12500.0, 12500.0, 1.0]),
        ("string-int", ["9000", "9000", "9000"]),
        ("string-padded", [" 9000 ", "9000\n", "\t9000"]),
        ("string-underscore", ["9_000", "9_000", "9_000"]),
        ("string-fullwidth-digits", ["９０００"] * 3),
        ("string-decimal", ["9000.5", "9000.5", "9000.5"]),
        ("string-exponent", ["9e3", "9e3", "9e3"]),
        ("bool", [True] * 3 + [9000, 9000, 9000]),
        ("huge-int", [10 ** 20, 10 ** 30]),
        ("nan-inf", [float("nan"), float("inf"), "NaN", "Infinity"]),
        ("mixed-int-float", [9000, 9000.9, "7000"]),
    ]
    for name, amounts in variants:
        env = Env(f"g1amt-{name}")
        before = env.state()
        rows, errs = [], []
        for i, a in enumerate(amounts):
            g = env.gateway(env.kernel(f"amt{i}"))
            try:
                r = g.submit(T(SRC, f"X{i}", a))
                rows.append({"amount": repr(a), "verdict": r["verdict"],
                             "rule": r["rule"], "executed": r["executed"],
                             "result": r["result"][:120]})
            except Exception as e:                   # noqa: BLE001
                errs.append(_err(e))
        m, v, sec = g1_eval(env)
        record(f"G1-02-amount-{name}", "G1", "within_config",
               CFG_G1 + "; distinct principal per attempt",
               f"transfers from SHARED with amounts {[repr(a) for a in amounts]}",
               before, env.state(), v, {**m, "attempts": rows}, errs,
               secondary=sec)


def g1_negative_amount_net():
    """Negative transfer FROM SHARED (credits SHARED, outflow sum drops),
    then positives that the rule sees as within budget."""
    env = Env("g1neg")
    before = env.state()
    rows = []
    g = env.gateway(env.kernel("neg-a"))
    r = g.submit(T(SRC, "NEG-PAYEE", -9000))
    rows.append((r["verdict"], r["executed"]))
    for i in range(4):
        r = env.gateway(env.kernel(f"neg-p{i}")).submit(T(SRC, f"Y{i}", 8500))
        rows.append((r["verdict"], r["executed"]))
    m, v, sec = g1_eval(env)
    record("G1-03-negative-amount-landed", "G1", "within_config", CFG_G1,
           "principal A transfers -9000 from SHARED (lands: SHARED credited "
           "9000 from NEG-PAYEE); 4 principals then transfer 8500 each",
           before, env.state(), v, {**m, "attempts": rows},
           secondary=sec,
           note="Ledger.outflow is a NET sum, so it stays at the limit; gross "
                "positive debits from SHARED exceed it. The negative leg is "
                "a debit of NEG-PAYEE (an auto-created external account).")


def g1_negative_phantom():
    """A negative-amount transfer that the LEDGER refuses (no 'to') is still
    committed in governed history and offsets the budget."""
    for name, call in [
        ("missing-to", {"tool": "transfer", "args": {"from": SRC, "amount": -50000}}),
        ("to-is-dict", T(SRC, {"x": 1}, -50000)),
        ("to-is-list", T(SRC, ["a", "b"], "-50000")),
    ]:
        env = Env(f"g1phantom-{name}")
        before = env.state()
        g = env.gateway(env.kernel("phantom"))
        r = g.submit(call)
        rows = [{"call": call, "verdict": r["verdict"], "executed": r["executed"],
                 "result": r["result"][:160]}]
        for i in range(10):
            r2 = env.gateway(env.kernel(f"ph-p{i}")).submit(T(SRC, f"Z{i}", 9000))
            rows.append({"verdict": r2["verdict"], "rule": r2["rule"],
                         "executed": r2["executed"]})
        m, v, sec = g1_eval(env)
        record(f"G1-04-negative-phantom-{name}", "G1", "within_config", CFG_G1,
               "principal 'phantom' submits a transfer from SHARED with a "
               "negative amount that the ledger rejects (executor raises); "
               "the kernel files it as EXECUTED (outcome unknown, treated as "
               "landed) so -50000 offsets the shared budget; then 10 "
               "principals transfer 9000 each",
               before, env.state(), v, {**m, "attempts": rows}, secondary=sec)


def g1_negative_reverse_leg():
    """Negative transfer from OPS to SHARED: debits SHARED, filed under
    scope account:OPS, invisible to the SHARED rule."""
    env = Env("g1rev")
    before = env.state()
    rows = []
    r = env.gateway(env.kernel("rev-a")).submit(T("OPS", SRC, -40000))
    rows.append((r["verdict"], r["rule"], r["executed"]))
    for i in range(3):
        r = env.gateway(env.kernel(f"rev-p{i}")).submit(T(SRC, f"R{i}", 8000))
        rows.append((r["verdict"], r["rule"], r["executed"]))
    m, v, sec = g1_eval(env)
    record("G1-05-negative-reverse-leg", "G1", "within_config", CFG_G1,
           "transfer {from: OPS, to: SHARED, amount: -40000} (moves 40000 OUT "
           "of SHARED), then 3 principals x 8000 from SHARED",
           before, env.state(), v, {**m, "attempts": rows}, secondary=sec,
           note="Primary measure counts only effects with src=SHARED; the "
                "balance-drop measure shows SHARED lost more than 25000.")


def g1_preview_remote_record():
    """Decision-plane path: preview() PERMIT, remote runtime executes,
    record_remote_execution() accepts the unreserved decision."""
    env = Env("g1preview")
    before = env.state()
    ka, kb = env.kernel("remote-a"), env.kernel("local-b")
    rows, errs = [], []
    for i in range(3):
        d = ka.preview(T(SRC, f"R{i}", 9000))
        row = {"who": "remote-a", "verdict": d.verdict, "reserved": d.reserved}
        if d.permitted:
            env.ledger.apply(env.token, d.action, "remote-a", d.decision_id)
            try:
                ka.record_remote_execution(d)
                row["recorded"] = True
            except Exception as e:                   # noqa: BLE001
                row["recorded"] = _err(e)
        rows.append(row)
    for i in range(3):
        d = kb.authorize(T(SRC, f"B{i}", 9000))
        row = {"who": "local-b", "verdict": d.verdict, "rule": d.rule}
        if d.permitted:
            ok, _ = kb.execute(d, env.commit_fn(kb, d))
            row["executed"] = ok
        rows.append(row)
    m, v, sec = g1_eval(env)
    record("G1-06-preview-then-record-remote-execution", "G1", "within_config",
           CFG_G1,
           "principal remote-a: preview() -> PERMIT (reserve=False), remote "
           "runtime applies it to the ledger, record_remote_execution(d) "
           "accepts it (files EXECUTED under the principal key only, never "
           "under __resource__/account:SHARED); principal local-b then "
           "authorizes/executes 3 x 9000",
           before, env.state(), v, {**m, "steps": rows}, errs, secondary=sec,
           note="record_remote_execution checks _lease_problem but not "
                "decision.reserved; its no-reservation branch calls _file() "
                "without the scope mirror. The kernel docstring says a "
                "reserve=False decision cannot be executed; this API "
                "nevertheless records one as executed.")


def g1_reserved_remote_record():
    """Control: authorize (reserved) then record_remote_execution."""
    env = Env("g1remote-ok")
    before = env.state()
    ka, kb = env.kernel("remote-a"), env.kernel("local-b")
    rows = []
    for i in range(3):
        d = ka.authorize(T(SRC, f"R{i}", 9000))
        rows.append(("a", d.verdict))
        if d.permitted:
            env.ledger.apply(env.token, d.action, "remote-a", d.decision_id)
            ka.record_remote_execution(d)
    for i in range(3):
        d = kb.authorize(T(SRC, f"B{i}", 9000))
        rows.append(("b", d.verdict))
        if d.permitted:
            kb.execute(d, env.commit_fn(kb, d))
    m, v, sec = g1_eval(env)
    record("G1-07-reserved-record-remote-execution", "G1", "within_config",
           CFG_G1, "authorize (reserved) + remote apply + record_remote_execution"
           " for A, then B authorizes/executes", before, env.state(), v,
           {**m, "steps": rows}, secondary=sec)


def g1_release_reconcile_ttl():
    """Expired decisions, UNCONFIRMED, release, reconcile."""
    env = Env("g1ttl")
    before = env.state()
    ka = env.kernel("ttl-a", decision_ttl_s=0.3)
    kb = env.kernel("ttl-b", decision_ttl_s=0.3)
    steps, errs = [], []
    d1 = ka.authorize(T(SRC, "A1", 9000)); d2 = ka.authorize(T(SRC, "A2", 9000))
    steps.append(("a auth x2", d1.verdict, d2.verdict))
    time.sleep(0.45)                       # both lapse -> UNCONFIRMED
    ok1 = ka.execute(d1, env.commit_fn(ka, d1))
    steps.append(("a execute expired d1", ok1[0], str(ok1[1])[:80]))
    steps.append(("a release lapsed d2", ka.release(d2)))
    db = kb.authorize(T(SRC, "B1", 9000))
    steps.append(("b auth while a holds 18000 UNCONFIRMED", db.verdict))
    if db.permitted:
        steps.append(("b exec", kb.execute(db, env.commit_fn(kb, db))[0]))
    # remote runtime actually applied d2 although its lease lapsed
    env.ledger.apply(env.token, d2.action, "ttl-a", d2.decision_id)
    try:
        ka.record_remote_execution(d2)
        steps.append(("record lapsed d2", "accepted"))
    except Exception as e:                       # noqa: BLE001
        steps.append(("record lapsed d2", _err(e)[:100]))
    steps.append(("reconcile d1 executed=False", ka.reconcile(d1, False, "op checked ledger: d1 absent")))
    steps.append(("reconcile d2 executed=True", ka.reconcile(d2, True, "op checked ledger: d2 present")))
    kc = env.kernel("ttl-c")
    for i in range(3):
        dc = kc.authorize(T(SRC, f"C{i}", 9000))
        steps.append((f"c auth {i}", dc.verdict))
        if dc.permitted:
            steps.append((f"c exec {i}", kc.execute(dc, env.commit_fn(kc, dc))[0]))
    m, v, sec = g1_eval(env)
    record("G1-08-ttl-unconfirmed-release-reconcile", "G1", "within_config",
           CFG_G1 + "; decision_ttl_s=0.3",
           "A authorizes 2x9000, both lapse to UNCONFIRMED; execute of lapsed "
           "refused; release of lapsed refused; B authorizes; a remote runtime "
           "applies d2 anyway; truthful reconcile (d1 absent, d2 present); C "
           "authorizes 3x9000", before, env.state(), v, {**m, "steps": steps},
           errs, secondary=sec)


def g1_release_mix():
    """Authorize to fill budget, release some, others take the slot."""
    env = Env("g1release")
    before = env.state()
    ka, kb = env.kernel("rel-a"), env.kernel("rel-b")
    steps = []
    held = [ka.authorize(T(SRC, f"A{i}", 9000)) for i in range(3)]
    steps.append(("a auth x3", [d.verdict for d in held]))
    for d in held:
        if d.permitted:
            steps.append(("release", ka.release(d)))
            steps.append(("execute released", ka.execute(d, env.commit_fn(ka, d))[0]))
    # release by a different principal's kernel of A's live decision
    d = ka.authorize(T(SRC, "A9", 9000))
    steps.append(("b.release(a's decision)", kb.release(d)))
    steps.append(("a exec", ka.execute(d, env.commit_fn(ka, d))[0]))
    for i in range(4):
        db = kb.authorize(T(SRC, f"B{i}", 9000))
        steps.append((f"b auth {i}", db.verdict))
        if db.permitted:
            steps.append((f"b exec {i}", kb.execute(db, env.commit_fn(kb, db))[0]))
    m, v, sec = g1_eval(env)
    record("G1-09-release-mix", "G1", "within_config", CFG_G1,
           "reserve/release/execute-after-release, cross-principal release, "
           "then refill", before, env.state(), v, {**m, "steps": steps},
           secondary=sec)


def g1_approvals():
    """Approved (signed) large transfers from SHARED by several principals."""
    env = Env("g1appr")
    before = env.state()
    approver = ApprovalService(APPROVAL_KEY, lambda c: (True, "approve all"))
    rows = []
    for i in range(4):
        g = env.gateway(env.kernel(f"ap{i}", signing_key=APPROVAL_KEY), approver)
        r = g.submit(T(SRC, f"AP{i}", 12000))
        rows.append({"verdict": r["verdict"], "rule": r["rule"],
                     "approval": bool(r["approval"]), "executed": r["executed"]})
    # pre-issued approval for an over-limit second transfer, same principal
    k = env.kernel("ap0", signing_key=APPROVAL_KEY)
    art = approver.request(T(SRC, "AP-X", 12000))
    r = env.gateway(k).submit(T(SRC, "AP-X", 12000), approvals=(art,))
    rows.append({"pre-approved": r["verdict"], "rule": r["rule"], "executed": r["executed"]})
    m, v, sec = g1_eval(env)
    record("G1-10-approvals", "G1", "within_config",
           CFG_G1 + "; approver signs everything",
           "4 principals each request 12000 (above auto-approve 10000) from SHARED with a signed approval;"
           " then a pre-approved over-limit transfer", before, env.state(), v,
           {**m, "attempts": rows}, secondary=sec)


def g1_call_shapes():
    """Aliases, top-level fields, nested/extra args, tool-name spellings."""
    shapes = [
        {"tool": "transfer", "arguments": json.dumps({"from": SRC, "to": "S1", "amount": 9000})},
        {"tool": "TRANSFER", "args": {"from": SRC, "to": "S2", "amount": 9000}},
        {"tool": " Transfer ", "input": {"from": SRC, "to": "S3", "amount": 9000}},
        {"tool": "transfer", "from": SRC, "to": "S4", "amount": 9000},
        {"tool": "transfer", "args": {"from": SRC, "to": "S5", "amount": 9000,
                                      "memo": {"from": "OPS", "amount": -1}}},
        {"tool": "transfer", "tool_input": {"from": SRC, "to": "S6", "amount": 9000,
                                            "_trace_id": "x"}},
        {"tool": "transfer", "arguments": '{"from":"OPS","from":"SHARED","to":"S7","amount":9000}'},
        {"tool": "transfer", "args": {"from": SRC, "to": "S8", "amount": 9000,
                                      "authorized": False}},
    ]
    env = Env("g1shapes")
    before = env.state()
    rows, errs = [], []
    for i, call in enumerate(shapes):
        try:
            r = env.gateway(env.kernel(f"sh{i}")).submit(call)
            rows.append({"call": call, "verdict": r["verdict"], "rule": r["rule"],
                         "executed": r["executed"], "result": r["result"][:100]})
        except Exception as e:                       # noqa: BLE001
            errs.append(_err(e))
    m, v, sec = g1_eval(env)
    record("G1-11-call-shapes", "G1", "within_config", CFG_G1,
           "8 differently-spelled transfers of 9000 from SHARED by 8 principals",
           before, env.state(), v, {**m, "attempts": rows}, errs, secondary=sec)


def g1_account_spellings():
    """Spellings of SHARED: does the ledger debit SHARED for any spelling the
    scope/rule treat as a different account?"""
    spellings = ["shared", " SHARED", "SHARED ", "SHARED\x00", "ＳHARED",
                 "SHARED​", "SHΑRED", "Shared"]
    env = Env("g1spell")
    before = env.state()
    rows = []
    for i, s in enumerate(spellings):
        k = env.kernel(f"sp{i}")
        d = k.authorize(T(s, f"P{i}", 20000 if i % 2 else 9000))
        row = {"spelling": repr(s), "verdict": d.verdict}
        if d.permitted:
            ok, res = k.execute(d, env.commit_fn(k, d))
            row.update(executed=ok, result=str(res)[:100])
        rows.append(row)
    # Fill the real budget afterwards to see if any spelling landed on SHARED.
    for i in range(4):
        env.gateway(env.kernel(f"fill{i}")).submit(T(SRC, f"F{i}", 9000))
    m, v, sec = g1_eval(env)
    record("G1-12-account-spellings", "G1", "within_config", CFG_G1,
           f"transfers from {[repr(s) for s in spellings]} then fill SHARED",
           before, env.state(), v, {**m, "attempts": rows}, secondary=sec)


def g1_same_principal_many_kernels():
    """One principal, 5 kernels (sessions), interleaved authorize/execute."""
    env = Env("g1samep")
    before = env.state()
    ks = [env.kernel("same", session_id=f"s{i}") for i in range(5)]
    others = [env.kernel(f"o{i}") for i in range(3)]
    pend = []
    for i, k in enumerate(ks + others):
        d = k.authorize(T(SRC, f"Q{i}", 6000))
        pend.append((k, d))
    for k, d in reversed(pend):
        if d.permitted:
            k.execute(d, env.commit_fn(k, d))
    m, v, sec = g1_eval(env)
    record("G1-13-same-principal-several-kernels", "G1", "within_config",
           CFG_G1, "principal 'same' in 5 kernels + 3 others: authorize all "
           "6000 first, execute in reverse order", before, env.state(), v,
           {**m, "verdicts": [d.verdict for _, d in pend]}, secondary=sec)


def g1_mint_lease():
    """Exported (EXPORTED) authority redeemed at the resource; others see it."""
    from morrison_governance._ed25519_test_signer import public_key, sign
    from morrison_governance.kernel import LeaseVerifier, SQLiteLeaseStore
    seed = hashlib.sha256(b"refalsify-lease-seed").digest()
    env = Env("g1lease")
    before = env.state()
    reg = SQLiteLeaseStore(str(env.dir / "leases.db"))
    ka = env.kernel("lease-a")
    ka.ctx = dataclasses.replace(ka.ctx, lease_signer=lambda m: sign(seed, m),
                                 lease_store=reg)
    verifier = LeaseVerifier(public_key(seed), reg)
    steps, errs = [], []
    try:
        d = ka.authorize(T(SRC, "L1", 9000))
        lease = ka.mint_lease(d)
        ok, res = verifier.execute(lease.encode(), d.action,
                                   lambda a: env.ledger.apply(env.token, a, "lease-a", d.decision_id))
        steps.append(("redeem", ok))
        steps.append(("release after redeem", ka.release(d)))
        d2 = ka.authorize(T(SRC, "L2", 9000))
        lease2 = ka.mint_lease(d2)
        steps.append(("release before redeem", ka.release(d2)))
        ok2, r2 = verifier.execute(lease2.encode(), d2.action,
                                   lambda a: env.ledger.apply(env.token, a, "lease-a", d2.decision_id))
        steps.append(("redeem cancelled", ok2, str(r2)[:80]))
    except Exception as e:                           # noqa: BLE001
        errs.append(_err(e))
    kb = env.kernel("lease-b")
    for i in range(4):
        db = kb.authorize(T(SRC, f"LB{i}", 5000))
        steps.append((f"b auth {i}", db.verdict))
        if db.permitted:
            kb.execute(db, env.commit_fn(kb, db))
    m, v, sec = g1_eval(env)
    record("G1-14-mint-lease", "G1", "within_config", CFG_G1 +
           "; Ed25519 lease_signer + SQLiteLeaseStore",
           "A mints+redeems 9000, release-after-redeem, mint 9000 + release + "
           "redeem attempt; B tries 4x5000", before, env.state(), v,
           {**m, "steps": steps}, errs, secondary=sec)


# ── concurrency ───────────────────────────────────────────────────────────
def _thread_rep(store_kind: str, n: int, amount: int, mode: str) -> dict:
    env = Env(f"g1thr-{store_kind}-{mode}", store_kind=store_kind)
    stores = None
    if store_kind == "file-multi":
        stores = [FileContinuityStore(env.store_path, fsync=False) for _ in range(n)]
    barrier = threading.Barrier(n)
    errs: list = []
    verdicts: list = []

    def go(i):
        try:
            store = stores[i] if stores else None
            k = env.kernel(f"t{i}" if mode != "same-principal" else "same",
                           store=store, session_id=f"sess{i}")
            if mode == "auth-barrier-exec":
                d = k.authorize(T(SRC, f"T{i}", amount))
                barrier.wait()
                if d.permitted:
                    k.execute(d, env.commit_fn(k, d))
                verdicts.append(d.verdict)
            elif mode == "release-mix":
                barrier.wait()
                d = k.authorize(T(SRC, f"T{i}", amount))
                if d.permitted and i % 3 == 0:
                    k.release(d)
                    d = k.authorize(T(SRC, f"T{i}b", amount))
                if d.permitted:
                    k.execute(d, env.commit_fn(k, d))
                verdicts.append(d.verdict)
            else:
                barrier.wait()
                for j in range(2):
                    d = k.authorize(T(SRC, f"T{i}-{j}", amount))
                    if d.permitted:
                        k.execute(d, env.commit_fn(k, d))
                    verdicts.append(d.verdict)
        except Exception as e:                       # noqa: BLE001
            errs.append(_err(e))

    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(120)
    m, v, sec = g1_eval(env)
    shutil.rmtree(env.dir, ignore_errors=True)
    return {"violated": v, **m, "permits": verdicts.count("PERMIT"),
            "secondary": sec, "errors": errs[:5]}


def g1_threads(reps: int):
    configs = [
        ("memory", 16, 5000, "auth-exec-x2"),
        ("memory", 16, 9000, "auth-barrier-exec"),
        ("memory", 16, 5000, "release-mix"),
        ("memory", 12, 5000, "same-principal"),
        ("file", 8, 5000, "auth-exec-x2"),
        ("file-multi", 8, 5000, "auth-barrier-exec"),
    ]
    for kind, n, amount, mode in configs:
        r = reps if kind == "memory" else max(30, reps // 2)
        before = {"SHARED": INITIAL[SRC][1]}
        reps_out = [_thread_rep(kind, n, amount, mode) for _ in range(r)]
        worst = max(x["ledger_outflow_SHARED"] for x in reps_out)
        record(f"G1-20-threads-{kind}-{mode}-n{n}", "G1", "within_config",
               CFG_G1 + f"; store={kind}; {n} threads, one principal per thread"
               + (" (all the same principal)" if mode == "same-principal" else ""),
               f"{r} reps; each thread transfers {amount} from SHARED ({mode})",
               before, {"max_ledger_outflow_SHARED": worst},
               any(x["violated"] for x in reps_out),
               {"max_outflow": worst,
                "outflow_per_rep": [x["ledger_outflow_SHARED"] for x in reps_out]},
               sorted({e for x in reps_out for e in x["errors"]})[:10],
               repeats=reps_out)


def _proc_worker(store_path, ledger_path, token, principal, session, amount,
                 attempts, barrier, queue, mode):
    try:
        env_store = FileContinuityStore(store_path, fsync=False)
        ledger = Ledger.attach(Path(ledger_path), token)
        k = make_kernel(principal=principal, tenant="acme", store=env_store,
                        rules=[aggregate_outflow_rule(SRC, LIMIT)],
                        resource_scopes=account_scopes, session_id=session)
        out = []
        decisions = []
        barrier.wait(60)
        for j in range(attempts):
            d = k.authorize(T(SRC, f"{principal}-{session}-{j}", amount))
            if mode == "auth-all-then-exec":
                decisions.append(d)
                continue
            ok = False
            if d.permitted:
                ok, _ = k.execute(d, lambda a, d=d: ledger.apply(token, a, principal, d.decision_id))
            out.append((d.verdict, ok))
        for d in decisions:
            ok = False
            if d.permitted:
                ok, _ = k.execute(d, lambda a, d=d: ledger.apply(token, a, principal, d.decision_id))
            out.append((d.verdict, ok))
        queue.put({"principal": principal, "results": out})
    except Exception as e:                           # noqa: BLE001
        queue.put({"principal": principal, "error": _err(e)})


def g1_processes(reps: int, nproc: int):
    ctx = mp.get_context("spawn")
    configs = [("distinct", "exec-each"), ("distinct", "auth-all-then-exec"),
               ("same-principal", "exec-each")]
    for who, mode in configs:
        reps_out = []
        for _ in range(reps):
            env = Env(f"g1proc-{who}", store_kind="file")
            q, barrier = ctx.Queue(), ctx.Barrier(nproc)
            procs = []
            for i in range(nproc):
                principal = f"proc{i}" if who == "distinct" else "same"
                p = ctx.Process(target=_proc_worker, args=(
                    env.store_path, str(env.ledger_path), env.token, principal,
                    f"s{i}", 5000, 2, barrier, q, mode))
                p.start()
                procs.append(p)
            res = [q.get(timeout=180) for _ in procs]
            for p in procs:
                p.join(60)
            m, v, sec = g1_eval(env)
            reps_out.append({"violated": v, **m, "secondary": sec,
                             "errors": [r["error"] for r in res if "error" in r],
                             "permits": sum(1 for r in res for x in r.get("results", [])
                                            if x[0] == "PERMIT")})
            shutil.rmtree(env.dir, ignore_errors=True)
        worst = max(x["ledger_outflow_SHARED"] for x in reps_out)
        record(f"G1-21-processes-{who}-{mode}-p{nproc}", "G1", "within_config",
               CFG_G1 + f"; FileContinuityStore on one host; {nproc} processes"
               + ("; all the same principal" if who != "distinct" else ""),
               f"{reps} reps; each process transfers 5000 from SHARED twice ({mode})",
               {"SHARED": INITIAL[SRC][1]}, {"max_ledger_outflow_SHARED": worst},
               any(x["violated"] for x in reps_out),
               {"max_outflow": worst,
                "outflow_per_rep": [x["ledger_outflow_SHARED"] for x in reps_out]},
               sorted({e for x in reps_out for e in x["errors"]})[:10],
               repeats=reps_out)


def g1_retention_window():
    """Default continuity_window_s (3600s): simulate wall time moving past
    the window. Clock shim on the gate module only (no kernel code changed)."""
    env = Env("g1window")
    before = env.state()
    ka = env.kernel("win-a")
    steps = []
    for i in range(3):
        d = ka.authorize(T(SRC, f"W{i}", 9000))
        steps.append(("t0", d.verdict))
        if d.permitted:
            ka.execute(d, env.commit_fn(ka, d))
    real = time.time

    class _Clock:
        def __getattr__(self, name):
            return getattr(time, name)

        @staticmethod
        def time():
            return real() + 3601.0

    saved = gate_mod.time
    try:
        gate_mod.time = _Clock()
        kb = env.kernel("win-b")
        for i in range(3):
            d = kb.authorize(T(SRC, f"V{i}", 9000))
            steps.append(("t0+3601s", d.verdict))
            if d.permitted:
                kb.execute(d, env.commit_fn(kb, d))
    finally:
        gate_mod.time = saved
    m, v, sec = g1_eval(env)
    record("G1-15-default-retention-window", "G1", "within_config",
           CFG_G1 + "; SecurityContext defaults (continuity_window_s=3600)",
           "A executes 2x9000; wall clock (as seen by gate.py) advanced by "
           "3601s; B executes 9000s again", before, env.state(), v,
           {**m, "steps": steps}, secondary=sec,
           note="Documented retention: history older than continuity_window_s "
                "leaves the trajectory (except EXPORTED). The limit is a "
                "rolling-window limit, not a lifetime limit.")


# ── precondition-not-met ──────────────────────────────────────────────────
def g1_preconditions():
    def scenario(cid, cfg, build):
        env = Env(cid)
        before = env.state()
        kernels = build(env)
        for i, k in enumerate(kernels):
            for j in range(2):
                d = k.authorize(T(SRC, f"{cid}-{i}-{j}", 9000))
                if d.permitted:
                    k.execute(d, env.commit_fn(k, d))
        m, v, sec = g1_eval(env)
        record(f"G1-30-{cid}", "G1", "precondition_not_met", cfg,
               f"{len(kernels)} kernels x 2 transfers of 9000 from SHARED",
               before, env.state(), v, m, secondary=sec)

    scenario("separate-stores", "each kernel has its own InMemoryContinuityStore",
             lambda e: [e.kernel(f"a{i}", store=InMemoryContinuityStore()) for i in range(3)])
    scenario("one-kernel-unscoped", "one kernel without resource_scopes",
             lambda e: [e.kernel("scoped"), e.kernel("unscoped", scopes=None)])
    scenario("different-limit", "second kernel's rule limit 1_000_000",
             lambda e: [e.kernel("a"), e.kernel("b", rules=[aggregate_outflow_rule(SRC, 1_000_000)])])
    scenario("different-resolver", "second kernel's resolver uses lowercased ids",
             lambda e: [e.kernel("a"), e.kernel("b", scopes=lambda c: [f"account:{str((c.get('args') or {}).get('from')).lower()}"] if c.get("tool") == "transfer" else [])])

    def anon(e):
        ks = []
        for i in range(3):
            k = e.kernel("anonymous")
            k.ctx = dataclasses.replace(k.ctx, continuity_policy="permit")
            ks.append(k)
        return ks
    scenario("anonymous-continuity-permit",
             "principal 'anonymous' with continuity_policy='permit' (no "
             "continuity key, so _reserve files nothing, scope copy skipped)", anon)

    def window(e):
        ks = []
        for i in range(2):
            k = e.kernel(f"w{i}")
            k.ctx = dataclasses.replace(k.ctx, continuity_window_s=0.05)
            ks.append(k)
        return ks
    env = Env("small-window")
    before = env.state()
    for i, k in enumerate(window(env)):
        for j in range(2):
            d = k.authorize(T(SRC, f"sw{i}{j}", 9000))
            if d.permitted:
                k.execute(d, env.commit_fn(k, d))
        time.sleep(0.1)
    m, v, sec = g1_eval(env)
    record("G1-30-small-window", "G1", "precondition_not_met",
           "continuity_window_s=0.05 (non-default)", "2 kernels x 2x9000, 0.1s apart",
           before, env.state(), v, m, secondary=sec)


# ══════════════════════════════════════════════════════════════════════════
# E12
# ══════════════════════════════════════════════════════════════════════════
def e12_cases():
    approver = ApprovalService(APPROVAL_KEY, lambda c: (True, "approve all"))
    cases = [
        ("baseline-acme-from", T("OPS", "BETA-PAYEE", 1000), False),
        ("negative-int-to-acme", T("BETA-OPS", "OPS", -5000), False),
        ("negative-string-to-acme", T("BETA-OPS", "ACME-2", "-5000"), False),
        ("negative-float-to-acme", T("BETA-OPS", "OPS", -5000.5), False),
        ("negative-big-to-shared", T("BETA-OPS", "SHARED", -90000), False),
        ("negative-with-approval", T("BETA-OPS", "OPS", -50000), True),
        ("tool-upper", {"tool": "TRANSFER", "args": {"from": "OPS", "to": "B", "amount": 10}}, False),
        ("tool-padded", {"tool": " transfer\t", "args": {"from": "OPS", "to": "B", "amount": 10}}, False),
        ("arguments-json-dup-keys", {"tool": "transfer", "arguments": '{"from":"BETA-OPS","from":"OPS","to":"B","amount":10}'}, False),
        ("toplevel-from-plus-args", {"tool": "transfer", "from": "BETA-OPS", "args": {"from": "OPS", "to": "B", "amount": 10}}, False),
        ("toplevel-only", {"tool": "transfer", "from": "OPS", "to": "B", "amount": 10}, False),
        ("input-alias", {"tool": "transfer", "input": {"from": "OPS", "to": "B", "amount": 10}}, False),
        ("from-list", T(["OPS"], "B", 10), False),
        ("from-missing", {"tool": "transfer", "args": {"to": "B", "amount": 10}}, False),
        ("from-lower", T("ops", "B", 10), False),
        ("from-nul", T("OPS\x00", "B", 10), False),
        ("from-zwsp", T("OPS​", "B", 10), False),
        ("approval-cross-tenant", T("OPS", "B", 10), True),
        ("approval-large-cross-tenant", T("OPS", "B", 50000), True),
        ("tenant-key-confusion", T("BETA-OPS", "B", 10, tenant_id="beta", account_id="BETA-OPS"), False),
        ("control-own-beta", T("BETA-OPS", "OPS", 1000), False),
    ]
    for name, call, use_approval in cases:
        env = Env(f"e12-{name}")
        before = env.state()
        k = env.kernel("beta-agent", tenant="beta", owners=OWNERS,
                       signing_key=APPROVAL_KEY if use_approval else b"")
        g = env.gateway(k, approver if use_approval else None)
        errs = []
        try:
            r = g.submit(call)
            row = {"verdict": r["verdict"], "rule": r["rule"], "layer": r["layer"],
                   "approval": bool(r["approval"]), "executed": r["executed"],
                   "result": r["result"][:140]}
        except Exception as e:                       # noqa: BLE001
            row, errs = {}, [_err(e)]
        debits = env.acme_debits_by({"beta-agent"})
        record(f"E12-{name}", "E12", "within_config",
               CFG_E12 + "; principal beta-agent, tenant beta" +
               ("; approver signs everything" if use_approval else ""),
               f"submit {call!r}", before, env.state(), bool(debits),
               {**row, "acme_debits": debits}, errs)

    # preview + record_remote_execution cross-tenant (remote path)
    env = Env("e12-remote")
    before = env.state()
    k = env.kernel("beta-agent", tenant="beta", owners=OWNERS)
    d = k.preview(T("OPS", "B", 10))
    record("E12-preview-remote", "E12", "within_config", CFG_E12,
           "preview cross-tenant transfer (remote runtime would only act on a "
           "PERMIT)", before, env.state(), d.permitted, {"verdict": d.verdict,
                                                       "rule": d.rule})

    # precondition-not-met: E12 switched off / registry wrong
    for name, owners, tenant in [("owners-none", None, "beta"),
                                 ("registry-says-beta", {**OWNERS, "OPS": "beta"}, "beta"),
                                 ("tenant-spelled-differently", OWNERS, "Beta")]:
        env = Env(f"e12pre-{name}")
        before = env.state()
        k = env.kernel("beta-agent", tenant=tenant, owners=owners)
        r = env.gateway(k).submit(T("OPS", "B", 10))
        debits = env.acme_debits_by({"beta-agent"})
        record(f"E12-pre-{name}", "E12", "precondition_not_met",
               f"owners={owners!r}, tenant={tenant!r}", "submit T(OPS,B,10)",
               before, env.state(), bool(debits),
               {"verdict": r["verdict"], "rule": r["rule"], "acme_debits": debits})


# ══════════════════════════════════════════════════════════════════════════
# E10
# ══════════════════════════════════════════════════════════════════════════
def _intent_for(kernel, decision_id) -> bool:
    return any(getattr(r, "layer", "") == "execution_intent"
               and (r.authorization or {}).get("decision_id") == decision_id
               for r in list(kernel.chain.records))


def _e10_run(name: str, inject: Callable, *, executor_raises=False,
             call_param=False, label="within_config", note=""):
    env = Env(f"e10-{name}")
    before = env.state()
    k = env.kernel("e10-agent", scopes=account_scopes)
    d = k.authorize(T("OPS", "E", 100))
    runs = []

    def executor(action):
        runs.append({"intent_present_at_dispatch": _intent_for(k, d.decision_id)})
        env.ledger.apply(env.token, action, "e10-agent", d.decision_id)
        if executor_raises:
            raise RuntimeError("executor failed after the write")
        return "ok"

    errs = []
    restore = inject(k, d)
    try:
        ok, res = k.execute(d, executor, call=T("OPS", "E", 100) if call_param else None)
    except BaseException as e:                       # noqa: BLE001
        ok, res = False, None
        errs.append("propagated: " + _err(e))
    finally:
        if restore:
            restore()
    violated = any(not r["intent_present_at_dispatch"] for r in runs)
    effects = env.state()["effect_count"] - before["effect_count"]
    # executor not run but effect present would also be a violation
    violated = violated or (effects > 0 and not runs)
    record(f"E10-{name}", "E10", label, CFG_E10, f"inject: {name}", before,
           env.state(), violated,
           {"execute_returned": [ok, str(res)[:160]], "executor_runs": runs,
            "ledger_effects": effects,
            "intent_records_for_decision": sum(
                1 for r in k.chain.records if r.layer == "execution_intent"
                and (r.authorization or {}).get("decision_id") == d.decision_id),
            "chain_verify": k.chain.verify()[0],
            "evidence_failures": len(k.evidence_failures)}, errs, note=note)


def e10_cases():
    def raise_on(pred, exc=RuntimeError("evidence store down")):
        def inj(k, d):
            real = k.chain.append

            def broken(rec):
                if pred(rec):
                    raise exc
                return real(rec)
            k.chain.append = broken
            return lambda: setattr(k.chain, "append", real)
        return inj

    _e10_run("append-always-fails", raise_on(lambda r: True))
    _e10_run("append-fails-on-intent-only", raise_on(lambda r: r.layer == "execution_intent"))
    _e10_run("append-keyboardinterrupt-on-intent",
             raise_on(lambda r: r.layer == "execution_intent", KeyboardInterrupt()))
    _e10_run("append-systemexit-on-intent",
             raise_on(lambda r: r.layer == "execution_intent", SystemExit(3)))
    _e10_run("append-fails-on-execution-outcome", raise_on(lambda r: r.layer == "execution"))
    _e10_run("append-fails-on-refusal", raise_on(lambda r: r.decision == "BLOCK"))

    for nth in range(1, 5):
        def inj(k, d, nth=nth):
            real, n = k.chain.append, {"c": 0}

            def broken(rec):
                n["c"] += 1
                if n["c"] == nth:
                    raise RuntimeError(f"append #{nth} fails")
                return real(rec)
            k.chain.append = broken
            return lambda: setattr(k.chain, "append", real)
        _e10_run(f"append-fails-on-call-{nth}", inj)

    def append_then_raise(k, d):
        real = k.chain.append

        def broken(rec):
            real(rec)
            if rec.layer == "execution_intent":
                raise RuntimeError("written but ack lost")
            return rec
        k.chain.append = broken
        return lambda: setattr(k.chain, "append", real)
    _e10_run("append-writes-then-raises", append_then_raise)

    def record_exec_fails(k, d):
        real = k.chain.record_execution
        k.chain.record_execution = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("down"))
        return lambda: setattr(k.chain, "record_execution", real)
    _e10_run("record-execution-fails", record_exec_fails)

    for meth in ("consume", "set_state", "entries", "consumed", "revocation",
                 "transaction", "append", "drop"):
        def inj(k, d, meth=meth):
            real = getattr(k.store, meth)

            def broken(*a, **kw):
                raise RuntimeError(f"store.{meth} down")
            setattr(k.store, meth, broken)
            return lambda: setattr(k.store, meth, real)
        _e10_run(f"store-{meth}-fails", inj)

    _e10_run("executor-raises", lambda k, d: None, executor_raises=True)
    _e10_run("call-param-path", lambda k, d: None, call_param=True)

    def forged_auth(k, d):
        d.authorization = {**(d.authorization or {}), "decision_id": "forged"}
    _e10_run("decision-authorization-forged-id", forged_auth)

    def none_auth(k, d):
        d.authorization = None
    _e10_run("decision-authorization-none", none_auth)

    def chain_swapped(k, d):
        from morrison_governance.kernel.evidence import EvidenceChain
        k.chain = EvidenceChain()
    _e10_run("chain-replaced-between-authorize-and-execute", chain_swapped)

    # pending outcome + intent failure on the next execution
    env = Env("e10-pending")
    before = env.state()
    k = env.kernel("e10-agent")
    runs = []
    d1 = k.authorize(T("OPS", "E", 1)); d2 = k.authorize(T("OPS", "E", 2))
    real_rx, real_ap = k.chain.record_execution, k.chain.append
    k.chain.record_execution = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("down"))

    def ex(d):
        def run(a):
            runs.append(_intent_for(k, d.decision_id))
            env.ledger.apply(env.token, a, "e10-agent", d.decision_id)
        return run
    r1 = k.execute(d1, ex(d1))
    k.chain.record_execution = real_rx
    k.chain.append = lambda rec: (_ for _ in ()).throw(RuntimeError("down")) \
        if rec.layer == "execution_intent" else real_ap(rec)
    r2 = k.execute(d2, ex(d2))
    k.chain.append = real_ap
    record("E10-pending-outcome-then-intent-fails", "E10", "within_config",
           CFG_E10, "d1 runs with outcome recorder down (queued); d2: pending "
           "flush succeeds, intent append fails", before, env.state(),
           not all(runs) or len(runs) != 1,
           {"r1": [r1[0], str(r1[1])[:80]], "r2": [r2[0], str(r2[1])[:80]],
            "intent_at_dispatch": runs, "chain_verify": k.chain.verify()[0]})

    # reentrant executor
    env = Env("e10-reentrant")
    before = env.state()
    k = env.kernel("e10-agent")
    d_out = k.authorize(T("OPS", "E", 1)); d_in = k.authorize(T("OPS", "E", 2))
    seen = []

    def inner(a):
        seen.append(("inner", _intent_for(k, d_in.decision_id)))
        env.ledger.apply(env.token, a, "e10-agent", d_in.decision_id)

    def outer(a):
        seen.append(("outer", _intent_for(k, d_out.decision_id)))
        env.ledger.apply(env.token, a, "e10-agent", d_out.decision_id)
        return k.execute(d_in, inner)
    res = k.execute(d_out, outer)
    record("E10-reentrant-executor", "E10", "within_config", CFG_E10,
           "executor of d_out calls kernel.execute(d_in)", before, env.state(),
           not all(x[1] for x in seen), {"seen": seen, "result": str(res)[:120]})

    # submit() and GovernedGateway paths
    env = Env("e10-submit")
    before = env.state()
    k = env.kernel("e10-agent")
    seen = []
    holder = {}

    def ex2(a):
        ok = any(r.layer == "execution_intent" for r in k.chain.records
                 if r.action_hash == holder.get("h"))
        seen.append(ok)
        env.ledger.apply(env.token, a, "e10-agent", "")
    from morrison_governance.kernel.canonical import action_hash, canonicalize
    holder["h"] = action_hash(canonicalize(T("OPS", "E", 3)))
    k.submit(T("OPS", "E", 3), ex2)
    record("E10-kernel-submit", "E10", "within_config", CFG_E10,
           "GovernanceKernel.submit()", before, env.state(), not all(seen),
           {"intent_at_dispatch": seen})


def _e10_concurrency_rep(n: int, same_decision: bool) -> dict:
    env = Env("e10conc")
    k = env.kernel("e10-agent", scopes=account_scopes)
    k.ctx = dataclasses.replace(k.ctx, max_outstanding_reservations=0)
    shared = k.authorize(T("OPS", "E", 1)) if same_decision else None
    decisions = ([shared] * n if same_decision
                 else [k.authorize(T("OPS", f"E{i}", 1)) for i in range(n)])
    barrier = threading.Barrier(n)
    runs, errs = [], []
    lock = threading.Lock()

    def go(i):
        d = decisions[i]
        try:
            def ex(a):
                present = _intent_for(k, d.decision_id)
                with lock:
                    runs.append(present)
                time.sleep(0.001)
                env.ledger.apply(env.token, a, "e10-agent", d.decision_id)
            barrier.wait()
            k.execute(d, ex)
        except Exception as e:                       # noqa: BLE001
            errs.append(_err(e))

    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(60)
    eff = env.state()["effect_count"]
    ok_chain, problems = k.chain.verify()
    shutil.rmtree(env.dir, ignore_errors=True)
    expected = 1 if same_decision else n
    return {"violated": (not all(runs)) or eff != len(runs) or len(runs) > expected,
            "executor_runs": len(runs), "ledger_effects": eff,
            "all_intents_present": all(runs), "chain_verify": ok_chain,
            "chain_problems": problems[:3], "errors": errs[:3]}


def e10_concurrency(reps: int):
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for same, n in ((False, 16), (True, 16)):
            rs = [_e10_concurrency_rep(n, same) for _ in range(reps)]
            record(f"E10-concurrency-{'same' if same else 'distinct'}-decision-n{n}",
                   "E10", "within_config", CFG_E10 + "; switchinterval 1us",
                   f"{reps} reps; {n} threads execute "
                   f"{'ONE decision' if same else 'distinct decisions'} on one kernel",
                   None, None, any(r["violated"] for r in rs),
                   {"executor_runs_per_rep": [r["executor_runs"] for r in rs],
                    "chain_verify_failures": sum(1 for r in rs if not r["chain_verify"])},
                   repeats=rs,
                   note="chain_verify is reported separately: the outcome "
                        "record is appended outside the kernel lock, so a "
                        "concurrent append may fork the hash chain. It does "
                        "not remove an intent record.")
    finally:
        sys.setswitchinterval(old)


def e10_other_effect_paths():
    """record_remote_execution and mint_lease cause/acknowledge effects
    without kernel.execute; check whether an execution_intent exists."""
    env = Env("e10-other")
    before = env.state()
    k = env.kernel("e10-agent")
    d = k.authorize(T("OPS", "E", 5))
    env.ledger.apply(env.token, d.action, "e10-agent", d.decision_id)
    k.record_remote_execution(d)
    record("E10-other-record-remote-execution", "E10", "outside_property", CFG_E10,
           "authorize, remote runtime applies, record_remote_execution",
           before, env.state(), False,
           {"intent_records": sum(1 for r in k.chain.records if r.layer == "execution_intent"),
            "layers": [r.layer for r in k.chain.records]},
           note="Not a violation of the stated property (execute() is not "
                "used); recorded because the remote path has no pre-effect "
                "intent record.")


# ══════════════════════════════════════════════════════════════════════════
def main(argv=None) -> int:
    global WORK
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--output", required=True)
    ap.add_argument("--tag", default="")
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--procs", type=int, default=6)
    ap.add_argument("--keep-work", action="store_true")
    a = ap.parse_args(argv)
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=True)
    tag = a.tag or time.strftime("%Y%m%dT%H%M%S")
    WORK = out / f"work-{tag}"
    WORK.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    steps = [g1_sequential_many_principals, g1_amount_types,
             g1_negative_amount_net, g1_negative_phantom,
             g1_negative_reverse_leg, g1_preview_remote_record,
             g1_reserved_remote_record, g1_release_reconcile_ttl,
             g1_release_mix, g1_approvals, g1_call_shapes,
             g1_account_spellings, g1_same_principal_many_kernels,
             g1_mint_lease, g1_retention_window,
             lambda: g1_threads(a.reps), lambda: g1_processes(a.reps, a.procs),
             g1_preconditions, e12_cases, e10_cases,
             lambda: e10_concurrency(a.reps), e10_other_effect_paths]
    for fn in steps:
        print(f"- {getattr(fn, '__name__', 'step')}", flush=True)
        run_case(fn)

    def tally(prop, label):
        cs = [c for c in CASES if c["property"] == prop and c["label"] == label]
        return {"cases": len(cs), "violated": sum(c["violated"] for c in cs),
                "violated_ids": [c["id"] for c in cs if c["violated"]]}
    summary = {p: {lab: tally(p, lab) for lab in
                   ("within_config", "precondition_not_met", "outside_property")}
               for p in ("G1", "E12", "E10")}
    summary["harness_errors"] = [c["id"] for c in CASES if c["label"] == "harness_error"]
    doc = {"tool": "runtime_eval.falsification.refalsify.kernel_claims",
           "commit_under_test": "9bb466a", "tag": tag,
           "python": platform.python_version(), "started": t0,
           "duration_s": round(time.time() - t0, 1),
           "reps": a.reps, "procs": a.procs, "limit": LIMIT,
           "primary_g1_measure": "Ledger.outflow('SHARED')",
           "summary": summary, "cases": CASES}
    path = out / f"kernel_claims-{tag}.json"
    path.write_text(json.dumps(doc, indent=2, default=str, sort_keys=False))
    if not a.keep_work:
        shutil.rmtree(WORK, ignore_errors=True)
    print(json.dumps(summary, indent=2))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
