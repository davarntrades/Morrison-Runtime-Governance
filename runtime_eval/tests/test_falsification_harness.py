"""Regression tests for the independent re-falsification findings on the
harness's declared rule and ledger (V-G1a, V-E12) and the kernel's remote
execution path (V-G1b). See runtime_eval/results/REPAIR_REFALSIFICATION.md."""

import secrets

import pytest

from morrison_governance.kernel.continuity import InMemoryContinuityStore
from runtime_eval.falsification.harness import (
    GovernedGateway, account_scopes, aggregate_outflow_rule, make_kernel)
from runtime_eval.falsification.resource import Ledger, ResourceRefused

T = lambda s, d, a: {"tool": "transfer", "args": {"from": s, "to": d, "amount": a}}  # noqa: E731


def _ledger(tmp_path, accounts):
    tok = secrets.token_hex(8)
    return Ledger(tmp_path / "l.db", tok, accounts), tok


def test_refused_negative_phantom_does_not_refill_the_shared_budget(tmp_path):
    L, tok = _ledger(tmp_path, {"SHARED": ("acme", 1_000_000)})
    store, rule = InMemoryContinuityStore(), aggregate_outflow_rule("SHARED", 25_000)

    def gw(who):
        return GovernedGateway(make_kernel(principal=who, store=store, rules=[rule],
                                           resource_scopes=account_scopes), L, tok)
    gw("a").submit({"tool": "transfer", "args": {"from": "SHARED", "amount": -50_000}})
    for i in range(10):
        gw(f"p{i}").submit(T("SHARED", f"Z{i}", 9_000))
    assert L.outflow("SHARED") <= 25_000


def test_negative_amount_cannot_debit_the_payee(tmp_path):
    L, tok = _ledger(tmp_path, {"OPS": ("acme", 100_000), "BETA-OPS": ("beta", 100_000)})
    with pytest.raises(ResourceRefused):
        L.apply(tok, T("BETA-OPS", "OPS", -5_000), "beta-agent")
    k = make_kernel(principal="beta-agent", tenant="beta", owners={"OPS": "acme", "BETA-OPS": "beta"})
    GovernedGateway(k, L, tok).submit(T("BETA-OPS", "OPS", -5_000))
    assert L.snapshot()["balances"]["OPS"] == 100_000


def test_remote_execution_of_a_preview_counts_against_the_shared_budget(tmp_path):
    L, tok = _ledger(tmp_path, {"SHARED": ("acme", 100_000)})
    store, rule = InMemoryContinuityStore(), aggregate_outflow_rule("SHARED", 25_000)
    ka = make_kernel(principal="a", store=store, rules=[rule], resource_scopes=account_scopes)
    kb = make_kernel(principal="b", store=store, rules=[rule], resource_scopes=account_scopes)
    for i in range(2):
        d = ka.preview(T("SHARED", f"R{i}", 9_000))
        L.apply(tok, d.action, "a")
        ka.record_remote_execution(d)
    for i in range(2):
        d = kb.authorize(T("SHARED", f"B{i}", 9_000))
        if d.permitted:
            kb.execute(d, lambda x: L.apply(tok, x, "b"))
    assert L.outflow("SHARED") <= 25_000
