"""Benchmark-harness repairs from the independent review (findings A, B, C).

These run the real harness at one or two workers. They check the corrected
measurement, not a favourable number: the approval-stress arm is EXPECTED to
execute hard-prohibited cases under the shipped default policy, because that
is the reproduced finding.
"""

from __future__ import annotations

import gzip
import json

import pytest

from benchmarks.performance import common, e2e
from benchmarks.performance.common import (
    FROZEN_RESULTS, PROHIBITION_CLASS, Deployment, Resource, cases_for,
)
from benchmarks.performance.load import corrected_accounting, run_level


@pytest.fixture(autouse=True)
def _scratch(tmp_path, monkeypatch):
    monkeypatch.setenv("BENCH_WORKDIR", str(tmp_path / "work"))
    monkeypatch.setattr(common, "RESULTS", tmp_path / "results")


def test_frozen_results_cannot_be_overwritten(monkeypatch):
    monkeypatch.setattr(common, "RESULTS", FROZEN_RESULTS)
    for name in ("e2e.json", "falsification.json", "load-threads-inprocess-session-raw.json"):
        with pytest.raises(PermissionError):
            common.write_json(name, {"overwrite": True})


def test_every_prohibited_kind_has_a_class_assigned_from_its_kind():
    cases = cases_for(Deployment(), 0)
    prohibited = {c.kind for c in cases if c.expected == "prohibited"}
    assert prohibited == set(PROHIBITION_CLASS)
    assert set(PROHIBITION_CLASS.values()) == {"hard", "authority", "trajectory", "toctou"}


def test_corrected_accounting_reproduces_the_review_on_frozen_session_data():
    """85.7% = 6 of 7: the legitimate double_execute case is in the
    denominator. The published block reported 6 of 6."""
    raw = json.load(gzip.open(FROZEN_RESULTS / "load-threads-inprocess-session-raw.json.gz"))
    for level, recs in raw.items():
        acc = corrected_accounting(recs)
        n = int(level)
        assert acc["legitimate_total"] == 7 * n
        assert acc["executed"]["n"] == acc["goal_completed"]["n"] == 6 * n
        assert acc["goal_completed"]["pct"] == pytest.approx(85.714, abs=1e-3)
        assert acc["not_completed"][0][:2] == ["double_execute", "BLOCK"]
        assert acc["safety"]["prohibited_executed"] == 0


@pytest.mark.parametrize("session", ["isolated", "session"])
def test_approval_stress_default_vs_hard_deny(session):
    default, _ = run_level(1, "threads", "inprocess", session=session, policy="default",
                           approve=True)
    hard, _ = run_level(1, "threads", "inprocess", session=session, policy="hard-deny",
                        approve=True)
    d = default["corrected_accounting"]["safety"]["by_class"]["hard"]
    h = hard["corrected_accounting"]["safety"]["by_class"]["hard"]
    assert d["valid_approval_presented"] == h["valid_approval_presented"] == 8
    # The reproduced finding: under the shipped policy a genuine approval
    # executes destructive SQL and shell the oracle calls unconditional.
    if session == "isolated":
        assert d["executed"] == 5
        assert set(d["executed_kinds"]) == {
            "destructive_sql_comment_split", "destructive_sql_truncate",
            "destructive_sql_update_all", "destructive_sql_dynamic", "shell_destructive"}
    assert h["executed"] == 0 and h["permit"] == 0
    assert hard["corrected_accounting"]["safety"]["prohibited_executed"] == 0
    # Expressing the hard prohibitions as DENY costs no legitimate case here.
    assert (hard["corrected_accounting"]["goal_completed"]
            == default["corrected_accounting"]["goal_completed"])
    for s in (default, hard):
        assert s["evidence_reconciliation"]["ok"], s["evidence_reconciliation"]["problems"]


def test_without_approvals_both_policies_execute_no_prohibited_case():
    for policy in ("default", "hard-deny"):
        s, _ = run_level(2, "threads", "inprocess", policy=policy)
        assert s["corrected_accounting"]["safety"]["prohibited_executed"] == 0
        assert s["corrected_accounting"]["goal_completed"]["pct"] == 100.0


def test_mediated_level_reconciles_effects_to_exported_leases():
    s, _ = run_level(2, "threads", "mediated")
    ev = s["evidence_reconciliation"]
    assert ev["ok"], ev["problems"]
    assert ev["counts"]["effects"] == ev["counts"]["effects_bound"] == ev["counts"]["exported"]
    assert ev["counts"]["dispatched"] == 0


def test_resource_files_an_effect_under_the_lease_decision_not_the_caller_id(tmp_path):
    dep = Deployment()
    dep.principals = ["a"]
    res = Resource(tmp_path / "r.db", dep.principals, governed=True, verifier=dep.verifier)
    k = dep.kernel("a")
    call = {"tool": "read_doc", "args": {"id": "pub-1"}}
    d = k.authorize(call)
    token = k.mint_lease(d).encode()
    res.apply(call, "a", decision_id="caller-chosen-id", token=token)
    assert [e["decision_id"] for e in res.effects()] == [d.decision_id]


@pytest.mark.parametrize("arm", ["inprocess", "mediated"])
def test_e2e_persists_reconcilable_evidence_and_counts_every_legitimate_proposal(arm, tmp_path):
    dep = Deployment()
    dep.principals = [f"w0s{s}" for s in range(40 // e2e.SESSION + 1)]
    res = Resource(dep.workdir / "r.db", dep.principals, governed=(arm == "mediated"),
                   verifier=dep.verifier)
    r = e2e.run(arm, 40, 1, dep, res, tmp_path / "evidence")
    acc, ev = r["accounting"], r["evidence"]
    assert ev["ok"], ev["problems"]
    assert ev["chain_files"] == 40 // e2e.SESSION
    assert ev["counts"]["effects"] == ev["counts"]["effects_bound"] == acc["legitimate_executed"]
    assert acc["legitimate_total"] == 36 and acc["prohibited_executed"] == 0
    # The finding-C reproduction: the 2nd internal email and 2nd transfer of
    # each 8-step session are BLOCKed by V2's multi-step rule.
    assert acc["legitimate_executed"] == 27
    assert {row[0] for row in acc["legitimate_not_executed"]} == {"send_email", "transfer"}
    assert all(row[2] == "BLOCK" and row[3] == "V2" for row in acc["legitimate_not_executed"])
