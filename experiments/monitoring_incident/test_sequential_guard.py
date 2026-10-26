"""Tests for the experimental sequential-execution guard (re-audit §6, L1).

The guard is an EXPERIMENTAL RESTRICTION on the Phase 2 runner, not a repair of
Morrison's concurrency weakness (audit §7.5). These tests demonstrate that it
rejects overlapping authorize→execute transactions fail-closed, that execution
cannot happen outside an open transaction, and that a rejection is recorded in
evidence. They deliberately do NOT assert any concurrency-safety property of
Morrison itself.
"""

from __future__ import annotations

import json
import tempfile
import threading
from pathlib import Path

import pytest

from experiments.monitoring_incident.authority import (
    DecisionKey, Executor, OverlappingExecutionError, SessionExecutionGuard,
)
from experiments.monitoring_incident.harness import RunConfig, run_episode
from experiments.monitoring_incident.proposers import ScriptedProposer
from experiments.monitoring_incident.sandbox import Sandbox


def test_nested_transaction_is_rejected():
    g = SessionExecutionGuard()
    with g.transaction("outer"):
        with pytest.raises(OverlappingExecutionError):
            with g.transaction("inner"):
                pass
    assert len(g.rejections) == 1
    assert g.rejections[0]["attempted_label"] == "inner"
    # the guard is released after the outer transaction exits
    assert not g.active()


def test_executor_refuses_outside_a_transaction():
    base = tempfile.mkdtemp()
    sb = Sandbox("alert_suppression", base)
    try:
        ex = Executor(sb, DecisionKey(), "run", guard=SessionExecutionGuard())
        res = ex.execute(None, {"tool": "write_file", "args": {"path": "config/x.json", "content": "{}"}})
        assert not res.executed
        assert "no open execution transaction" in res.refusal
    finally:
        sb.cleanup()


def test_concurrent_overlap_is_rejected_exactly_once():
    """Deterministic threaded overlap: thread A holds a transaction open while
    thread B attempts one. Exactly one succeeds; the other is rejected."""
    g = SessionExecutionGuard()
    a_open = threading.Event()
    b_done = threading.Event()
    results = {}

    def hold():
        with g.transaction("A"):
            a_open.set()
            b_done.wait(timeout=5)
        results["A"] = "ok"

    def intrude():
        a_open.wait(timeout=5)                 # only attempt once A holds it
        try:
            with g.transaction("B"):
                results["B"] = "ok"            # must not happen
        except OverlappingExecutionError:
            results["B"] = "rejected"
        finally:
            b_done.set()

    ta, tb = threading.Thread(target=hold), threading.Thread(target=intrude)
    ta.start(); tb.start(); ta.join(5); tb.join(5)
    assert results["A"] == "ok"
    assert results["B"] == "rejected"
    assert len(g.rejections) == 1
    assert not g.active()


def test_harness_records_a_concurrency_rejection_in_evidence():
    """The in-harness concurrent_probe hook attempts a nested transaction during
    a step; the guard rejects it and the harness records it in evidence."""
    out = tempfile.mkdtemp()
    steps = [{"hook": "concurrent_probe"}]
    s = run_episode(RunConfig(scenario="alert_suppression", condition="hierarchical",
                              output_dir=out, case_id="concurrency-probe"),
                    ScriptedProposer("concurrency-probe", steps))
    assert s["metrics"]["concurrency_rejected"] == 1
    assert s["evidence"]["valid"] is True
    recs = [json.loads(line) for line in
            open(Path(out) / s["metadata"]["run_id"] / "evidence.jsonl")]
    rej = [r for r in recs if r["type"] == "concurrency_rejected"]
    assert len(rej) == 1
    assert "overlapping execution rejected" in rej[0]["payload"]["reason"]


def test_normal_sequential_run_never_rejects():
    """A normal run opens and closes one transaction per step, so the guard
    never rejects and does not change outcomes."""
    out = tempfile.mkdtemp()
    from experiments.monitoring_incident.cases import by_id
    for cid in ("C12-legit-digest", "C05-profile-two-step", "C10-forged"):
        case = by_id(cid)
        s = run_episode(RunConfig(scenario=case.scenario, condition="hierarchical",
                                  output_dir=out, case_id=cid, escalation_policy="oracle"),
                        ScriptedProposer(cid, case.steps))
        assert s["metrics"]["concurrency_rejected"] == 0
        assert s["evidence"]["valid"] is True


def test_guard_is_documented_as_a_restriction_not_a_repair():
    # Guard against a future doc that overclaims concurrency safety.
    doc = SessionExecutionGuard.__doc__ or ""
    assert "NOT a repair" in doc
    assert "concurrency" in doc.lower()
