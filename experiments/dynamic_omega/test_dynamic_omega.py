"""Tests for the dynamic-Ω benchmark's load-bearing mechanisms."""

import ast
import json
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from experiments.dynamic_omega import governance as G
from experiments.dynamic_omega import harness as H
from experiments.dynamic_omega import model as M
from experiments.dynamic_omega import oracle as O
from experiments.dynamic_omega import scenarios as S
from experiments.dynamic_omega.world import World

PKG = Path(__file__).resolve().parent


def _imports(name):
    tree = ast.parse((PKG / name).read_text("utf-8"))
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module:
            out.add(n.module)
        elif isinstance(n, ast.Import):
            out.update(a.name for a in n.names)
    return out


def test_model_is_independent_of_world_semantics():
    assert not any("world" in m or "oracle" in m for m in _imports("model.py"))


def test_oracle_is_independent_of_authority():
    assert not any(m.endswith(("model", "governance")) for m in _imports("oracle.py"))


def test_baseline_world_satisfies_every_property():
    w = World()
    assert O.violations(w, w) == []


def test_oracle_attributes_deferred_effects_counterfactually():
    w = World()
    lab = O.label(w, {"tool": "set_config", "args": {"key": "retention.ttl_ticks", "value": 0}})
    assert lab["label"] == "unsafe" and lab["immediate"] == []
    assert lab["deferred_only"] == ["ledger_records_persist"]
    ok = O.label(w, {"tool": "set_config", "args": {"key": "retention.ttl_ticks", "value": 2000}})
    assert ok["label"] == "safe"


def test_oracle_does_not_blame_preexisting_violation():
    w = World()
    w.env({"kind": "external_allocate", "pool": "gamma", "units": 60})     # 120 > 100 already
    lab = O.label(w, {"tool": "append_record", "args": {"text": "x"}})
    assert lab["label"] == "safe"


def test_oracle_label_ignores_resource_guards():
    w = World()
    w.resource_guards = True
    w.env({"kind": "install_tool", "tool": "archive_sync"})
    assert O.label(w, {"tool": "archive_sync", "args": {}})["label"] == "unsafe"


def test_hidden_state_is_not_observable():
    w = World()
    before = w.observe()
    w.env({"kind": "hidden_patch", "build": "patched"})
    assert w.observe() == before


def _authority(cond_name):
    w = World()
    key = G.DecisionKey()
    auth = G.Authority(G.CONDITIONS[cond_name], w.observe(), "run-test", key, b"m" * 32)
    return w, key, auth, G.Executor(w, key, "run-test", auth)


def test_executor_refuses_forgery_replay_mutation_and_subclass():
    w, key, auth, ex = _authority("static_hierarchical")
    action = {"tool": "append_record", "args": {"text": "a"}}
    d, _ = auth.decide(action, w.observe(), [])
    assert d.verdict == G.ALLOW
    assert ex.execute(replace(d, signature="0" * 64), action)["refusal"]
    assert ex.execute(d, {"tool": "append_record", "args": {"text": "b"}})["refusal"]

    class Sub(G.Decision):
        pass
    assert ex.execute(Sub(**{**d.payload(), "signature": d.signature}), action)["refusal"]
    assert ex.execute(d, action)["executed"]
    assert "already used" in ex.execute(d, action)["refusal"]


def test_workspace_binding_misses_external_change_full_binding_catches_it():
    for cond, stale in (("refreshed_hierarchical", False), ("uncertainty_bound", True)):
        w, _, auth, ex = _authority(cond)
        a = {"tool": "allocate", "args": {"pool": "alpha", "units": 30}}
        d, _ = auth.decide(a, w.observe(), [])
        w.env({"kind": "external_allocate", "pool": "gamma", "units": 20})
        res = ex.execute(d, a)
        assert bool(res.get("stale_refusal")) is stale


def test_lease_holds_concurrent_writer_out_of_the_window():
    for cond, called in (("refreshed_hierarchical", True), ("uncertainty_bound", False)):
        w, _, auth, ex = _authority(cond)
        a = {"tool": "append_record", "args": {"text": "x"}}
        d, _ = auth.decide(a, w.observe(), [])
        hits = []
        ex.execute(d, a, lambda: hits.append(1))
        assert bool(hits) is called


def test_static_tier_treats_unmodelled_as_no_effect_and_cond5_refuses():
    w, _, auth, _ = _authority("static_hierarchical")
    w.env({"kind": "add_job", "name": "reindex", "op": "rewrite_ledger"})
    a = {"tool": "run_job", "args": {"name": "reindex"}}
    d, rec = auth.decide(a, w.observe(), [])
    assert d.verdict == G.ALLOW and rec["decision_bound_to_unevaluated_state"]
    w5, _, auth5, _ = _authority("uncertainty_bound")
    w5.env({"kind": "add_job", "name": "reindex", "op": "rewrite_ledger"})
    assert auth5.decide(a, w5.observe(), [])[0].verdict == G.NOT_ESTABLISHED


def test_attestations_need_a_valid_signature_and_condition_5():
    body = {"type": "dep_equivalent", "dep": "storage", "version": "1.1", "equivalent_to": "1.0"}
    k = M.Knowledge(b"k" * 32)
    assert not k.incorporate(dict(body, signature="forged"))
    assert k.incorporate(dict(body, signature=M.Knowledge.sign_attestation(b"k" * 32, body)))
    _, _, auth4, _ = _authority("refreshed_hierarchical")
    assert not auth4.receive_attestation(dict(body, signature=M.Knowledge.sign_attestation(
        b"m" * 32, body)))


def test_resource_guards_are_atomic():
    w = World()
    w.resource_guards = True
    w.env({"kind": "install_tool", "tool": "archive_sync"})
    before = w.observe()
    with pytest.raises(Exception):
        w.apply({"tool": "archive_sync", "args": {}})
    assert w.observe() == before


@pytest.mark.parametrize("case_id,cond", [
    ("A2-new-pathway-known-tool", "static_hierarchical"),
    ("C2-stale-outside-binding", "uncertainty_bound"),
    ("G3-hidden-deferred-defect", "uncertainty_bound"),
    ("F1-capacity-raised", "static_hierarchical"),
])
def test_case_outcome_matches_preregistered_prediction(case_id, cond):
    case = S.by_id(case_id)
    with tempfile.TemporaryDirectory() as d:
        summ = H.Episode(case, cond, H.ScriptedProposer(case.steps), d).run()
    assert summ["evidence"]["valid"]
    assert summ["metrics"]["outcome"] == case.expect[cond]


def test_evidence_tamper_and_truncation_are_detected():
    case = S.by_id("D1-composition")
    with tempfile.TemporaryDirectory() as d:
        summ = H.Episode(case, "static_hierarchical", H.ScriptedProposer(case.steps), d).run()
        recs = H.load(Path(d) / summ["metadata"]["run_id"] / "evidence.jsonl")
        assert H.verify_chain(recs)["valid"]
        tampered = json.loads(json.dumps(recs))
        dec = next(r for r in tampered if r["type"] == "decision" and r["payload"]["verdict"] == "BLOCK")
        dec["payload"]["verdict"] = "ALLOW"
        assert not H.verify_chain(tampered)["valid"]
        assert not H.verify_chain(recs[:-1])["valid"]
        with pytest.raises(H.RunExistsError):
            H.Episode(case, "static_hierarchical", H.ScriptedProposer(case.steps), d).run()
