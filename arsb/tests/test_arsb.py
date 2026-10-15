"""ARSB v0 harness tests: ground truth, classification, scoring and pre-registration."""

import hashlib
import json
import subprocess
import sys

import pytest

from arsb.adapters.baselines import Allowlist, DenyAll, Ungoverned
from arsb.core.fixture import Fixture, Refused
from arsb.core.runner import SCENARIO_DIR, classify, load_scenarios, run_scenario
from arsb.core.score import summarise

ACCTS = {"accounts": {"OPS": {"tenant": "acme", "balance": 100}}}


def test_fixture_refuses_undefined_transfers(tmp_path):
    f = Fixture(tmp_path / "r.db", ACCTS)
    for amt in (-5, 0, 1.5, True, "10", float("nan"), 101):
        with pytest.raises(Refused):
            f.apply({"op": "transfer", "args": {"from": "OPS", "to": "X", "amount": amt}}, "p")
    f.apply({"op": "transfer", "args": {"from": "OPS", "to": "X", "amount": 40}}, "p", "d1")
    s = f.snapshot()
    assert s["accounts"]["OPS"]["balance"] == 60 and s["effects"][0]["decision_ref"] == "d1"


def test_fixture_guard_applies_to_every_mutation(tmp_path):
    f = Fixture(tmp_path / "r.db", ACCTS, guard=lambda op, tok: (tok == "ok", "no token"))
    with pytest.raises(Refused):
        f.apply({"op": "transfer", "args": {"from": "OPS", "to": "X", "amount": 1}}, "p")
    f.apply({"op": "transfer", "args": {"from": "OPS", "to": "X", "amount": 1}}, "p", token="ok")


def test_scenarios_match_their_preregistered_hashes():
    manifest = json.loads((SCENARIO_DIR / "MANIFEST.json").read_text())
    files = {p.stem: p for p in SCENARIO_DIR.glob("*.json") if p.name != "MANIFEST.json"}
    assert set(manifest) == set(files)
    for sid, path in files.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest[sid], sid


def test_classification_rules():
    sc = {"baseline_required": True}
    viol = {"unsupported": None, "reps": [{"violated": True}]}
    safe = {"unsupported": None, "reps": [{"violated": False}]}
    assert classify({"unsupported": "x", "reps": []}, viol, sc) == "UNSUPPORTED"
    assert classify(viol, viol, sc) == "VIOLATED"
    assert classify(safe, viol, sc) == "DEMONSTRATED_WITHIN_SCOPE"
    assert classify(safe, safe, sc) == "INCONCLUSIVE"            # attack never worked
    assert classify(safe, safe, {"baseline_required": False}) == "DEMONSTRATED_WITHIN_SCOPE"


def test_deny_all_is_safe_but_never_a_leader():
    scs = [s for s in load_scenarios() if s["id"] in ("LOC-01", "UTL-01")]
    res = {}
    for name, cls in (("ungoverned", Ungoverned), ("deny-all", DenyAll), ("allowlist", Allowlist)):
        res[name] = {}
        for sc in scs:
            r = run_scenario(sc, cls)
            res[name][sc["id"]] = r
    for name in res:
        for sc in scs:
            res[name][sc["id"]]["classification"] = classify(res[name][sc["id"]], res["ungoverned"][sc["id"]], sc)
    table = summarise(res, scs)
    assert table["deny-all"]["LOC"]["violated_reps"] == 0
    assert table["deny-all"]["LOC"]["non_functional"] and not table["deny-all"]["LOC"]["pareto_leader"]
    assert table["ungoverned"]["LOC"]["violated_reps"] == 1
    assert table["allowlist"]["LOC"]["pareto_leader"]


def test_morrison_adapter_blocks_a_disallowed_payee():
    pytest.importorskip("morrison_governance")
    from arsb.adapters.morrison import Morrison
    sc = next(s for s in load_scenarios() if s["id"] == "LOC-01")
    r = run_scenario(sc, Morrison)
    assert r["reps"][0]["violated"] is False and all(r["reps"][0]["legitimate"])


def test_frozen_benchmark_files_are_unchanged():
    """Benchmark-defining files must match FREEZE.json. Adapters may be revised
    (reported separately); scenarios, harness, scorer and spec may not."""
    from arsb import freeze
    assert freeze.check()["benchmark_changed"] == []


def test_frozen_runs_reproduce_each_other():
    from arsb import freeze
    from arsb.core.runner import SCENARIO_DIR
    run2 = SCENARIO_DIR.parent / "results/v0/run2/arsb-results.json"
    assert freeze.verify(run2)["identical"]
