"""The TLC cross-check must fail closed (independent review, finding D).

Before the repair `run_tlc` read `violated = "is violated" in text` and never
looked at the exit code, so a TLC process that errored out before exploring a
single state reported "no violation" — which is exactly the expected answer
for `governed_safety` in the deny mode. A bundle whose governed-safety config
named a non-existent invariant produced exit 151, no state count, and
`agree: True`.

These tests drive `run_tlc` with a fake `java` executable that prints a chosen
TLC transcript and exits with a chosen status, so they run in CI without a JVM.
Each negative case proves a specific failed verification cannot be reported as
successful. When MORRISON_TLC_JAR points at a real tla2tools.jar, the real
checker is also run on a good bundle (positive control) and on a sabotaged
bundle (negative control).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from .comparison import compare_control_and_governed
from .governance import MorrisonKernelAdapter
from .pipeline import enterprise_pipeline
from .state import VerificationState
from .tla_export import (
    _GOALS_TLA, _UNSAFE_TLA, _VARS, classify_tlc_run, run_tlc, write_bundle,
)
from .unsafe import DEFAULT_UNSAFE_INVARIANTS

OK = ("Model checking completed. No error has been found.\n"
      "31 states generated, {n} distinct states found, 0 states left on queue.\n")
VIOLATION = ("Error: Invariant {inv} is violated.\n"
             "Error: The behavior up to this point is:\n"
             "28 states generated, 28 distinct states found, 3 states left on queue.\n")


@pytest.fixture(scope="module")
def bundle(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("tla-deny")
    write_bundle(out, "deny")
    return out


@pytest.fixture
def jar(tmp_path) -> Path:
    path = tmp_path / "tla2tools.jar"
    path.write_bytes(b"not a real jar; the fake java never opens it")
    return path


def _expected(bundle: Path) -> dict:
    return json.loads((bundle / "expected.json").read_text())


def _honest_script(bundle: Path) -> dict[str, tuple[int, str]]:
    """What a correct TLC would print for each config, from expected.json."""
    exp = _expected(bundle)
    out: dict[str, tuple[int, str]] = {
        "control_count": (0, OK.format(n=exp["control_states"])),
        "governed_count": (0, OK.format(n=exp["governed_states"])),
    }

    def inv_run(violated: bool, inv: str):
        return (12, VIOLATION.format(inv=inv)) if violated else (0, OK.format(n=5))
    out["control_safety"] = inv_run(exp["control_unsafe_reachable"], "Safe")
    out["governed_safety"] = inv_run(exp["governed_unsafe_reachable"], "Safe")
    for gid in _GOALS_TLA:
        out[f"governed_goal_{gid}"] = inv_run(exp["governed_goals"][gid], f"NotGoal_{gid}")
        out[f"control_goal_{gid}"] = inv_run(exp["control_goals"][gid], f"NotGoal_{gid}")
    return out


def _fake_java(tmp_path: Path, script: dict[str, tuple[int, str]],
               sleep_s: float = 0.0) -> str:
    """An executable that answers `java ... -config X.cfg ...` from `script`."""
    data = tmp_path / "script.json"
    data.write_text(json.dumps(script))
    exe = tmp_path / "fakejava"
    exe.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys, time\n"
        f"time.sleep({sleep_s!r})\n"
        "cfg = sys.argv[sys.argv.index('-config') + 1][:-4]\n"
        f"script = json.load(open({str(data)!r}))\n"
        "code, text = script.get(cfg, [1, ''])\n"
        "sys.stdout.write(text)\n"
        "sys.exit(code)\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return str(exe)


# ── positive control: an honest transcript agrees ──────────────────────────

def test_honest_transcript_agrees(bundle, jar, tmp_path):
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, _honest_script(bundle)))
    assert res["errors"] == []
    assert res["agree"] is True
    assert all(res["checks"].values())


# ── negative controls: every way TLC can fail must fail the cross-check ────

@pytest.mark.parametrize("code", [1, 10, 11, 13, 14, 75, 150, 151, 255, -9])
def test_nonzero_non_violation_exit_is_an_error(bundle, jar, tmp_path, code):
    """The pre-repair false success: governed_safety errors, prints nothing
    that says "is violated", and was read as "safe" (exit 151 observed)."""
    script = _honest_script(bundle)
    script["governed_safety"] = (code, "Error: TLC threw an unexpected exception.\n")
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, script))
    assert res["agree"] is False
    assert res["checks"]["governed_unsafe_reachable"] is False
    assert res["tlc"]["governed_safety"]["status"] == "error"
    assert res["tlc"]["governed_safety"]["violated"] is None


def test_exit_zero_without_completion_line_is_an_error(bundle, jar, tmp_path):
    script = _honest_script(bundle)
    script["governed_safety"] = (0, "Starting...\n")
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, script))
    assert res["agree"] is False and res["checks"]["governed_unsafe_reachable"] is False


def test_empty_output_is_an_error(bundle, jar, tmp_path):
    script = _honest_script(bundle)
    script["governed_count"] = (0, "")
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, script))
    assert res["agree"] is False and res["checks"]["governed_state_count"] is False


def test_incomplete_exploration_is_an_error(bundle, jar, tmp_path):
    """A progress line with the right count but a non-empty queue is partial."""
    exp = _expected(bundle)
    script = _honest_script(bundle)
    script["governed_count"] = (0, "Model checking completed. No error has been found.\n"
                                   f"40 states generated, {exp['governed_states']} distinct "
                                   "states found, 9 states left on queue.\n")
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, script))
    assert res["agree"] is False
    assert "incomplete" in res["tlc"]["governed_count"]["error"]


def test_malformed_summary_is_an_error(bundle, jar, tmp_path):
    script = _honest_script(bundle)
    script["control_count"] = (0, "Model checking completed. No error has been found.\n"
                                  "lots of distinct states found\n")
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, script))
    assert res["agree"] is False and res["checks"]["control_state_count"] is False


def test_violation_of_the_wrong_invariant_is_an_error(bundle, jar, tmp_path):
    script = _honest_script(bundle)
    script["control_safety"] = (12, VIOLATION.format(inv="SomethingElse"))
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, script))
    assert res["agree"] is False and res["checks"]["control_unsafe_reachable"] is False


def test_exit_zero_that_reports_a_violation_is_an_error(bundle, jar, tmp_path):
    script = _honest_script(bundle)
    script["governed_safety"] = (0, VIOLATION.format(inv="Safe") + OK.format(n=31))
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, script))
    assert res["agree"] is False


def test_count_run_that_reports_a_violation_is_an_error(bundle, jar, tmp_path):
    script = _honest_script(bundle)
    script["control_count"] = (12, VIOLATION.format(inv="Safe"))
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, script))
    assert res["agree"] is False and res["checks"]["control_state_count"] is False


def test_timeout_is_an_error(bundle, jar, tmp_path):
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, _honest_script(bundle), sleep_s=5),
                  timeout_s=0.5)
    assert res["agree"] is False
    assert all(r["status"] == "error" for r in res["tlc"].values())


def test_checker_that_cannot_start_is_an_error(bundle, jar, tmp_path):
    res = run_tlc(bundle, jar, java=str(tmp_path / "no-such-java"))
    assert res["agree"] is False and len(res["errors"]) == len(res["tlc"])


def test_missing_config_is_an_error(bundle, jar, tmp_path):
    copy = tmp_path / "bundle"
    shutil.copytree(bundle, copy)
    (copy / "governed_safety.cfg").unlink()
    res = run_tlc(copy, jar, java=_fake_java(tmp_path, _honest_script(bundle)))
    assert res["agree"] is False
    assert res["tlc"]["governed_safety"]["error"] == "config file missing"


def test_config_without_its_invariant_is_an_error(bundle, jar, tmp_path):
    """A safety config whose INVARIANT line was dropped would check nothing."""
    copy = tmp_path / "bundle"
    shutil.copytree(bundle, copy)
    cfg = copy / "governed_safety.cfg"
    cfg.write_text(cfg.read_text().replace("INVARIANT Safe\n", ""))
    res = run_tlc(copy, jar, java=_fake_java(tmp_path, _honest_script(bundle)))
    assert res["agree"] is False and res["checks"]["governed_unsafe_reachable"] is False


@pytest.mark.parametrize("drop", ["governed_goals", "control_states"])
def test_missing_expected_property_is_refused(bundle, jar, tmp_path, drop):
    copy = tmp_path / "bundle"
    shutil.copytree(bundle, copy)
    exp = _expected(copy)
    if drop == "governed_goals":
        exp[drop] = {}                       # vacuous: no goal would be checked
    else:
        del exp[drop]
    (copy / "expected.json").write_text(json.dumps(exp))
    with pytest.raises(ValueError):
        run_tlc(copy, jar, java=_fake_java(tmp_path, _honest_script(bundle)))


def test_disagreeing_count_still_disagrees(bundle, jar, tmp_path):
    script = _honest_script(bundle)
    script["governed_count"] = (0, OK.format(n=_expected(bundle)["governed_states"] + 1))
    res = run_tlc(bundle, jar, java=_fake_java(tmp_path, script))
    assert res["errors"] == [] and res["agree"] is False


def test_classifier_unit_cases():
    assert classify_tlc_run(None, "", "Safe")["status"] == "error"
    assert classify_tlc_run(0, OK.format(n=3), None) == {
        "status": "complete", "violated": False, "distinct_states": 3, "error": None}
    assert classify_tlc_run(12, VIOLATION.format(inv="Safe"), "Safe")["violated"] is True
    assert classify_tlc_run(12, VIOLATION.format(inv="Safe"), None)["status"] == "error"
    assert classify_tlc_run(151, "x", "Safe")["violated"] is None


# ── Python and TLA+ check the same safety property ─────────────────────────

def _tla_unsafe(state: dict) -> dict[str, bool]:
    """Evaluate each `_UNSAFE_TLA` formula on a verifier state, by hand."""
    v = {var: state[fld] for fld, (var, _) in _VARS.items()}
    return {
        "U1_SECRET_LEFT_TRUST_BOUNDARY": bool(v["secretExternalized"]),
        "U2_UNAUTHORISED_PRIVILEGE_ESCALATION": False,
        "U3_GOVERNANCE_BYPASS": False,
        "U4_UNAUTHORISED_PERSISTENCE": False,
        "U5_MONITORING_DISABLED": not v["monitoringEnabled"],
        "U6_GOVERNANCE_POLICY_MUTATED": bool(v["policyMutated"]),
        "U7_UNAUTHORISED_EXTERNAL_CONSEQUENCE": v["externalSideEffects"] > 0,
    }


def _as_state(raw: dict) -> VerificationState:
    defaults = VerificationState()
    kw = {}
    for name, value in raw.items():
        kw[name] = frozenset(value) if isinstance(getattr(defaults, name), frozenset) else value
    return VerificationState(**kw)


@pytest.mark.parametrize("escalations", [None, lambda p, d: ("deny", "approve")])
def test_python_and_tla_invariants_agree_on_every_reachable_state(escalations):
    """Each TLA+ unsafe formula equals its Python predicate on every state the
    verifier reaches (control and governed), invariant by invariant — not only
    the disjunction. The simplifications in `_UNSAFE_TLA` (U2-U4 FALSE, U5 and
    U7 without their authorisation conjunct) are therefore exact in-model."""
    assert set(_UNSAFE_TLA) == {u.identifier for u in DEFAULT_UNSAFE_INVARIANTS}
    comp = compare_control_and_governed(enterprise_pipeline(), MorrisonKernelAdapter(),
                                        escalation_policy=escalations)
    checked = 0
    for graph in (comp.control.graph, comp.governed.graph):
        for node in graph.nodes.values():
            state = _as_state(node.state)
            tla = _tla_unsafe(node.state)
            for inv in DEFAULT_UNSAFE_INVARIANTS:
                assert inv.evaluate(state) == tla[inv.identifier], (inv.identifier, node.state)
            assert (not node.safe) == any(tla.values())
            checked += 1
    assert checked > 100


# ── real TLC, when available ───────────────────────────────────────────────

TLC_JAR = os.environ.get("MORRISON_TLC_JAR", "")
needs_tlc = pytest.mark.skipif(not (TLC_JAR and Path(TLC_JAR).is_file() and shutil.which("java")),
                               reason="set MORRISON_TLC_JAR to a tla2tools.jar to run real TLC")


@needs_tlc
@pytest.mark.parametrize("mode", ["deny", "deny-and-approve"])
def test_real_tlc_agrees_on_a_good_bundle(tmp_path, mode):
    write_bundle(tmp_path, mode)
    res = run_tlc(tmp_path, Path(TLC_JAR))
    assert res["errors"] == [], res["errors"]
    assert res["agree"] is True


@needs_tlc
def test_real_tlc_error_is_not_success(tmp_path):
    """The exact reproduction from the review: governed_safety names an
    undefined operator, real TLC exits non-zero, and the check must fail."""
    write_bundle(tmp_path, "deny")
    cfg = tmp_path / "governed_safety.cfg"
    cfg.write_text(cfg.read_text().replace("INVARIANT Safe", "INVARIANT NoSuchOperator"))
    res = run_tlc(tmp_path, Path(TLC_JAR))
    assert res["agree"] is False
    assert res["tlc"]["governed_safety"]["status"] == "error"
    assert res["tlc"]["governed_safety"]["exit_code"] not in (0, 12)
