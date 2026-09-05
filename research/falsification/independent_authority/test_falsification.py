"""Regression tests pinning every counterexample found in the study.

These are FALSIFICATION tests. Each one asserts that a counterexample still
reproduces. If a future change makes one of these pass "safely", the claim
boundary has moved and the study must be re-run -- these tests are not here to
be made green by patching the model.
"""

from __future__ import annotations

from morrison_governance.kernel.evidence import EvidenceChain, EvidenceRecord

from .h1_adversarial import MediatedExecutor, Step, _p, _set, run as h1_run
from .h1_baseline import run_baseline
from .h2_adversarial import (
    EXECUTE_THEN_RECORD, RECORD_THEN_EXECUTE, TWO_PHASE_INTENT_OUTCOME,
    run_condition,
)
from .h2_evidence import enumerate_all, evaluate, simulate

KEY = b"independent-evidence-authority-study"


# ── H1 baseline ───────────────────────────────────────────────────────────

def test_control_reaches_omega_governed_does_not():
    r = run_baseline()
    assert r["control"]["reachable_omega_states"] > 0
    assert r["control"]["complete_enumeration"] is True
    assert r["governed_oracle"]["reachable_omega_states"] == 0
    assert r["governed_oracle"]["complete_enumeration"] is True
    assert r["admissible_capability_preserved"]["all_admissible_preserved"] is True


# ── H1 minimal counterexamples ────────────────────────────────────────────

def test_cx1_bypass_reaches_omega():
    """MINIMAL COUNTEREXAMPLE 1 -- one step, no authorisation call at all."""
    tr = MediatedExecutor().run([
        Step("bypass", _p("send_external_message"),
             _set(secret_externalized=True), bypasses_authority=True)])
    assert tr.reached_omega
    assert "W1_SECRET_EXTERNALIZED" in tr.omega_invariants


def test_cx2_effect_divergence_reaches_omega():
    """MINIMAL COUNTEREXAMPLE 2 -- authority permits an admissible DECLARED
    successor; the committed effect is prohibited."""
    tr = MediatedExecutor().run([
        Step("benign", _p("write_file", path="/tmp/ok"),
             declared_effect=_set(files_modified=frozenset({"/tmp/ok"})),
             actual_effect=_set(secret_externalized=True))])
    assert tr.reached_omega
    assert tr.blocked == []          # authority never saw anything to block


def test_cx3_toctou_reaches_omega():
    """MINIMAL COUNTEREXAMPLE 3 -- authorisation sound when made, invalidated
    before commit. Authority was neither bypassed nor lied to."""
    tr = MediatedExecutor().run([
        Step("toctou", _p("request_privilege"),
             declared_effect=_set(privilege_level="admin", privilege_authorized=True),
             actual_effect=_set(privilege_level="admin"),
             interference=_set(privilege_authorized=False))])
    assert tr.reached_omega
    assert "W2_UNAUTHORISED_PRIVILEGE" in tr.omega_invariants


def test_h1_falsifier_categories_are_distinct():
    r = h1_run()
    assert r["falsifying"] == 8
    assert set(r["by_category"]) == {
        "1_PRINCIPLE", "2_AOE_SPEC", "3_ENV_MODEL", "4_SEMANTICS", "5_BYPASS"}


def test_undetected_harm_is_not_reported_as_safe():
    """A06/A07: real consequence occurred, Omega registered nothing."""
    r = h1_run()
    silent = [a for a in r["attacks"] if a["undetected_harm"]]
    assert {a["id"] for a in silent} == {"A06", "A07"}
    for a in silent:
        assert a["omega_reached_under_authority"] is False
        assert a["real_consequence_occurred"] is True
        assert a["falsifies_h1"] is True


# ── H2 ────────────────────────────────────────────────────────────────────

def test_vendor_only_attacks_do_not_falsify_h2():
    r = evaluate(simulate(frozenset(
        {"vendor_withhold", "vendor_delete", "vendor_modify"})))
    assert r["strong_unhideability"] is True
    assert r["evidence_completeness"] == 1.0


def test_64_combination_enumeration_is_exhaustive():
    r = enumerate_all()
    assert r["total_combinations"] == 64
    assert r["property_holds"] == 8
    assert r["property_fails"] == 56


def test_three_single_faults_each_break_h2_alone():
    r = enumerate_all()
    assert set(r["single_faults_that_break_alone"]) == {
        "recorder_crash_before_commit",
        "execution_bypasses_recorder",
        "evidence_writer_compromised"}


def test_cx4_integrity_valid_while_history_incomplete():
    """MINIMAL COUNTEREXAMPLE 4 -- THE central H2 result.

    Reality: x0 -> x1 -> x2 -> OMEGA
    L_I    : x0 -> x1 -> x2
    with valid hashes, valid signatures, intact chain, no detectable tampering.
    """
    w = simulate(frozenset({"recorder_crash_before_commit"}))
    r = evaluate(w)
    assert r["integrity_valid"] is True            # cryptographically perfect
    assert r["completeness_holds"] is False        # yet incomplete
    assert r["missing_events"] == ["x2--export-->OMEGA"]
    assert r["undetected_reality_divergence"] is True
    ok, problems = w.independent.verify()
    assert ok and problems == []                   # Morrison's own verifier: clean


def test_morrison_chain_cannot_express_completeness():
    """The CURRENT IMPLEMENTATION has no predicate over absent records."""
    chain = EvidenceChain(key=KEY)
    chain.append(EvidenceRecord(
        seq=0, timestamp=0.0, actor="a", tenant="t", action_hash="only-event",
        proposed={"tool": "x", "args": {}}, decision="PERMIT", executed=True))
    ok, problems = chain.verify()
    assert ok is True and problems == []
    # An empty chain is equally "valid" -- absence is unrepresentable.
    assert EvidenceChain(key=KEY).verify() == (True, [])


# ── H2' ordering / atomicity ──────────────────────────────────────────────

def test_cx5_record_then_execute_trades_completeness_for_soundness():
    """MINIMAL COUNTEREXAMPLE 5 -- H2' does not eliminate divergence.

    Gating execution on evidence removes completeness violations and
    introduces soundness violations: evidence asserts an execution that never
    happened.
    """
    r = run_condition(RECORD_THEN_EXECUTE, "execution_fails_after_evidence")
    assert r.completeness_violation is False
    assert r.soundness_violation is True
    assert r.integrity_valid is True
    assert r.verifier_can_establish_execution is True
    assert r.executed_externally is False


def test_execute_then_record_leaves_verifier_blind():
    r = run_condition(EXECUTE_THEN_RECORD, "recorder_crash_after_execution")
    assert r.completeness_violation is True
    assert r.verifier_knows_something_attempted is False


def test_two_phase_converts_blindness_into_known_uncertainty():
    """The surviving weaker property: no SILENT omission."""
    r = run_condition(TWO_PHASE_INTENT_OUTCOME, "recorder_crash_after_execution")
    assert r.completeness_violation is True          # still cannot confirm
    assert r.verifier_knows_something_attempted is True   # but is not blind
    assert r.soundness_violation is False


# ── 2x2 ───────────────────────────────────────────────────────────────────

def test_cell_d_is_not_strictly_safe():
    from .matrix2x2 import run as matrix_run
    r = matrix_run()
    d = r["cells"]["D_exec_independent_evidence"]
    assert r["d_is_strictly_safe"] is False
    assert d["prohibited_reachability"] > 0
    assert d["undetected_reality_divergence"] is True


def test_bypass_is_common_mode_across_both_authorities():
    """One attack defeats execution authority AND evidence authority."""
    from .matrix2x2 import run as matrix_run
    d = matrix_run()["cells"]["D_exec_independent_evidence"]
    assert "boundary_bypass" in d["omega_reached"]
    assert "boundary_bypass" in d["missing_events"]
