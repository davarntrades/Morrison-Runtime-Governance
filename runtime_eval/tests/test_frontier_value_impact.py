"""Illustrative value projection stays downstream of governance evidence."""

from __future__ import annotations

from copy import deepcopy

from runtime_eval.frontier.value_impact import calculate_session_value_impact


def _step(number, tool, args, verdict, executed, operator_decision=None):
    step = {
        "step": number,
        "normalized_call": {"tool": tool, "args": args},
        "morrison_decision": {
            "verdict": verdict,
            "rule": "payment.move_funds" if tool == "transfer_funds" else None,
            "layer": "capability_policy",
            "metadata": {"capabilities": (
                ["payment.move_funds"] if tool == "transfer_funds" else [])},
        },
        "execution_occurred": executed,
    }
    if operator_decision is not None:
        step["operator_decision"] = operator_decision
    return step


def test_guarded_pilot_derives_direct_prevented_exposure_from_blocked_action():
    impact = calculate_session_value_impact([
        _step(1, "transfer_funds", {"amount": 100000}, "BLOCK", False),
    ], "guarded_pilot")
    assert impact["direct_simulated_exposure_identified"] == 100000
    assert impact["direct_simulated_exposure_prevented"] == 100000
    assert impact["estimated_enterprise_impact"]["min"] == 250000
    assert impact["estimated_enterprise_impact"]["max"] == 1000000


def test_shadow_identifies_exposure_but_never_calls_it_prevented():
    impact = calculate_session_value_impact([
        _step(1, "transfer", {"amount": 100000}, "BLOCK", True),
    ], "shadow")
    assert impact["direct_simulated_exposure_identified"] == 100000
    assert impact["direct_simulated_exposure_prevented"] is None
    assert impact["would_guarded_pilot_intervene"] is True


def test_permit_and_block_preserve_legitimate_workflow_capacity():
    impact = calculate_session_value_impact([
        _step(1, "read_customer_record", {"customer_id": "C-001"},
              "BLOCK", False),
        _step(2, "prepare_summary", {"subject": "C-001"}, "PERMIT", True),
        _step(3, "read_account", {}, "PERMIT", True),
        _step(4, "transfer_funds", {"amount": 100000}, "BLOCK", False),
    ], "guarded_pilot")
    continuity = impact["workflow_continuity"]
    assert continuity == {
        "preserved": True, "permitted_actions": 2,
        "intercepted_actions": 2, "continued_after_intervention": True,
    }


def test_non_monetary_action_does_not_fabricate_direct_exposure():
    impact = calculate_session_value_impact([
        _step(1, "read_customer_record", {"customer_id": "C-999"},
              "BLOCK", False),
    ], "guarded_pilot")
    assert impact["direct_simulated_exposure_identified"] is None
    assert impact["direct_simulated_exposure_prevented"] is None


def test_estimates_are_explicitly_illustrative():
    impact = calculate_session_value_impact([
        _step(1, "transfer_funds", {"amount": 1000}, "BLOCK", False),
    ], "guarded_pilot")
    assert impact["measurement_type"] == "illustrative"
    assert impact["estimated_enterprise_impact"]["basis"] == (
        "illustrative_impact_profile")
    assert impact["disclaimer"] == (
        "Illustrative estimate — not guaranteed savings.")


def test_runtime_unauthorized_execution_count_remains_authoritative():
    impact = calculate_session_value_impact([], "guarded_pilot",
                                            unauthorized_executions=7)
    assert impact["measured_facts"]["unauthorized_executions"] == 7


def test_value_projection_cannot_mutate_governance_record_or_execute():
    steps = [_step(1, "transfer_funds", {"amount": 100000}, "BLOCK", False)]
    before = deepcopy(steps)
    impact = calculate_session_value_impact(steps, "guarded_pilot")
    assert steps == before
    assert steps[0]["morrison_decision"]["verdict"] == "BLOCK"
    assert steps[0]["execution_occurred"] is False
    assert set(impact)  # the function only returned an explanation


def test_executed_monetary_action_is_never_described_as_prevented_value():
    impact = calculate_session_value_impact([
        _step(1, "transfer_funds", {"amount": 100000}, "BLOCK", True),
    ], "guarded_pilot", unauthorized_executions=1)
    assert impact["direct_simulated_exposure_identified"] == 100000
    assert impact["direct_simulated_exposure_prevented"] is None
    assert impact["estimated_enterprise_impact"] is None
    assert impact["measured_facts"]["unauthorized_executions"] == 1


def test_pending_escalation_is_identified_but_not_called_prevented():
    held = calculate_session_value_impact([
        _step(1, "transfer_funds", {"amount": 100000}, "ESCALATE", False),
    ], "guarded_pilot")
    denied = calculate_session_value_impact([
        _step(1, "transfer_funds", {"amount": 100000}, "ESCALATE", False,
              {"decision": "deny"}),
    ], "guarded_pilot")
    assert held["direct_simulated_exposure_identified"] == 100000
    assert held["direct_simulated_exposure_prevented"] is None
    assert denied["direct_simulated_exposure_prevented"] == 100000


def test_invalid_or_prose_amount_is_not_treated_as_measured_money():
    for amount in ("100000", "£100,000", -1, 0, True, float("inf")):
        impact = calculate_session_value_impact([
            _step(1, "transfer_funds", {"amount": amount}, "BLOCK", False),
        ], "guarded_pilot")
        assert impact["direct_simulated_exposure_identified"] is None
