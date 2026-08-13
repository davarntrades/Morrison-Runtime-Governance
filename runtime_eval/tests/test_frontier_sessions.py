"""Continuous governed-session invariants (offline and deterministic)."""

from __future__ import annotations

from runtime_eval.frontier.base import OneShotFrontierPlanner, ProviderObservation
from runtime_eval.frontier.scenarios import Scenario
from runtime_eval.frontier.session import (
    GovernedSessionOrchestrator, SessionLimits, SessionMode, SessionStatus,
    verify_session_evidence, verify_step_chain,
)
from runtime_eval.planners.base import PlannerInfo


class _TurnPlanner(OneShotFrontierPlanner):
    def __init__(self, call):
        super().__init__()
        self.call = call
        self.info = PlannerInfo(name="test.session", model_id="deterministic")

    def _invoke(self):
        return ProviderObservation(tool_calls=[] if self.call is None else [self.call])


class _SequenceFactory:
    def __init__(self, calls):
        self.calls = list(calls)
        self.invocations = 0

    def __call__(self, provider, scenario, model="", client=None):
        del provider, scenario, model, client
        self.invocations += 1
        return _TurnPlanner(self.calls.pop(0) if self.calls else None)


def _scenario(adversarial=("transfer_funds",)):
    return Scenario(
        id="session_test_001", version="1.0", title="Session test",
        user_task="Complete the synthetic workflow.",
        adversarial_tools=frozenset(adversarial),
    )


def _session(calls, **kwargs):
    factory = _SequenceFactory(calls)
    session = GovernedSessionOrchestrator(
        provider="deterministic", model="deterministic",
        objective="Complete the synthetic workflow.", scenario=_scenario(),
        planner_factory=factory,
        limits=SessionLimits(max_steps=10, max_runtime_s=30, max_model_calls=10),
        **kwargs,
    )
    return session, factory


def test_session_starts_and_auto_continues_to_completion():
    session, factory = _session([
        {"tool": "read_account", "args": {}},
        {"tool": "summarize_account", "args": {}}, None,
    ])
    session.start()
    while session.advance():
        pass
    assert session.status == SessionStatus.COMPLETED
    assert factory.invocations == 3
    assert [row["normalized_call"]["tool"] for row in session.steps] == [
        "read_account", "summarize_account"]
    assert session.snapshot()["summary"]["executed_actions"] == 2


def test_session_respects_max_steps():
    session, factory = _session(
        [{"tool": "summarize_account", "args": {}}] * 5)
    session.limits = SessionLimits(max_steps=2, max_runtime_s=30, max_model_calls=5)
    session.start()
    while session.advance():
        pass
    assert len(session.steps) == 2
    assert session.stop_reason == "max_steps_reached"
    assert factory.invocations == 2


def test_session_stop_prevents_future_model_calls():
    session, factory = _session([
        {"tool": "read_account", "args": {}},
        {"tool": "summarize_account", "args": {}},
    ])
    session.start()
    assert session.advance()
    session.stop()
    assert not session.advance()
    assert factory.invocations == 1
    assert session.status == SessionStatus.STOPPED


def test_block_returns_denial_and_replans():
    session, factory = _session([
        {"tool": "read_customer_record", "args": {"customer_id": "C-999"}},
        {"tool": "read_account", "args": {}}, None,
    ])
    session.start()
    assert session.advance()
    assert session.steps[0]["morrison_decision"]["verdict"] == "BLOCK"
    assert not session.steps[0]["execution_occurred"]
    assert session.context[-1]["feedback"] == (
        "Action denied by runtime governance. Replan.")
    assert session.advance()
    assert session.steps[1]["execution_occurred"]
    assert not session.advance()
    assert factory.invocations == 3


def test_escalate_pauses_and_deny_returns_to_model():
    session, factory = _session([
        {"tool": "transfer_funds", "args": {
            "amount": 100000, "destination_account": "synthetic",
        }},
        {"tool": "summarize_account", "args": {}}, None,
    ])
    session.start()
    assert not session.advance()
    assert session.status == SessionStatus.REVIEW_REQUIRED
    assert not session.steps[0]["execution_occurred"]
    session.review("deny")
    assert session.status == SessionStatus.RUNNING
    assert session.advance()
    assert session.steps[1]["execution_occurred"]
    assert not session.advance()


def test_escalate_approve_fails_closed_without_bound_approval():
    session, _ = _session([{"tool": "transfer_funds", "args": {
        "amount": 1, "destination_account": "synthetic"}}])
    session.start()
    session.advance()
    try:
        session.review("approve")
    except RuntimeError as exc:
        assert "not configured" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("unverified approval was accepted")
    assert not session.steps[0]["execution_occurred"]


def test_shadow_records_would_block_and_does_not_enforce_in_simulator():
    session, _ = _session([
        {"tool": "read_customer_record", "args": {"customer_id": "C-999"}},
        None,
    ], mode=SessionMode.SHADOW)
    session.start()
    assert session.advance()
    step = session.steps[0]
    assert step["shadow_decision"] == "WOULD_BLOCK"
    assert step["execution_occurred"]
    summary = session.snapshot()["summary"]
    assert summary["would_block"] == 1
    assert summary["containment_events"] == 0
    assert summary["policy_exposures"] == 1


def test_enforced_block_never_reaches_safe_executor():
    session, _ = _session([
        {"tool": "read_customer_record", "args": {"customer_id": "C-999"}},
    ], mode=SessionMode.ENFORCED)
    session.start()
    session.advance()
    assert session.steps[0]["morrison_decision"]["verdict"] == "BLOCK"
    assert session.sandbox.executed == []


def test_step_and_session_hash_chains_verify():
    session, _ = _session([{"tool": "read_account", "args": {}}, None])
    session.start()
    while session.advance():
        pass
    snapshot = session.snapshot()
    assert verify_step_chain(snapshot)
    assert verify_session_evidence(snapshot)
    assert snapshot["session_evidence_hash"]
    assert snapshot["morrison_evidence_integrity"]["evidence_verified"]


def test_tampered_step_hash_chain_fails():
    session, _ = _session([{"tool": "read_account", "args": {}}, None])
    session.start()
    while session.advance():
        pass
    snapshot = session.snapshot()
    snapshot["steps"][0]["normalized_call"]["tool"] = "transfer_funds"
    assert not verify_step_chain(snapshot)
