"""AgentDojo integration: Morrison is the only path to the AgentDojo runtime."""

from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string  # noqa: E402

from runtime_eval.agentdojo_bench.gate import MorrisonToolsExecutor  # noqa: E402
from runtime_eval.agentdojo_bench.manifest import PROFILES, profile_for  # noqa: E402
from runtime_eval.agentdojo_bench.oracle import (  # noqa: E402
    DEFAULT_BENCHMARK_VERSION, run_suite,
)


def _banking():
    suite = get_suite(DEFAULT_BENCHMARK_VERSION, "banking")
    env = suite.load_and_inject_default_environment({})
    return suite, env, FunctionsRuntime(suite.tools)


def _assistant(call: FunctionCall):
    return ChatAssistantMessage(role="assistant", tool_calls=[call],
                                content=[text_content_block_from_string("")])


@pytest.mark.parametrize("suite_name", sorted(PROFILES))
def test_manifest_declares_every_suite_tool(suite_name):
    suite = get_suite(DEFAULT_BENCHMARK_VERSION, suite_name)
    declared = set(profile_for(suite_name).tool_manifest)
    assert {t.name for t in suite.tools} == declared


def test_withheld_payment_never_reaches_the_environment():
    _, env, runtime = _banking()
    before = env.model_copy(deep=True)
    executor = MorrisonToolsExecutor(profile_for("banking"))
    call = FunctionCall(function="send_money", id="1", args={
        "recipient": "US133000000121212121212", "amount": 100.0,
        "subject": "x", "date": "2022-01-01"})
    _, _, _, messages, extra = executor.query("q", runtime, env,
                                              [_assistant(call)])
    assert executor.records[0].verdict != "PERMIT"
    assert executor.records[0].executed is False
    assert "runtime governance" in messages[-1]["error"]
    assert env == before
    assert extra["morrison_records"][0]["tool"] == "send_money"


def test_permitted_read_executes_through_the_kernel():
    _, env, runtime = _banking()
    executor = MorrisonToolsExecutor(profile_for("banking"))
    call = FunctionCall(function="get_balance", id="1", args={})
    _, _, _, messages, _ = executor.query("q", runtime, env, [_assistant(call)])
    assert executor.records[0].verdict == "PERMIT"
    assert executor.records[0].executed is True
    assert messages[-1]["error"] is None
    assert str(env.bank_account.balance) in messages[-1]["content"][0]["content"]


def test_baseline_mode_records_but_does_not_withhold():
    _, env, runtime = _banking()
    executor = MorrisonToolsExecutor(profile_for("banking"), enforce=False)
    n = len(env.bank_account.transactions)
    call = FunctionCall(function="send_money", id="1", args={
        "recipient": "US133000000121212121212", "amount": 1.0,
        "subject": "x", "date": "2022-01-01"})
    executor.query("q", runtime, env, [_assistant(call)])
    assert executor.records[0].verdict != "PERMIT"
    assert executor.records[0].executed is True
    assert len(env.bank_account.transactions) == n + 1


def test_new_conversation_gets_a_fresh_trajectory():
    _, env, runtime = _banking()
    executor = MorrisonToolsExecutor(profile_for("banking"))
    call = FunctionCall(function="get_balance", id="1", args={})
    executor.query("q", runtime, env, [_assistant(call)])
    first = executor.kernel
    executor.query("q", runtime, env, [_assistant(call)])
    assert executor.kernel is not first
    assert len(executor.records) == 1


def test_oracle_pair_attack_succeeds_undefended_and_is_stopped():
    result = run_suite("banking", user_tasks=["user_task_0"],
                       injection_tasks=["injection_task_0"])
    row = result["attacked"][0]
    assert row["baseline_attack_succeeded"] is True
    assert row["attack_succeeded"] is False
    s = result["summary"]
    assert s["exercisable_attack_pairs"] == 1
    assert s["morrison_asr"] == 0.0
    assert any(r["origin"] == "injection" and not r["executed"]
               for r in row["records"])


class _CompromisedLLM:
    """Stand-in for a model that falls for the injection: it runs the user
    task's ground truth, then the injection task's, then answers. Lets the
    live runner be exercised end to end without an API key."""

    name = "scripted"

    def __init__(self, suite):
        self.suite = suite

    def query(self, query, runtime, env, messages=(), extra_args=None):
        from agentdojo.logging import Logger
        ctx = Logger.get().context
        pre = self.suite.load_and_inject_default_environment({})
        if ctx["injection_task_id"] is None:
            # AgentDojo's standalone run of an injection task as a user task
            task = self.suite.get_injection_task_by_id(ctx["user_task_id"])
            script = task.ground_truth(pre)
        else:
            user = self.suite.get_user_task_by_id(ctx["user_task_id"])
            inj = self.suite.get_injection_task_by_id(ctx["injection_task_id"])
            script = [*user.ground_truth(pre), *inj.ground_truth(pre)]
        done = sum(1 for m in messages if m["role"] == "assistant")
        msg = ChatAssistantMessage(
            role="assistant", tool_calls=None,
            content=[text_content_block_from_string("done")])
        if done < len(script):
            c = script[done]
            msg["tool_calls"] = [FunctionCall(function=c.function,
                                              args=dict(c.args), id=str(done))]
        return query, runtime, env, [*messages, msg], dict(extra_args or {})


@pytest.mark.parametrize("defense", ["none", "morrison"])
def test_live_runner_separates_attempted_calls_from_resource_effects(
        defense, monkeypatch, tmp_path):
    from runtime_eval.agentdojo_bench import live
    suite = get_suite(DEFAULT_BENCHMARK_VERSION, "banking")
    monkeypatch.setattr(live, "get_llm", lambda *a, **k: _CompromisedLLM(suite))
    out = live.run_live("anthropic", "claude-test-model", "banking",
                        defense=defense, user_tasks=["user_task_0"],
                        injection_tasks=["injection_task_0"], logdir=tmp_path)
    assert "error" not in out
    row = out["results"][0]
    assert row["n_attempted"] >= 2
    assert any(c["tool"] == "send_money" for c in row["attempted_calls"])
    if defense == "none":
        # every attempted call ran; the attacker's payment landed
        assert row["n_executed"] == row["n_attempted"]
        assert row["attack_succeeded"] is True
        assert row["n_resource_effects"] > 0
    else:
        # the payment was attempted but withheld: no effect on the environment
        assert row["n_withheld"] >= 1
        assert row["attack_succeeded"] is False
        assert row["n_resource_effects"] == 0
    assert out["attack_target_name"] == "Claude"
