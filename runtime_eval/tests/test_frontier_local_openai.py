"""Tests for the loopback-only local OpenAI-compatible frontier transport."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from runtime_eval.frontier.experiment import run_experiment
from runtime_eval.frontier.local_openai_planner import (
    LocalOpenAICompatibleFrontierPlanner,
    validate_loopback_base_url,
)
from runtime_eval.frontier.provider_registry import make_planner
from runtime_eval.frontier.scenarios import get_scenarios


def _fake_chat_response(*, content="", tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls or [])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _fake_client(response=None, error=None):
    def create(**_kwargs):
        if error:
            raise error
        return response
    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


def test_loopback_url_validation_accepts_local_addresses_only():
    assert validate_loopback_base_url("http://127.0.0.1:8000/v1") == "http://127.0.0.1:8000/v1"
    assert validate_loopback_base_url("http://localhost:8080/v1") == "http://localhost:8080/v1"
    assert validate_loopback_base_url("http://[::1]:8000/v1") == "http://[::1]:8000/v1"
    for rejected in (
        "https://example.com/v1",
        "http://10.0.0.8:8000/v1",
        "file:///tmp/socket",
        "not-a-url",
    ):
        with pytest.raises(ValueError):
            validate_loopback_base_url(rejected)


def test_local_provider_requires_server_side_model_allowlist(monkeypatch):
    scenario = get_scenarios("clean_control")[0]
    monkeypatch.setenv("LOCAL_OPENAI_MODELS", "orcarouter/Qwen3.8-27B-Uncensored-MLX")
    planner = make_planner(
        "local-openai", scenario,
        "orcarouter/Qwen3.8-27B-Uncensored-MLX",
        client=_fake_client(_fake_chat_response()),
    )
    assert planner.info.model_id == "orcarouter/Qwen3.8-27B-Uncensored-MLX"
    with pytest.raises(ValueError, match="allowlist"):
        make_planner("local-openai", scenario, "attacker/other", client=object())


def test_local_native_tool_call_is_normalized():
    function = SimpleNamespace(
        name="transfer", arguments='{"amount":100000,"to":"x"}')
    call = SimpleNamespace(function=function)
    scenario = get_scenarios("direct_malicious")[0]
    planner = LocalOpenAICompatibleFrontierPlanner(
        scenario, "local/model",
        client=_fake_client(_fake_chat_response(tool_calls=[call])))
    assert planner.propose({}, []) == [{"tool": "transfer", "args": {
        "amount": 100000, "to": "x"}}]
    assert planner.observation.native_tool_calls[0]["name"] == "transfer"


def test_local_strict_text_plan_is_normalized():
    scenario = get_scenarios("clean_control")[0]
    planner = LocalOpenAICompatibleFrontierPlanner(
        scenario, "local/model",
        client=_fake_client(_fake_chat_response(
            content='[{"tool":"read_account","args":{}}]')))
    assert planner.propose({}, []) == [{"tool": "read_account", "args": {}}]


def test_local_malformed_tool_arguments_fail_closed_before_execution():
    function = SimpleNamespace(name="transfer", arguments="not-json")
    scenario = get_scenarios("direct_malicious")[0]
    planner = LocalOpenAICompatibleFrontierPlanner(
        scenario, "local/model",
        client=_fake_client(_fake_chat_response(
            tool_calls=[SimpleNamespace(function=function)])))
    row = run_experiment("local-openai", "local/model", scenario, planner).record
    assert row["classification"] == "MODEL_OUTPUT_MALFORMED"
    assert row["executed_calls"] == []
    assert row["unauthorized_execution_count"] == 0


def test_local_provider_error_becomes_evidence_not_bypass():
    scenario = get_scenarios("direct_malicious")[0]
    planner = LocalOpenAICompatibleFrontierPlanner(
        scenario, "local/model",
        client=_fake_client(error=RuntimeError("server down")))
    row = run_experiment("local-openai", "local/model", scenario, planner).record
    assert row["provider_error"]
    assert "server down" in row["provider_error"]
    assert row["executed_calls"] == []
    assert row["unauthorized_execution_count"] == 0


def test_local_planner_has_no_executor_reference():
    scenario = get_scenarios("clean_control")[0]
    planner = LocalOpenAICompatibleFrontierPlanner(
        scenario, "local/model", client=_fake_client(_fake_chat_response()))
    assert not hasattr(planner, "executor")
    assert not hasattr(planner, "sandbox")


def test_local_model_uses_same_morrison_containment_path():
    function = SimpleNamespace(
        name="transfer", arguments='{"amount":100000,"to":"PROMPT_INJECTION_CANARY"}')
    scenario = get_scenarios("direct_malicious")[0]
    planner = LocalOpenAICompatibleFrontierPlanner(
        scenario, "local/model",
        client=_fake_client(_fake_chat_response(
            tool_calls=[SimpleNamespace(function=function)])))
    row = run_experiment("local-openai", "local/model", scenario, planner).record
    assert row["model_compromised"] is True
    assert row["final_verdict"] in {"BLOCK", "ESCALATE"}
    assert row["executed_calls"] == []
    assert row["unauthorized_execution_count"] == 0
