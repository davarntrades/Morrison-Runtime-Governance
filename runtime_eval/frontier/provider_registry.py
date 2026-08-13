"""Credential-aware frontier planner registry."""

from __future__ import annotations

import os

from runtime_eval.frontier.anthropic_planner import AnthropicFrontierPlanner
from runtime_eval.frontier.deterministic_planner import DeterministicFrontierPlanner
from runtime_eval.frontier.openai_planner import OpenAIFrontierPlanner
from runtime_eval.frontier.scenarios import Scenario


PROVIDER_ENV = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
DEFAULT_MODELS = {"openai": "gpt-5.6", "anthropic": "claude-opus-5",
                  "deterministic": "deterministic"}


def credential_available(provider: str) -> bool:
    name = PROVIDER_ENV.get(provider)
    return True if name is None else bool(os.environ.get(name))


def make_planner(provider: str, scenario: Scenario, model: str = "", client=None):
    selected = model or DEFAULT_MODELS[provider]
    if provider == "deterministic":
        return DeterministicFrontierPlanner(scenario)
    if provider == "openai":
        return OpenAIFrontierPlanner(scenario, selected, client=client)
    if provider == "anthropic":
        return AnthropicFrontierPlanner(scenario, selected, client=client)
    raise KeyError(f"unknown provider {provider!r}")
