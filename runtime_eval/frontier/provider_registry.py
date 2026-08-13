"""Credential-aware frontier planner registry."""

from __future__ import annotations

import os

from runtime_eval.frontier.anthropic_planner import AnthropicFrontierPlanner
from runtime_eval.frontier.deterministic_planner import DeterministicFrontierPlanner
from runtime_eval.frontier.huggingface_planner import HuggingFaceFrontierPlanner
from runtime_eval.frontier.openai_planner import OpenAIFrontierPlanner
from runtime_eval.frontier.scenarios import Scenario


PROVIDER_ENV = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY",
                "huggingface": "HF_TOKEN"}
DEFAULT_MODELS = {"openai": "gpt-5.6", "anthropic": "claude-opus-5",
                  "deterministic": "deterministic"}


def configured_models(provider: str) -> list[str]:
    """Return the server-side model allowlist for a provider."""
    if provider == "huggingface":
        return [item.strip() for item in os.getenv("HF_MODELS", "").split(",")
                if item.strip()]
    configured = os.getenv(f"{provider.upper()}_MODEL", "").strip()
    return [configured] if configured else []


def credential_available(provider: str) -> bool:
    name = PROVIDER_ENV.get(provider)
    return True if name is None else bool(os.environ.get(name))


def make_planner(provider: str, scenario: Scenario, model: str = "", client=None):
    if provider == "huggingface":
        allowed = configured_models(provider)
        selected = model or (allowed[0] if allowed else "")
        if not selected or selected not in allowed:
            raise ValueError("Hugging Face model is not in HF_MODELS allowlist")
        temperature = float(os.getenv("HF_TEMPERATURE", "0"))
        timeout_s = float(os.getenv("FRONTIER_PROVIDER_TIMEOUT_S", "60"))
        return HuggingFaceFrontierPlanner(
            scenario, selected, client=client, temperature=temperature,
            timeout_s=timeout_s)
    selected = model or DEFAULT_MODELS[provider]
    if provider == "deterministic":
        return DeterministicFrontierPlanner(scenario)
    if provider == "openai":
        return OpenAIFrontierPlanner(scenario, selected, client=client)
    if provider == "anthropic":
        return AnthropicFrontierPlanner(scenario, selected, client=client)
    raise KeyError(f"unknown provider {provider!r}")
