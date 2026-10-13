"""Loopback OpenAI-compatible frontier planner (proposal generation only).

This transport exists for locally served open-weight models such as MLX. It
never executes tools. Model proposals are normalized into the same canonical
``{"tool", "args"}`` shape consumed by the existing Morrison experiment.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
from urllib.parse import urlparse

from runtime_eval.frontier.base import OneShotFrontierPlanner, ProviderObservation
from runtime_eval.frontier.scenarios import Scenario
from runtime_eval.frontier.tool_schema import chat_completion_tools
from runtime_eval.planners.base import PlannerInfo
from runtime_eval.planners.hf_planner import parse_tool_calls


DEFAULT_LOCAL_OPENAI_BASE_URL = "http://127.0.0.1:8000/v1"


def validate_loopback_base_url(value: str) -> str:
    """Return a normalized loopback-only HTTP(S) OpenAI-compatible base URL."""
    raw = (value or "").strip().rstrip("/")
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("LOCAL_OPENAI_BASE_URL must be an http(s) URL")
    host = parsed.hostname.lower()
    if host == "localhost":
        return raw
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("LOCAL_OPENAI_BASE_URL must resolve to loopback by literal host") from exc
    if not address.is_loopback:
        raise ValueError("LOCAL_OPENAI_BASE_URL must use a loopback address")
    return raw


class LocalOpenAICompatibleFrontierPlanner(OneShotFrontierPlanner):
    """Proposal-only adapter for a loopback OpenAI-compatible model server."""

    def __init__(self, scenario: Scenario, model: str, client=None,
                 base_url: str = DEFAULT_LOCAL_OPENAI_BASE_URL,
                 temperature: float = 0.0, timeout_s: float = 60.0):
        super().__init__()
        self.scenario = scenario
        self.client = client
        self.base_url = validate_loopback_base_url(base_url)
        self.temperature = temperature
        self.timeout_s = timeout_s
        self.info = PlannerInfo(
            name="frontier.local_openai", model_id=model,
            family="local-openai", deterministic=(temperature == 0.0),
            temperature=temperature,
        )

    @staticmethod
    def _value(obj, name: str, default=None):
        if isinstance(obj, dict):
            return obj.get(name, default)
        return getattr(obj, name, default)

    def _invoke(self) -> ProviderObservation:
        if self.client is None:
            from openai import OpenAI  # optional dependency already used by frontier
            self.client = OpenAI(
                base_url=self.base_url,
                api_key=os.getenv("LOCAL_OPENAI_API_KEY", "local-frontier-lab"),
                timeout=self.timeout_s,
            )

        started = time.perf_counter()
        try:
            response = self.client.chat.completions.create(
                model=self.info.model_id,
                messages=[{"role": "user", "content": self.scenario.prompt()}],
                tools=chat_completion_tools(),
                tool_choice="auto",
                temperature=self.temperature,
                max_tokens=1024,
            )
        except Exception as exc:  # provider failures are evidence, not bypasses
            return ProviderObservation(
                latency_ms=(time.perf_counter() - started) * 1000.0,
                error=f"{type(exc).__name__}: {exc}")

        choices = self._value(response, "choices", []) or []
        message = self._value(choices[0], "message", None) if choices else None
        text = str(self._value(message, "content", "") or "")
        normalized, native, malformed = [], [], False

        for item in self._value(message, "tool_calls", []) or []:
            function = self._value(item, "function", None)
            name = self._value(function, "name", "unknown")
            raw_args = self._value(function, "arguments", "{}")
            native.append({"type": "function", "name": str(name),
                           "arguments": raw_args})
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                if not isinstance(args, dict):
                    raise TypeError("function arguments are not an object")
                normalized.append({"tool": str(name), "args": dict(args)})
            except (json.JSONDecodeError, TypeError, ValueError):
                malformed = True

        # Some local servers emit canonical JSON in text rather than native calls.
        if not normalized and not malformed and text:
            normalized = parse_tool_calls(text)
            if normalized:
                native = [{"type": "structured_text", "content": text}]

        return ProviderObservation(
            tool_calls=normalized, native_tool_calls=native, text=text,
            malformed=malformed,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
