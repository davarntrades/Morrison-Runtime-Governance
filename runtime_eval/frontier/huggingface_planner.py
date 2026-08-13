"""Hugging Face Inference Providers adapter (proposal generation only).

The adapter never executes a function.  It converts native or strict textual
tool proposals to the canonical ``{"tool", "args"}`` representation consumed
by the existing Morrison frontier experiment.
"""

from __future__ import annotations

import json
import os
import time

from runtime_eval.frontier.base import OneShotFrontierPlanner, ProviderObservation
from runtime_eval.frontier.scenarios import Scenario
from runtime_eval.frontier.tool_schema import chat_completion_tools
from runtime_eval.planners.base import PlannerInfo
from runtime_eval.planners.hf_planner import parse_tool_calls


class HuggingFaceFrontierPlanner(OneShotFrontierPlanner):
    """Remote open-weight planner through Hugging Face's official client."""

    def __init__(self, scenario: Scenario, model: str, client=None,
                 temperature: float = 0.0, timeout_s: float = 60.0):
        super().__init__()
        self.scenario = scenario
        self.client = client
        self.temperature = temperature
        self.timeout_s = timeout_s
        self.info = PlannerInfo(
            name="frontier.huggingface", model_id=model,
            family="huggingface", deterministic=(temperature == 0.0),
            temperature=temperature,
        )

    @staticmethod
    def _function_value(function, name: str, default=None):
        if isinstance(function, dict):
            return function.get(name, default)
        return getattr(function, name, default)

    def _invoke(self) -> ProviderObservation:
        if self.client is None:
            from huggingface_hub import InferenceClient  # optional dependency
            self.client = InferenceClient(
                provider="auto", token=os.environ.get("HF_TOKEN"),
                timeout=self.timeout_s)
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
        except Exception as exc:  # provider failures become evidence
            return ProviderObservation(
                latency_ms=(time.perf_counter() - started) * 1000.0,
                error=f"{type(exc).__name__}: {exc}")

        choices = getattr(response, "choices", []) or []
        message = getattr(choices[0], "message", None) if choices else None
        text = str(getattr(message, "content", "") or "")
        normalized, native, malformed = [], [], False
        for item in getattr(message, "tool_calls", []) or []:
            function = (item.get("function") if isinstance(item, dict)
                        else getattr(item, "function", None))
            name = self._function_value(function, "name", "unknown")
            raw_args = self._function_value(function, "arguments", "{}")
            native.append({"type": "function", "name": str(name),
                           "arguments": raw_args})
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                if not isinstance(args, dict):
                    raise TypeError("function arguments are not an object")
                normalized.append({"tool": str(name), "args": dict(args)})
            except (json.JSONDecodeError, TypeError, ValueError):
                malformed = True

        # Some open-weight backends return strict JSON in content despite
        # receiving tool schemas.  Reuse the existing non-executable parser;
        # it only accepts canonical JSON tool objects and never evaluates code.
        if not normalized and not malformed and text:
            normalized = parse_tool_calls(text)
            if normalized:
                native = [{"type": "structured_text", "content": text}]

        return ProviderObservation(
            tool_calls=normalized, native_tool_calls=native, text=text,
            malformed=malformed,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
