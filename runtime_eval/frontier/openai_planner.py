"""OpenAI Responses API planner adapter (proposal generation only)."""

from __future__ import annotations

import json
import time

from runtime_eval.frontier.base import OneShotFrontierPlanner, ProviderObservation
from runtime_eval.frontier.scenarios import Scenario
from runtime_eval.frontier.tool_schema import openai_tools
from runtime_eval.planners.base import PlannerInfo


class OpenAIFrontierPlanner(OneShotFrontierPlanner):
    def __init__(self, scenario: Scenario, model: str = "gpt-5.6", client=None):
        super().__init__()
        self.scenario = scenario
        self.client = client
        self.info = PlannerInfo(
            name="frontier.openai", model_id=model, family="openai",
            deterministic=False,
        )

    def _invoke(self) -> ProviderObservation:
        if self.client is None:
            from openai import OpenAI  # optional dependency
            self.client = OpenAI()
        started = time.perf_counter()
        try:
            response = self.client.responses.create(
                model=self.info.model_id,
                input=self.scenario.prompt(),
                tools=openai_tools(),
                tool_choice="auto",
            )
        except Exception as exc:  # provider errors are evidence, not crashes
            return ProviderObservation(
                latency_ms=(time.perf_counter() - started) * 1000.0,
                error=f"{type(exc).__name__}: {exc}")
        calls, malformed, texts = [], False, []
        for item in getattr(response, "output", []) or []:
            kind = getattr(item, "type", None)
            if kind == "function_call":
                try:
                    args = json.loads(getattr(item, "arguments", "{}"))
                    if not isinstance(args, dict):
                        raise TypeError("function arguments are not an object")
                    calls.append({"tool": getattr(item, "name", "unknown"),
                                  "args": args})
                except (json.JSONDecodeError, TypeError, ValueError):
                    malformed = True
            elif kind == "message":
                for block in getattr(item, "content", []) or []:
                    text = getattr(block, "text", None)
                    if text:
                        texts.append(str(text))
        return ProviderObservation(
            tool_calls=calls, text="\n".join(texts), malformed=malformed,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
