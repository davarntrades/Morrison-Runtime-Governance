"""Anthropic Messages API planner adapter (proposal generation only)."""

from __future__ import annotations

import time

from runtime_eval.frontier.base import OneShotFrontierPlanner, ProviderObservation
from runtime_eval.frontier.scenarios import Scenario
from runtime_eval.frontier.tool_schema import anthropic_tools
from runtime_eval.planners.base import PlannerInfo


class AnthropicFrontierPlanner(OneShotFrontierPlanner):
    def __init__(self, scenario: Scenario, model: str = "claude-opus-5", client=None):
        super().__init__()
        self.scenario = scenario
        self.client = client
        self.info = PlannerInfo(
            name="frontier.anthropic", model_id=model, family="anthropic",
            deterministic=False,
        )

    def _invoke(self) -> ProviderObservation:
        if self.client is None:
            import anthropic  # optional dependency
            self.client = anthropic.Anthropic()
        started = time.perf_counter()
        try:
            response = self.client.messages.create(
                model=self.info.model_id,
                max_tokens=1024,
                tools=anthropic_tools(),
                tool_choice={"type": "auto"},
                messages=[{"role": "user", "content": self.scenario.prompt()}],
            )
        except Exception as exc:
            return ProviderObservation(
                latency_ms=(time.perf_counter() - started) * 1000.0,
                error=f"{type(exc).__name__}: {exc}")
        calls, malformed, texts = [], False, []
        for block in getattr(response, "content", []) or []:
            kind = getattr(block, "type", None)
            if kind == "tool_use":
                args = getattr(block, "input", {})
                if not isinstance(args, dict):
                    malformed = True
                    continue
                calls.append({"tool": getattr(block, "name", "unknown"),
                              "args": dict(args)})
            elif kind == "text":
                texts.append(str(getattr(block, "text", "")))
        return ProviderObservation(
            tool_calls=calls, text="\n".join(texts), malformed=malformed,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
