"""AgentDojo's Anthropic adapter, adjusted for current Claude models.

AgentDojo 0.1.35's `AnthropicLLM` was written for models that accept sampling
parameters and a thinking budget. Current models reject both with a 400:
`temperature` (which AgentDojo always sends, as 0.0) and
`thinking: {type: "enabled", budget_tokens}`. Thinking is always on and counts
toward `max_tokens`, so AgentDojo's 1024-token limit would cut turns off.

`GovernedBudgetLLM` keeps AgentDojo's own message conversion, tool schemas and
system prompt, and changes only the request:

* no `temperature`
* `thinking: {type: "adaptive"}` with `display: "summarized"` (billed the same
  as the default `omitted`, but the transcript keeps a readable reasoning
  summary)
* an explicit `output_config.effort` and a larger `max_tokens`
* `block_binding.prefix_mismatch_behavior: "drop_block"` (beta
  `thinking-binding-controls-2026-08-01`). AgentDojo rebuilds each assistant
  turn as text/thinking blocks followed by tool calls, which can reorder what
  the model produced. With `drop_block` a thinking block whose prefix no longer
  matches is dropped (and reported) instead of failing the request with a 400.
* no refusal fallback, on purpose: a fallback would answer with a different
  model, and both arms must be served by the model under test. Refusals are
  counted instead.

Every request is metered: tokens, stop reason, request id, any input
transformations the API reports, and an estimated cost. A `Budget` shared by
the run stops it before a request that would start past the cap; the run then
records the partial results as incomplete rather than successful.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from anthropic import NOT_GIVEN, AsyncAnthropic, BadRequestError
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.anthropic_llm import (
    _anthropic_to_assistant_message, _conversation_to_anthropic,
    _function_to_anthropic,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage
from tenacity import (
    retry, retry_if_not_exception_type, stop_after_attempt,
    wait_random_exponential,
)

THINKING_BINDING_BETA = "thinking-binding-controls-2026-08-01"

# USD per million tokens. Claude Opus 5.5 first-party API list prices; used
# only to estimate spend for the budget stop. The invoice is authoritative.
PRICES_PER_MTOK = {
    "claude-opus-5-5": {"input": 4.00, "output": 20.00,
                        "cache_write": 5.00, "cache_read": 0.20},
}


class BudgetExceeded(RuntimeError):
    """Raised before a request would start past the run's spend or call cap."""


@dataclass
class Budget:
    """Spend and request cap for one benchmark arm, plus the request log."""
    model: str
    max_usd: float
    max_requests: int
    requests: list[dict] = field(default_factory=list)

    @property
    def spent_usd(self) -> float:
        return round(sum(r["est_cost_usd"] for r in self.requests), 6)

    def check(self) -> None:
        if len(self.requests) >= self.max_requests:
            raise BudgetExceeded(
                f"request cap reached: {len(self.requests)}/{self.max_requests}")
        if self.spent_usd >= self.max_usd:
            raise BudgetExceeded(
                f"spend cap reached: est ${self.spent_usd:.2f} >= ${self.max_usd:.2f}")

    def record(self, completion, latency_s: float,
               request_id: str | None = None) -> None:
        usage = completion.usage
        price = PRICES_PER_MTOK.get(self.model)
        tokens = {
            "input_tokens": usage.input_tokens or 0,
            "output_tokens": usage.output_tokens or 0,
            "cache_creation_input_tokens":
                getattr(usage, "cache_creation_input_tokens", 0) or 0,
            "cache_read_input_tokens":
                getattr(usage, "cache_read_input_tokens", 0) or 0,
        }
        cost = None
        if price:
            cost = (tokens["input_tokens"] * price["input"]
                    + tokens["output_tokens"] * price["output"]
                    + tokens["cache_creation_input_tokens"] * price["cache_write"]
                    + tokens["cache_read_input_tokens"] * price["cache_read"]) / 1e6
        extra = getattr(completion, "model_extra", None) or {}
        self.requests.append({
            # The final message of a stream carries no `_request_id`; the id
            # comes from the stream's `request-id` response header.
            "request_id": request_id or getattr(completion, "_request_id", None),
            "message_id": getattr(completion, "id", None),
            "episode": _episode_label(),
            "served_model": completion.model,
            "stop_reason": completion.stop_reason,
            "stop_details": _plain(getattr(completion, "stop_details", None)),
            "input_transformations": _plain(
                getattr(completion, "input_transformations", None)
                or extra.get("input_transformations")),
            "block_types": [b.type for b in completion.content],
            **tokens,
            "est_cost_usd": round(cost, 6) if cost is not None else 0.0,
            "latency_s": round(latency_s, 3),
        })

    def summary(self) -> dict:
        reqs = self.requests

        def total(key: str) -> int:
            return sum(r[key] for r in reqs)

        stops: dict[str, int] = {}
        for r in reqs:
            stops[str(r["stop_reason"])] = stops.get(str(r["stop_reason"]), 0) + 1
        return {
            "model": self.model, "max_usd": self.max_usd,
            "max_requests": self.max_requests, "requests": len(reqs),
            "input_tokens": total("input_tokens"),
            "output_tokens": total("output_tokens"),
            "cache_creation_input_tokens": total("cache_creation_input_tokens"),
            "cache_read_input_tokens": total("cache_read_input_tokens"),
            "est_cost_usd": self.spent_usd,
            "stop_reasons": stops,
            "served_models": sorted({str(r["served_model"]) for r in reqs}),
            "requests_with_input_transformations":
                sum(1 for r in reqs if r["input_transformations"]),
            "requests_with_request_id": sum(1 for r in reqs if r["request_id"]),
        }


def _episode_label() -> str | None:
    """`user_task|injection_task` of the AgentDojo task now running."""
    try:
        from agentdojo.logging import Logger
        ctx = getattr(Logger.get(), "context", None) or {}
    except Exception:  # noqa: BLE001 - labelling must never break a request
        return None
    if "user_task_id" not in ctx:
        return None
    return f'{ctx["user_task_id"]}|{ctx.get("injection_task_id")}'


def _plain(obj):
    if obj is None:
        return None
    dump = getattr(obj, "model_dump", None)
    return dump(mode="json") if dump else obj


@dataclass(frozen=True)
class RequestSettings:
    """Model settings shared by both arms; recorded in every result file."""
    model: str
    max_tokens: int = 16000
    effort: str = "medium"
    thinking_display: str = "summarized"
    prefix_mismatch_behavior: str = "drop_block"

    def as_dict(self) -> dict:
        return {"model": self.model, "max_tokens": self.max_tokens,
                "effort": self.effort, "thinking": {
                    "type": "adaptive", "display": self.thinking_display,
                    "block_binding": {"prefix_mismatch_behavior":
                                      self.prefix_mismatch_behavior}},
                "betas": [THINKING_BINDING_BETA],
                "temperature": "not sent", "fallbacks": "not sent"}


@retry(wait=wait_random_exponential(multiplier=1, max=40),
       stop=stop_after_attempt(3),
       retry=retry_if_not_exception_type((BadRequestError, BudgetExceeded)))
async def _request(client: AsyncAnthropic, settings: RequestSettings,
                   budget: Budget, *, messages, tools, system_prompt):
    """One model request, retried like AgentDojo's own (3 attempts, never on
    a 400). Each attempt is checked against the budget first."""
    budget.check()
    t0 = time.perf_counter()
    async with client.beta.messages.stream(
        model=settings.model,
        max_tokens=settings.max_tokens,
        messages=messages,
        tools=tools or NOT_GIVEN,
        system=system_prompt or NOT_GIVEN,
        thinking={"type": "adaptive", "display": settings.thinking_display,
                  "block_binding": {"prefix_mismatch_behavior":
                                    settings.prefix_mismatch_behavior}},
        output_config={"effort": settings.effort},
        betas=[THINKING_BINDING_BETA],
    ) as stream:
        completion = await stream.get_final_message()
        request_id = getattr(stream, "request_id", None)
    budget.record(completion, time.perf_counter() - t0, request_id)
    return completion


class GovernedBudgetLLM(BasePipelineElement):
    """AgentDojo LLM element for current Claude models, with a spend cap."""

    def __init__(self, settings: RequestSettings, budget: Budget,
                 client: AsyncAnthropic | None = None) -> None:
        self.settings = settings
        self.budget = budget
        self.client = client or AsyncAnthropic()
        self.model = settings.model
        self.name = settings.model

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        system_prompt, anthropic_messages = _conversation_to_anthropic(messages)
        tools = [_function_to_anthropic(t) for t in runtime.functions.values()]
        completion = asyncio.run(_request(
            self.client, self.settings, self.budget,
            messages=anthropic_messages, tools=tools,
            system_prompt=system_prompt))
        output = _anthropic_to_assistant_message(completion)
        # Same filter as AgentDojo's adapter: drop tool calls whose name the
        # Anthropic API could not have produced for a declared tool.
        if output["tool_calls"] is not None:
            output["tool_calls"] = [
                c for c in output["tool_calls"]
                if re.match("^[a-zA-Z0-9_-]{1,64}$", c.function)]
        return query, runtime, env, [*messages, output], dict(extra_args or {})
