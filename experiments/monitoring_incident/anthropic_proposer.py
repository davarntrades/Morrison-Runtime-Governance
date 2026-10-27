"""Optional Anthropic Messages API proposer. Paid; never used in Phase 1.

Opt-in twice: the caller must pass allow_paid=True (CLI: --allow-paid-api), and
the `anthropic` SDK must be installed with credentials resolvable from the
environment (ANTHROPIC_API_KEY or an `ant auth login` profile). The model is
always supplied by the operator.

Request shape follows the current API: no sampling parameters (temperature /
top_p / top_k are rejected), thinking left at the model default (adaptive on
current models), depth controlled by output_config.effort, tool_choice auto.
The full assistant content (including thinking blocks) is appended back
unchanged each turn.

No refusal fallback is configured, deliberately: a fallback answers with a
different model, so a run would no longer measure the model under test.
Refusals are recorded as `stop_reason="refusal"` with their category.
"""

from __future__ import annotations

import time

from experiments.monitoring_incident.proposers import (
    SYSTEM_PROMPT, Proposer, ProposalBatch, tool_specs,
)


class AnthropicProposer(Proposer):
    provider = "anthropic"

    def __init__(self, model: str, allow_paid: bool = False, effort: str = "medium",
                 max_tokens: int = 16000, timeout_s: float = 600.0):
        if not allow_paid:
            raise PermissionError("the Anthropic proposer makes paid API calls; pass "
                                  "allow_paid=True (--allow-paid-api) to enable it")
        if not model:
            raise ValueError("a model name is required (no default is assumed)")
        import anthropic                                    # optional dependency
        super().__init__(model=model, config={"effort": effort, "max_tokens": max_tokens,
                                              "timeout_s": timeout_s})
        self._client = anthropic.Anthropic(timeout=timeout_s)
        self._tools = [{"name": t["name"], "description": t["description"],
                        "input_schema": t["parameters"]} for t in tool_specs()]
        self.messages: list = []

    def start(self, task_prompt: str) -> None:
        self.messages = [{"role": "user", "content": task_prompt}]

    def propose(self, feedback: list) -> ProposalBatch:
        import anthropic
        if feedback:
            self.messages.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": f.call_id, "content": f.content}
                for f in feedback]})
        t0 = time.monotonic()
        try:
            response = self._client.messages.create(
                model=self.model, max_tokens=self.config["max_tokens"], system=SYSTEM_PROMPT,
                tools=self._tools, tool_choice={"type": "auto"},
                output_config={"effort": self.config["effort"]},
                messages=self.messages)
        except anthropic.APIStatusError as e:
            return ProposalBatch(error="APIStatusError %s: %s" % (e.status_code, e.message),
                                 stop_reason="provider_error", latency_s=time.monotonic() - t0)
        except anthropic.APIConnectionError as e:
            return ProposalBatch(error="APIConnectionError: %s" % e,
                                 stop_reason="provider_error", latency_s=time.monotonic() - t0)
        self.messages.append({"role": "assistant", "content": response.content})
        calls, text = [], []
        for block in response.content:
            if block.type == "tool_use":
                calls.append({"id": block.id, "tool": block.name, "args": dict(block.input or {})})
            elif block.type == "text":
                text.append(block.text)
        stop = response.stop_reason or ""
        if stop == "refusal" and getattr(response, "stop_details", None) is not None:
            stop = "refusal:%s" % (response.stop_details.category,)
        usage = {"input_tokens": response.usage.input_tokens,
                 "output_tokens": response.usage.output_tokens,
                 "request_id": getattr(response, "_request_id", None)}
        return ProposalBatch(calls=calls, text="\n".join(text), usage=usage, stop_reason=stop,
                             latency_s=time.monotonic() - t0)
