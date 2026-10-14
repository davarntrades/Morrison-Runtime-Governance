"""Morrison as the tool executor of an AgentDojo agent pipeline.

`MorrisonToolsExecutor` is a drop-in replacement for AgentDojo's
`ToolsExecutor`. Every tool call the model proposes is first handed to
`GovernanceKernel.authorize`. Only a PERMIT reaches `GovernanceKernel.execute`,
which in turn is the only caller of AgentDojo's `FunctionsRuntime`. BLOCK and
ESCALATE come back to the model as a tool error; the environment is never
touched. Nothing here adds policy: the verdict is entirely Morrison's.

An ESCALATE has no human behind it in a benchmark run, so it is treated as
"not executed" — the fail-closed outcome. Results report escalations
separately so that cost is visible.
"""

from __future__ import annotations

import time
from ast import literal_eval
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import GovernanceKernel
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.trust import Principal, SecurityContext
from runtime_eval.agentdojo_bench.manifest import SuiteProfile

GOVERNED_DOMAINS = (
    OmegaDomain.FINANCE,
    OmegaDomain.CYBERSECURITY,
    OmegaDomain.DATA_PRIVACY,
    OmegaDomain.ENTERPRISE,
    OmegaDomain.COMPLIANCE,
)


def build_kernel(profile: SuiteProfile) -> GovernanceKernel:
    """A fresh kernel for one AgentDojo task run.

    Each (user task, injection task) pair is an independent episode, so it
    gets its own continuity store: history from one task must not change the
    verdicts in the next.
    """
    context = SecurityContext(
        principal=Principal(id=f"agentdojo-{profile.suite}",
                            tenant="agentdojo"),
        continuity_store=InMemoryContinuityStore(),
        tool_manifest={k: list(v) for k, v in profile.tool_manifest.items()},
        unknown_tool_policy="escalate",
        internal_email_domains=profile.internal_email_domains,
        internal_url_hosts=profile.internal_url_hosts,
    )
    layer = GovernanceLayer(domains=list(GOVERNED_DOMAINS), log_all=False)
    return GovernanceKernel(layer, context)


@dataclass
class GateRecord:
    tool: str
    args: dict
    verdict: str
    layer: str
    rule: str | None
    reason: str
    capabilities: list[str]
    executed: bool
    latency_ms: float
    origin: str = ""          # filled by the oracle runner: "user" / "injection"

    def as_dict(self) -> dict:
        return {
            "tool": self.tool, "args": self.args, "verdict": self.verdict,
            "layer": self.layer, "rule": self.rule, "reason": self.reason,
            "capabilities": self.capabilities, "executed": self.executed,
            "latency_ms": round(self.latency_ms, 4), "origin": self.origin,
        }


def _is_string_list(s: str) -> bool:
    try:
        return isinstance(literal_eval(s), list)
    except (ValueError, SyntaxError):
        return False


def _denial_text(rec: GateRecord) -> str:
    return (f"Action not executed: runtime governance returned {rec.verdict} "
            f"({rec.layer}{'/' + rec.rule if rec.rule else ''}). {rec.reason}")


class MorrisonToolsExecutor(BasePipelineElement):
    """AgentDojo `ToolsExecutor` with Morrison's kernel as the only path to
    the tool runtime.

    A new kernel is built whenever a conversation starts (no tool results in
    the message list yet), so every task episode is governed from an empty
    trajectory. Decisions for the current episode are kept on `records`.
    """

    name = "morrison"

    def __init__(self, profile: SuiteProfile,
                 tool_output_formatter: Callable = tool_result_to_str,
                 enforce: bool = True) -> None:
        self.profile = profile
        self.output_formatter = tool_output_formatter
        # enforce=False records Morrison's verdict but executes every call:
        # the no-defense baseline measured through identical plumbing.
        self.enforce = enforce
        self.kernel: GovernanceKernel | None = None
        self.records: list[GateRecord] = []

    def reset(self) -> None:
        self.kernel = build_kernel(self.profile)
        self.records = []

    def gate(self, runtime: FunctionsRuntime, env: Env, function: str,
             args: dict) -> tuple[GateRecord, object, str | None]:
        """Govern and (if permitted) run one call. Returns (record, result, error)."""
        if self.kernel is None:
            self.reset()
        call = {"tool": function, "args": dict(args)}
        t0 = time.perf_counter()
        decision = self.kernel.authorize(call)
        rec = GateRecord(
            tool=function, args=dict(args), verdict=decision.verdict,
            layer=decision.layer, rule=decision.rule, reason=decision.reason,
            capabilities=sorted(decision.capabilities), executed=False,
            latency_ms=(time.perf_counter() - t0) * 1000.0)
        self.records.append(rec)

        if decision.permitted:
            box: dict = {}

            def _run(action: dict):
                # Execute the action the kernel authorised, not the caller's copy.
                box["out"] = runtime.run_function(
                    env, action["tool"], dict(action.get("args") or {}))
                return box["out"]

            ok, out = self.kernel.execute(decision, _run)
            if ok and "out" in box:
                rec.executed = True
                result, error = box["out"]
                return rec, result, error
            if not self.enforce:
                # the kernel refused at execute time; the baseline still runs it
                result, error = runtime.run_function(env, function, args)
                rec.executed = True
                return rec, result, error
            return rec, "", f"Action not executed: {out}"

        if not self.enforce:
            result, error = runtime.run_function(env, function, args)
            rec.executed = True
            return rec, result, error
        return rec, "", _denial_text(rec)

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        extra_args = dict(extra_args or {})
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = messages[-1]["tool_calls"]
        if not tool_calls:
            return query, runtime, env, messages, extra_args
        if not any(m["role"] == "tool" for m in messages):
            self.reset()

        known = {tool.name for tool in runtime.functions.values()}
        results = []
        for tool_call in tool_calls:
            if tool_call.function not in known:
                results.append(ChatToolResultMessage(
                    role="tool", content=[text_content_block_from_string("")],
                    tool_call_id=tool_call.id, tool_call=tool_call,
                    error=f"Invalid tool {tool_call.function} provided."))
                continue
            for k, v in tool_call.args.items():
                if isinstance(v, str) and _is_string_list(v):
                    tool_call.args[k] = literal_eval(v)
            _, result, error = self.gate(runtime, env, tool_call.function,
                                         dict(tool_call.args))
            results.append(ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string(
                    self.output_formatter(result) if error is None else "")],
                tool_call_id=tool_call.id, tool_call=tool_call, error=error))
        extra_args = {**extra_args,
                      "morrison_records": [r.as_dict() for r in self.records]}
        return query, runtime, env, [*messages, *results], extra_args
