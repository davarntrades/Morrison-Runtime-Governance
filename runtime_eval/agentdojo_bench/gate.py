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

import copy
import time
from ast import literal_eval
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.logging import Logger
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


APPROVAL_ISSUER = "agentdojo-approval-service"


def build_kernel(profile: SuiteProfile, signing_key: bytes = b"") -> GovernanceKernel:
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
        signing_key=signing_key,
        trusted_issuers=frozenset({APPROVAL_ISSUER}) if signing_key else frozenset(),
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
    # Full kernel decision: layer, rule, capabilities, destination, the
    # binding (decision id, action/semantic hash, ruleset hash, lease) and the
    # hash of the sealed evidence record it was issued with.
    decision: dict | None = None
    trajectory_hash: str = ""
    # The approval request this call triggered (ESCALATE + approver), if any.
    approval: dict | None = None
    # How the call reached the environment: "kernel" (Morrison executed a
    # PERMIT), "baseline_bypass" (record-only arm ran it despite the verdict),
    # or "" (not executed).
    executed_via: str = ""

    def as_dict(self) -> dict:
        return {
            "tool": self.tool, "args": self.args, "verdict": self.verdict,
            "layer": self.layer, "rule": self.rule, "reason": self.reason,
            "capabilities": self.capabilities, "executed": self.executed,
            "latency_ms": round(self.latency_ms, 4), "origin": self.origin,
            "decision": self.decision, "trajectory_hash": self.trajectory_hash,
            "approval": self.approval,
            "executed_via": self.executed_via,
        }


def _is_string_list(s: str) -> bool:
    try:
        return isinstance(literal_eval(s), list)
    except (ValueError, SyntaxError):
        return False


def _denial_text(rec: GateRecord) -> str:
    return (f"Action not executed: runtime governance returned {rec.verdict} "
            f"({rec.layer}{'/' + rec.rule if rec.rule else ''}). {rec.reason}")


def _dump_env(env: Env) -> object:
    dump = getattr(env, "model_dump", None)
    return copy.deepcopy(dump(mode="json")) if dump else None


def env_diff(before: object, after: object, path: str = "") -> list[dict]:
    """Every leaf that differs between two environment dumps, by JSON path.

    This is what actually changed in the environment, as opposed to what the
    model attempted: a withheld call leaves no entry here.
    """
    if isinstance(before, dict) and isinstance(after, dict):
        out = []
        for k in sorted(set(before) | set(after), key=str):
            out += env_diff(before.get(k, "<absent>"), after.get(k, "<absent>"),
                            f"{path}.{k}" if path else str(k))
        return out
    if (isinstance(before, list) and isinstance(after, list)
            and len(before) == len(after)):
        out = []
        for i, (b, a) in enumerate(zip(before, after)):
            out += env_diff(b, a, f"{path}[{i}]")
        return out
    if before == after:
        return []
    if isinstance(before, list) and isinstance(after, list):
        # Length changed (an item added or removed): report the list's tail.
        n = min(len(before), len(after))
        return [{"path": f"{path}[{n}:]", "before": before[n:], "after": after[n:]}]
    return [{"path": path, "before": before, "after": after}]


def _episode_key() -> tuple[str, str] | None:
    """(user_task_id, injection_task_id) of the AgentDojo task now running."""
    context = getattr(Logger.get(), "context", None) or {}
    if "user_task_id" not in context:
        return None
    return (str(context["user_task_id"]), str(context.get("injection_task_id")))


@dataclass
class Episode:
    """Evidence for one AgentDojo task run: every call the model attempted and
    the environment before the first call, kept next to a live reference to
    the environment so the actual effect can be diffed at the end."""
    attempted: list[dict]
    env_before: object
    env: Env
    kernel: GovernanceKernel | None = None

    def evidence(self) -> dict:
        """The episode's sealed Morrison evidence chain, exported as JSONL
        records, with the kernel's own verification of it."""
        if self.kernel is None:
            return {"records": [], "jsonl": "", "integrity_verified": None,
                    "problems": []}
        ok, problems = self.kernel.chain.verify()
        jsonl = self.kernel.chain.to_jsonl()
        return {"records": len(self.kernel.chain.records), "jsonl": jsonl,
                "head": self.kernel.chain.head,
                "integrity_verified": ok, "problems": problems}

    def as_dict(self) -> dict:
        effects = env_diff(self.env_before, _dump_env(self.env))
        executed = [c for c in self.attempted if c["executed"]]
        layers: dict[str, int] = {}
        for c in self.attempted:
            key = f'{c["verdict"]}:{c.get("layer", "")}'
            layers[key] = layers.get(key, 0) + 1
        return {
            "attempted_calls": self.attempted,
            "n_attempted": len(self.attempted),
            "n_executed": len(executed),
            "n_withheld": len(self.attempted) - len(executed),
            "n_block": sum(c["verdict"] == "BLOCK" for c in self.attempted),
            "n_escalate": sum(c["verdict"] == "ESCALATE" for c in self.attempted),
            "n_executed_bypassing_verdict": sum(
                c.get("executed_via") == "baseline_bypass"
                and c["verdict"] != "PERMIT" for c in self.attempted),
            "verdicts_by_layer": layers,
            "resource_state_before": self.env_before,
            "resource_state_after": _dump_env(self.env),
            "resource_effects": effects,
            "n_resource_effects": len(effects),
            "evidence_chain": self.evidence(),
        }


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
        self.approver = None
        self._approval_key = b""
        # Per AgentDojo task (keyed by user/injection task id, read from the
        # TraceLogger the benchmark opens around each task): what the model
        # attempted and what the environment actually changed.
        self.episodes: dict[tuple[str, str], Episode] = {}
        self._episode: Episode | None = None

    def start_episode(self, env: Env) -> None:
        """Open the evidence record for the task now running: snapshot the
        environment before the model can act. `EpisodeStart` calls this ahead
        of the first model turn so tasks with no tool call are recorded too."""
        self._episode = Episode([], _dump_env(env), env)
        key = _episode_key()
        if key is not None:
            self.episodes[key] = self._episode

    def reset(self) -> None:
        self.kernel = build_kernel(self.profile, self._approval_key)
        self.records = []

    def attach_approver(self, approver) -> None:
        """Route ESCALATE verdicts to `approver` (see approvers.py). The key
        that signs approvals is generated here and held only by this executor
        and its kernels; the model never sees it."""
        import secrets
        self.approver = approver
        self._approval_key = secrets.token_bytes(32)

    def _request_approval(self, call: dict) -> tuple[object | None, dict]:
        import dataclasses
        import secrets
        from morrison_governance.kernel import issue_approval
        from runtime_eval.agentdojo_bench.approvers import EpisodeInfo
        key = _episode_key() or ("", None)
        info = EpisodeInfo(key[0], None if key[1] in (None, "None") else key[1],
                           self._episode.env_before if self._episode else {})
        t0 = time.perf_counter()
        ok, why = self.approver.decide(call, info)
        log = {"approver": self.approver.name, "approved": ok, "reason": why,
               "latency_ms": round((time.perf_counter() - t0) * 1e3, 4)}
        if not ok:
            return None, log
        art = issue_approval(call, APPROVAL_ISSUER, self._approval_key,
                             ttl_s=120.0, nonce=secrets.token_hex(12))
        log["nonce"] = art.nonce
        self.kernel.ctx = dataclasses.replace(self.kernel.ctx, approvals=(art,))
        return art, log

    def gate(self, runtime: FunctionsRuntime, env: Env, function: str,
             args: dict) -> tuple[GateRecord, object, str | None]:
        """Govern and (if permitted) run one call. Returns (record, result, error)."""
        if self.kernel is None:
            self.reset()
        call = {"tool": function, "args": dict(args)}
        t0 = time.perf_counter()
        decision = self.kernel.authorize(call)
        approval_log = None
        if decision.escalated and self.approver is not None:
            first = {"verdict": decision.verdict, "layer": decision.layer,
                     "rule": decision.rule}
            art, approval_log = self._request_approval(call)
            approval_log["initial_decision"] = first
            if art is not None:
                decision = self.kernel.authorize(call)
            # an approval is presented for this one request only
            import dataclasses
            self.kernel.ctx = dataclasses.replace(self.kernel.ctx, approvals=())
        rec = GateRecord(
            tool=function, args=dict(args), verdict=decision.verdict,
            layer=decision.layer, rule=decision.rule, reason=decision.reason,
            capabilities=sorted(decision.capabilities), executed=False,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            decision=decision.as_dict(),
            trajectory_hash=decision.trajectory_hash,
            approval=approval_log)
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
                rec.executed, rec.executed_via = True, "kernel"
                result, error = box["out"]
                return rec, result, error
            if not self.enforce:
                # the kernel refused at execute time; the baseline still runs it
                result, error = runtime.run_function(env, function, args)
                rec.executed, rec.executed_via = True, "baseline_bypass"
                return rec, result, error
            return rec, "", f"Action not executed: {out}"

        if not self.enforce:
            result, error = runtime.run_function(env, function, args)
            rec.executed, rec.executed_via = True, "baseline_bypass"
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
            if self._episode is None or self._episode.env is not env:
                self.start_episode(env)
            self._episode.kernel = self.kernel

        known = {tool.name for tool in runtime.functions.values()}
        results = []
        for tool_call in tool_calls:
            if tool_call.function not in known:
                if self._episode is not None:
                    self._episode.attempted.append({
                        "tool": tool_call.function, "args": dict(tool_call.args),
                        "verdict": "INVALID_TOOL", "executed": False})
                results.append(ChatToolResultMessage(
                    role="tool", content=[text_content_block_from_string("")],
                    tool_call_id=tool_call.id, tool_call=tool_call,
                    error=f"Invalid tool {tool_call.function} provided."))
                continue
            for k, v in tool_call.args.items():
                if isinstance(v, str) and _is_string_list(v):
                    tool_call.args[k] = literal_eval(v)
            rec, result, error = self.gate(runtime, env, tool_call.function,
                                           dict(tool_call.args))
            if self._episode is not None:
                self._episode.attempted.append({
                    **rec.as_dict(), "tool_error": error})
            results.append(ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string(
                    self.output_formatter(result) if error is None else "")],
                tool_call_id=tool_call.id, tool_call=tool_call, error=error))
        extra_args = {**extra_args,
                      "morrison_records": [r.as_dict() for r in self.records]}
        return query, runtime, env, [*messages, *results], extra_args


class EpisodeStart(BasePipelineElement):
    """Pipeline element placed before the first model call. It changes
    nothing; it lets the executor snapshot the environment for this task."""

    name = "episode_start"

    def __init__(self, executor: MorrisonToolsExecutor) -> None:
        self.executor = executor

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
        self.executor.start_episode(env)
        return query, runtime, env, messages, dict(extra_args or {})
