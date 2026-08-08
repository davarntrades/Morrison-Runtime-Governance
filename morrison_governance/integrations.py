"""
Real-agent deployment adapters.

Drop-in governance for the surfaces that actually execute tools in
production:

    · OpenAI tool calling
    · Claude tool-use chains
    · LangChain tools / agents
    · AutoGen function calls
    · Browser agents
    · MCP servers
    · Shell execution
    · Enterprise workflows (multi-step DAGs)

Design principles:
  - **No hard dependencies.** Every adapter uses duck typing; importing
    this module never imports langchain/openai/autogen/mcp.
  - **Fail closed.** The default on a BLOCK / NO_VALID_SOLUTION /
    ENVIRONMENT_SENSITIVE verdict is to *stop execution* (raise), never to
    silently continue.
  - **Deterministic.** Adapters only normalise inputs and delegate to the
    GovernanceLayer; they add no randomness.
"""

# Builtin generic annotations (dict[...], list[...]) below are evaluated
# at definition time and need Python 3.9+. Deferring evaluation keeps the
# syntax while restoring importability on older interpreters.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

from morrison_governance.core import GovernanceLayer
from morrison_governance.result import GovernanceResult, GovernanceVerdict


class GovernanceError(RuntimeError):
    """Raised by fail-closed adapters when a call is not permitted."""

    def __init__(self, result: GovernanceResult):
        self.result = result
        super().__init__(
            f"governance blocked [{result.layer}] "
            f"{result.verdict.value}: {result.reason}"
        )


@dataclass
class GovernanceGuard:
    """Reusable fail-closed wrapper around a GovernanceLayer.

    on_block:
        "raise"  → raise GovernanceError (default; safest for middleware)
        "deny"   → return the GovernanceResult, let the caller branch
    """

    governance: GovernanceLayer
    on_block: str = "raise"
    audit: Optional[Callable[[GovernanceResult], None]] = None

    # ---- core ---------------------------------------------------------
    def check_call(self, tool: str, args: Any = None, **context) -> GovernanceResult:
        call = {"tool": tool, "args": args if args is not None else {}}
        call.update(context)
        return self._gate(self.governance.evaluate(call))

    def check_plan(self, steps: list[dict]) -> GovernanceResult:
        return self._gate(self.governance.evaluate_plan(steps))

    def allow(self, tool: str, args: Any = None, **context) -> bool:
        call = {"tool": tool, "args": args if args is not None else {}}
        call.update(context)
        return self.governance.evaluate(call).permitted

    def _gate(self, result: GovernanceResult) -> GovernanceResult:
        if self.audit is not None:
            self.audit(result)
        if not result.permitted and self.on_block == "raise":
            raise GovernanceError(result)
        return result


# ─────────────────────────────────────────────────────────────
# OpenAI tool calling
# ─────────────────────────────────────────────────────────────

def _openai_call_to_dict(tc: Any) -> dict:
    """Normalise an OpenAI tool_call (object or dict) to {tool, args}."""
    import json
    if hasattr(tc, "function"):
        name = tc.function.name
        raw = tc.function.arguments
    elif isinstance(tc, dict):
        fn = tc.get("function", tc)
        name = fn.get("name", tc.get("name", "unknown"))
        raw = fn.get("arguments", tc.get("arguments", {}))
    else:  # pragma: no cover - defensive
        name, raw = "unknown", {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raw = {"raw": raw}
    return {"tool": name, "args": raw}


def openai_partition_tool_calls(
    guard: GovernanceGuard, tool_calls: Iterable[Any], **context
) -> tuple[list[Any], list[tuple[Any, GovernanceResult]]]:
    """Split a response's tool_calls into (allowed, [(denied, result), ...]).
    Never raises — use this when you want to answer the model with
    tool_result errors instead of aborting the turn."""
    allowed, denied = [], []
    for tc in tool_calls:
        call = _openai_call_to_dict(tc)
        call.update(context)
        r = guard.governance.evaluate(call)
        if guard.audit:
            guard.audit(r)
        (allowed if r.permitted else denied).append(
            tc if r.permitted else (tc, r))
    return allowed, denied


def openai_guarded_dispatch(
    guard: GovernanceGuard,
    tool_calls: Iterable[Any],
    dispatch: Callable[[str, dict], Any],
    **context,
) -> list[dict]:
    """Evaluate then dispatch each permitted call; return OpenAI-style
    tool result messages. Denied calls yield an error tool message rather
    than executing."""
    results = []
    for tc in tool_calls:
        call = _openai_call_to_dict(tc)
        call.update(context)
        r = guard.governance.evaluate(call)
        if guard.audit:
            guard.audit(r)
        tc_id = getattr(tc, "id", None) or (
            tc.get("id") if isinstance(tc, dict) else None)
        if r.permitted:
            out = dispatch(call["tool"], call["args"])
            results.append({"role": "tool", "tool_call_id": tc_id,
                            "content": str(out)})
        else:
            results.append({"role": "tool", "tool_call_id": tc_id,
                            "content": f"BLOCKED by governance "
                                       f"[{r.layer}]: {r.reason}"})
    return results


# ─────────────────────────────────────────────────────────────
# Claude tool-use chains
# ─────────────────────────────────────────────────────────────

def _claude_block_to_dict(block: Any) -> dict:
    if isinstance(block, dict):
        return {"tool": block.get("name", "unknown"),
                "args": block.get("input", {}) or {}}
    return {"tool": getattr(block, "name", "unknown"),
            "args": getattr(block, "input", {}) or {}}


def claude_filter_tool_use(
    guard: GovernanceGuard, content: Iterable[Any], **context
) -> tuple[list[Any], list[dict]]:
    """Given the content blocks of a Claude assistant message, return
    (allowed_tool_use_blocks, tool_result_blocks_for_denied). The denied
    list is ready to send back to the API as `tool_result` content with
    is_error=True."""
    allowed, denied_results = [], []
    for block in content:
        btype = block.get("type") if isinstance(block, dict) else getattr(
            block, "type", None)
        if btype != "tool_use":
            continue
        call = _claude_block_to_dict(block)
        call.update(context)
        r = guard.governance.evaluate(call)
        if guard.audit:
            guard.audit(r)
        if r.permitted:
            allowed.append(block)
        else:
            tu_id = block.get("id") if isinstance(block, dict) else getattr(
                block, "id", None)
            denied_results.append({
                "type": "tool_result",
                "tool_use_id": tu_id,
                "is_error": True,
                "content": f"Blocked by Morrison governance "
                           f"[{r.layer}] {r.verdict.value}: {r.reason}",
            })
    return allowed, denied_results


# ─────────────────────────────────────────────────────────────
# LangChain
# ─────────────────────────────────────────────────────────────

def govern_langchain_tool(guard: GovernanceGuard, tool: Any) -> Any:
    """Wrap a LangChain tool so every invocation is gated. Works with
    objects exposing `.name` and one of `func` / `_run` / `run` / `invoke`."""
    name = getattr(tool, "name", getattr(tool, "__name__", "unknown"))

    for attr in ("func", "_run", "run", "invoke"):
        original = getattr(tool, attr, None)
        if original is None or not callable(original):
            continue

        def gated(*args, __orig=original, **kwargs):
            payload = kwargs if kwargs else (args[0] if args else {})
            guard.check_call(name, payload)
            return __orig(*args, **kwargs)

        try:
            setattr(tool, attr, gated)
        except (AttributeError, TypeError):
            # Pydantic v2 tools may forbid attribute assignment; fall back
            # to wrapping the callable the caller will actually invoke.
            return _CallableToolProxy(tool, name, guard, original)
        return tool
    return tool


class _CallableToolProxy:
    """Last-resort wrapper for immutable tool objects."""

    def __init__(self, tool, name, guard, original):
        self._tool, self.name, self._guard, self._orig = (
            tool, name, guard, original)

    def __call__(self, *a, **kw):
        self._guard.check_call(self.name, kw or (a[0] if a else {}))
        return self._orig(*a, **kw)

    def __getattr__(self, item):
        return getattr(self._tool, item)


class GovernanceCallbackHandler:
    """LangChain-style callback handler. Plug into callbacks=[...]; raises
    GovernanceError from on_tool_start for a blocked tool."""

    def __init__(self, guard: GovernanceGuard):
        self.guard = guard

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
        name = (serialized or {}).get("name", "unknown")
        self.guard.check_call(name, {"input": input_str})

    # no-ops so the handler satisfies the callback protocol duck-test
    def on_tool_end(self, *a, **k): pass
    def on_tool_error(self, *a, **k): pass
    def on_chain_start(self, *a, **k): pass
    def on_chain_end(self, *a, **k): pass


# ─────────────────────────────────────────────────────────────
# AutoGen
# ─────────────────────────────────────────────────────────────

def autogen_guard_function_call(
    guard: GovernanceGuard, name: str, arguments: dict, **context
) -> GovernanceResult:
    """Call from an AutoGen function-execution hook. Raises (fail closed)
    on a blocked call when guard.on_block == 'raise'."""
    return guard.check_call(name, arguments, **context)


def register_autogen_guard(agent: Any, guard: GovernanceGuard) -> Any:
    """Wrap every function registered on an AutoGen ConversableAgent's
    `function_map` with a governance gate."""
    fmap = getattr(agent, "function_map", None)
    if not isinstance(fmap, dict):
        return agent
    for fname, fn in list(fmap.items()):
        def wrapped(*args, __fn=fn, __n=fname, **kwargs):
            guard.check_call(__n, kwargs or (args[0] if args else {}))
            return __fn(*args, **kwargs)
        fmap[fname] = wrapped
    return agent


# ─────────────────────────────────────────────────────────────
# Browser agents
# ─────────────────────────────────────────────────────────────

# Browser actions are mapped onto governable tool calls so the same Ω
# rules and taint flow apply (e.g. download → read source; submit → egress).
BROWSER_ACTION_TOOL = {
    "navigate":  "browser_navigate",
    "goto":      "browser_navigate",
    "click":     "browser_click",
    "type":      "browser_type",
    "fill":      "browser_type",
    "download":  "download",
    "upload":    "upload",
    "submit":    "http_request",
    "execute_js": "exec",
    "screenshot": "read_file",
    "extract":   "get_data",
}


def browser_action_guard(
    guard: GovernanceGuard, action: str, target: str = "",
    value: Any = None, **context
) -> GovernanceResult:
    """Gate a single browser-agent action. `action` is navigate/click/
    type/download/upload/submit/execute_js/extract/..."""
    tool = BROWSER_ACTION_TOOL.get(action, f"browser_{action}")
    args = {"target": target}
    if value is not None:
        args["value"] = value
    if action in ("submit", "upload", "download"):
        args["url"] = target
    return guard.check_call(tool, args, **context)


# ─────────────────────────────────────────────────────────────
# MCP servers
# ─────────────────────────────────────────────────────────────

def mcp_guard_call_tool(
    guard: GovernanceGuard, name: str, arguments: dict, **context
) -> GovernanceResult:
    """Call at the top of an MCP server's call_tool handler."""
    return guard.check_call(name, arguments, **context)


def wrap_mcp_call_tool(guard: GovernanceGuard, call_tool: Callable) -> Callable:
    """Decorate an MCP `call_tool(name, arguments)` coroutine/function so
    every invocation is governed. Supports both sync and async handlers."""
    import asyncio
    import functools

    if asyncio.iscoroutinefunction(call_tool):
        @functools.wraps(call_tool)
        async def _aw(name, arguments=None, *a, **kw):
            guard.check_call(name, arguments or {})
            return await call_tool(name, arguments, *a, **kw)
        return _aw

    @functools.wraps(call_tool)
    def _sw(name, arguments=None, *a, **kw):
        guard.check_call(name, arguments or {})
        return call_tool(name, arguments, *a, **kw)
    return _sw


# ─────────────────────────────────────────────────────────────
# Shell execution
# ─────────────────────────────────────────────────────────────

def governed_run(
    guard: GovernanceGuard, command: Any,
    runner: Optional[Callable] = None, tool: str = "shell", **kwargs
):
    """Gate a shell command, then execute it with `runner` (defaults to
    subprocess.run). The command never spawns if governance blocks it."""
    guard.check_call(tool, command if isinstance(command, str)
                     else " ".join(map(str, command)))
    if runner is None:
        import subprocess
        runner = subprocess.run
    return runner(command, **kwargs)


# ─────────────────────────────────────────────────────────────
# Enterprise workflows (multi-step DAG / pipeline)
# ─────────────────────────────────────────────────────────────

@dataclass
class WorkflowGovernor:
    """Governs a whole multi-step workflow as one trajectory (so the V2
    taint / escalation analysis sees the full plan), plus per-step gating
    for streaming executors."""

    guard: GovernanceGuard

    def submit(self, steps: list[dict]) -> GovernanceResult:
        """Evaluate the entire workflow up-front. Raises (fail closed) if
        the plan as a whole is unsafe."""
        return self.guard.check_plan(steps)

    def step_gate(self, step: dict, history: Optional[list[dict]] = None
                  ) -> GovernanceResult:
        """Gate one step in the context of everything executed so far,
        so a late exfiltration step is still caught against earlier reads."""
        plan = list(history or []) + [step]
        if len(plan) == 1:
            return self.guard.check_call(step["tool"], step.get("args", {}))
        return self.guard.check_plan(plan)
