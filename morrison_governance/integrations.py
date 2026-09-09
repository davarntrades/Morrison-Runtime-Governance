"""
Real-agent deployment adapters.

Governance for the surfaces that actually execute tools in production:

    · OpenAI tool calling
    · Claude tool-use chains
    · LangChain tools / agents
    · AutoGen function calls
    · Browser agents
    · MCP servers
    · Shell execution
    · Enterprise workflows (multi-step DAGs)

THE DISTINCTION THIS MODULE ENFORCES
────────────────────────────────────
`GovernanceLayer` is reasoning and policy evaluation. It answers "does this
trajectory reach Ω?" and it is the right object to ask that question of.

`GovernanceKernel` is the VETO AUTHORITY. It is the only component that
quarantines caller-supplied authority, classifies capabilities semantically,
resolves destinations from trusted configuration, verifies approval artifacts,
holds the session trajectory, reserves a transition before it runs, binds
execution to the authorised action, and seals hash-chained evidence.

Every adapter in this module previously called `GovernanceLayer.evaluate()` and
dispatched on `if result.permitted:`. That made the layer the de-facto veto
authority, which it is not:

  * caller-supplied `authorized: true` was honoured, because nothing
    quarantined it;
  * `shell` was refused and `run_shell` carrying the same command was not,
    because nothing classified capabilities;
  * a read and its exfiltration issued as one parallel batch were both
    dispatched, because a single-call evaluation has no trajectory;
  * eight of ten catastrophic actions the kernel refuses were permitted.

So there is no longer an execution path through this module that does not pass
through the kernel. `GovernanceGuard` requires a `SecurityContext`, dispatch
happens inside `kernel.execute()`, and the advisory-only construction cannot
dispatch at all.

Design principles:
  - **No hard dependencies.** Every adapter uses duck typing; importing this
    module never imports langchain/openai/autogen/mcp.
  - **Fail closed.** A non-PERMIT verdict stops execution (raise by default).
    A guard that cannot enforce refuses to be used for execution.
  - **Deterministic.** Adapters only normalise inputs and delegate to the
    kernel; they add no randomness.
"""

# Builtin generic annotations (dict[...], list[...]) below are evaluated
# at definition time and need Python 3.9+. Deferring evaluation keeps the
# syntax while restoring importability on older interpreters.
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from morrison_governance.core import GovernanceLayer
from morrison_governance.result import GovernanceResult, GovernanceVerdict


class GovernanceError(RuntimeError):
    """Raised by fail-closed adapters when a call is not permitted."""

    def __init__(self, decision: Any):
        self.decision = decision
        # `result` kept for callers written against the pre-kernel adapters.
        self.result = decision
        verdict = getattr(decision, "verdict", "BLOCK")
        verdict = getattr(verdict, "value", verdict)
        super().__init__(
            f"governance blocked [{getattr(decision, 'layer', '?')}] "
            f"{verdict}: {getattr(decision, 'reason', '')}"
        )


class GovernanceConfigurationError(RuntimeError):
    """Raised when a guard is asked to gate execution it cannot actually veto.

    This is deliberately a hard failure at the integration point rather than a
    warning. A guard with no `SecurityContext` has no trust boundary, no
    capability policy, no trusted destinations, no session trajectory and no
    evidence chain — it can produce an opinion, not a veto. Letting it sit in
    front of a live executor is the exact configuration that permitted eight of
    ten catastrophic actions.
    """


@dataclass
class AuthorizedCall:
    """A permitted call plus the kernel decision that authorises it.

    Returned by the batch adapters instead of a bare tool call. The decision is
    a single-use lease bound to this transition, this session and this
    principal; it is redeemed by `GovernanceGuard.execute_authorized`, which is
    the only thing that can turn it into an execution.
    """

    call: dict
    decision: Any
    original: Any = None            # the framework's own object, for replies

    @property
    def tool(self) -> str:
        return str(self.call.get("tool", ""))

    @property
    def args(self) -> dict:
        return self.call.get("args") or {}


@dataclass
class DeniedCall:
    """A refused call plus the decision explaining the refusal."""

    call: dict
    decision: Any
    original: Any = None

    @property
    def tool(self) -> str:
        return str(self.call.get("tool", ""))

    @property
    def args(self) -> dict:
        return self.call.get("args") or {}

    @property
    def reason(self) -> str:
        return getattr(self.decision, "reason", "")


@dataclass
class GovernanceGuard:
    """Fail-closed wrapper around the KERNEL.

    Construct with the deployment's `SecurityContext`:

        guard = GovernanceGuard(gov, security_context=ctx)

    `on_block`:
        "raise"  → raise GovernanceError (default; safest for middleware)
        "deny"   → return the Decision, let the caller branch

    For non-enforcing analysis — shadow mode, offline scoring, dashboards —
    use `GovernanceGuard.advisory(gov)`. That guard answers questions and
    raises `GovernanceConfigurationError` from every execution-capable entry
    point, so an advisory object cannot be wired in front of a real executor by
    accident.
    """

    governance: GovernanceLayer
    security_context: Any = None
    on_block: str = "raise"
    audit: Optional[Callable[[Any], None]] = None
    session_id: str = ""
    _advisory: bool = field(default=False, repr=False)
    kernel: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self._advisory:
            if self.security_context is not None:
                raise GovernanceConfigurationError(
                    "an advisory guard must not carry a SecurityContext; use "
                    "GovernanceGuard(gov, security_context=ctx) to enforce")
            return
        if self.security_context is None:
            raise GovernanceConfigurationError(
                "GovernanceGuard requires a SecurityContext: without one there "
                "is no trust boundary, no capability policy, no trusted "
                "destination resolution, no session trajectory and no evidence "
                "chain, so the guard can produce an opinion but cannot veto "
                "anything. Pass security_context=..., or construct "
                "GovernanceGuard.advisory(gov) for non-enforcing analysis.")
        from morrison_governance.kernel import GovernanceKernel
        self.kernel = GovernanceKernel(self.governance, self.security_context,
                                       session_id=self.session_id)

    # ---- construction -------------------------------------------------
    @classmethod
    def advisory(cls, governance: GovernanceLayer,
                 audit: Optional[Callable[[Any], None]] = None
                 ) -> "GovernanceGuard":
        """A guard for ANALYSIS ONLY. It cannot gate execution."""
        return cls(governance=governance, on_block="deny", audit=audit,
                   _advisory=True)

    @property
    def enforcing(self) -> bool:
        return self.kernel is not None

    def _require_kernel(self, what: str) -> Any:
        if self.kernel is None:
            raise GovernanceConfigurationError(
                f"{what} needs the veto authority: this guard was constructed "
                f"for advisory analysis and cannot authorise or execute "
                f"anything. Build it with security_context=... to enforce.")
        return self.kernel

    # ---- core ---------------------------------------------------------
    @staticmethod
    def _call(tool: str, args: Any = None) -> dict:
        """Build the canonical call shape.

        NOTE what is absent: the pre-kernel adapters took `**context` and
        merged it into the call, so `guard.allow(tool, args, authorized=True)`
        wrote an authority flag straight into the namespace the Ω rules read
        their control flags from — the agent authorised itself. Authority comes
        from the SecurityContext and nowhere else, so there is no longer a
        parameter through which a caller can supply any.
        """
        return {"tool": tool, "args": args if args is not None else {}}

    def authorize(self, tool: str, args: Any = None) -> Any:
        """Get a kernel Decision for one call. Reserves a trajectory slot."""
        decision = self._require_kernel("authorize").authorize(
            self._call(tool, args))
        return self._gate(decision)

    def execute_authorized(self, authorized: AuthorizedCall,
                           executor: Callable[[dict], Any]) -> tuple[bool, Any]:
        """Redeem an `AuthorizedCall`. Single-use, and refused if stale."""
        kernel = self._require_kernel("execute_authorized")
        return kernel.execute(authorized.decision, executor)

    def dispatch(self, tool: str, args: Any, executor: Callable[[dict], Any]
                 ) -> tuple[Any, bool, Any]:
        """Authorize and execute in one step, through the kernel.

        Returns `(decision, executed, output)`. This is the only path in this
        module from a proposed call to a real side effect.
        """
        kernel = self._require_kernel("dispatch")
        decision, executed, out = kernel.submit(self._call(tool, args), executor)
        self._gate(decision)
        return decision, executed, out

    def check_call(self, tool: str, args: Any = None) -> Any:
        """Authorize one call without executing it.

        Kept for callers written against the previous adapters, but it now
        returns a kernel `Decision` and reserves a trajectory slot. If you are
        not going to execute the result, call `guard.release(decision)` or use
        `preview` so the session is not left holding the reservation.
        """
        return self.authorize(tool, args)

    def preview(self, tool: str, args: Any = None) -> Any:
        """Non-reserving, NON-EXECUTABLE evaluation of one call."""
        kernel = self._require_kernel("preview")
        decision = kernel.preview(self._call(tool, args))
        if self.audit is not None:
            self.audit(decision)
        return decision

    def release(self, decision: Any) -> bool:
        """Abandon a decision the caller will not execute."""
        return self._require_kernel("release").release(decision)

    def check_plan(self, steps: list[dict]) -> GovernanceResult:
        """Whole-plan reasoning. ADVISORY BY CONSTRUCTION.

        This is `GovernanceLayer` doing what it is for — evaluating a proposed
        trajectory — and it is genuinely useful before committing to a plan.
        It is NOT a veto: it authorises nothing, reserves nothing, and returns
        a `GovernanceResult` rather than a Decision. Steps must still be
        authorised individually as they run.
        """
        result = self.governance.evaluate_plan(steps)
        if self.audit is not None:
            self.audit(result)
        if not result.permitted and self.on_block == "raise":
            raise GovernanceError(result)
        return result

    def allow(self, tool: str, args: Any = None) -> bool:
        """Advisory boolean. Does not authorise execution.

        Uses the non-reserving preview path, so calling it does not silently
        consume trajectory slots.
        """
        return bool(self.preview(tool, args).permitted)

    def _gate(self, decision: Any) -> Any:
        if self.audit is not None:
            self.audit(decision)
        if not getattr(decision, "permitted", False) and self.on_block == "raise":
            raise GovernanceError(decision)
        return decision


# ─────────────────────────────────────────────────────────────
# OpenAI tool calling
# ─────────────────────────────────────────────────────────────

def _openai_call_to_dict(tc: Any) -> dict:
    """Normalise an OpenAI tool_call (object or dict) to {tool, args}."""
    import json

    if isinstance(tc, dict):
        fn = tc.get("function") or {}
        name = fn.get("name") or tc.get("name") or "unknown"
        raw = fn.get("arguments", tc.get("arguments", {}))
    else:
        fn = getattr(tc, "function", None)
        name = getattr(fn, "name", None) or getattr(tc, "name", "unknown")
        raw = getattr(fn, "arguments", getattr(tc, "arguments", {}))
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "{}")
        except (ValueError, TypeError):
            raw = {"_raw": raw}
    return {"tool": str(name), "args": raw if isinstance(raw, dict) else {"_positional": raw}}


def _tc_id(tc: Any) -> Any:
    return getattr(tc, "id", None) or (tc.get("id") if isinstance(tc, dict) else None)


def openai_partition_tool_calls(
    guard: GovernanceGuard, tool_calls: Iterable[Any]
) -> tuple[list[AuthorizedCall], list[DeniedCall]]:
    """Split a response's tool_calls into (authorized, denied). Never raises.

    Two changes from the pre-kernel version, both load-bearing:

    * The batch is authorised THROUGH THE KERNEL, in order. Each PERMIT
      reserves its place in the session trajectory, so the second call in a
      batch is evaluated against the first. A read and its exfiltration issued
      as one parallel batch are no longer both permitted — which is what
      happened when each call was evaluated standalone.
    * `authorized` contains `AuthorizedCall` objects, not bare tool calls. The
      caller cannot dispatch one without redeeming its decision through
      `guard.execute_authorized`, so "partition then execute the allowed list
      yourself" is no longer an ungoverned path.

    Parallel calls that are genuinely independent are unaffected: reserving a
    read does not refuse another read.
    """
    kernel = guard._require_kernel("openai_partition_tool_calls")
    authorized: list[AuthorizedCall] = []
    denied: list[DeniedCall] = []
    for tc in tool_calls:
        call = _openai_call_to_dict(tc)
        decision = kernel.authorize(call)
        if guard.audit:
            guard.audit(decision)
        if decision.permitted:
            authorized.append(AuthorizedCall(call, decision, tc))
        else:
            denied.append(DeniedCall(call, decision, tc))
    return authorized, denied


def openai_guarded_dispatch(
    guard: GovernanceGuard,
    tool_calls: Iterable[Any],
    dispatch: Callable[[str, dict], Any],
) -> list[dict]:
    """Authorize then execute each permitted call; return OpenAI-style tool
    result messages. Denied calls yield an error tool message.

    Execution happens inside `kernel.execute`, so the action that runs is the
    action that was authorised and the trajectory advances as it goes.
    """
    kernel = guard._require_kernel("openai_guarded_dispatch")
    results = []
    for tc in tool_calls:
        call = _openai_call_to_dict(tc)
        decision, executed, out = kernel.submit(
            call, lambda governed: dispatch(governed["tool"], governed["args"]))
        if guard.audit:
            guard.audit(decision)
        if executed:
            content = str(out)
        else:
            content = (f"BLOCKED by governance [{decision.layer}] "
                       f"{decision.verdict}: {decision.reason}")
        results.append({"role": "tool", "tool_call_id": _tc_id(tc),
                        "content": content})
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
    guard: GovernanceGuard, content: Iterable[Any]
) -> tuple[list[AuthorizedCall], list[dict]]:
    """Given the content blocks of a Claude assistant message, return
    (authorized_calls, tool_result_blocks_for_denied).

    As with the OpenAI batch adapter, blocks are authorised through the kernel
    in order so the batch is one trajectory, and the permitted half comes back
    as `AuthorizedCall` objects that must be redeemed through
    `guard.execute_authorized` rather than dispatched directly.

    The denied list is ready to send back to the API as `tool_result` content
    with `is_error=True`.
    """
    kernel = guard._require_kernel("claude_filter_tool_use")
    authorized: list[AuthorizedCall] = []
    denied_results: list[dict] = []
    for block in content:
        btype = block.get("type") if isinstance(block, dict) else getattr(
            block, "type", None)
        if btype != "tool_use":
            continue
        call = _claude_block_to_dict(block)
        decision = kernel.authorize(call)
        if guard.audit:
            guard.audit(decision)
        if decision.permitted:
            authorized.append(AuthorizedCall(call, decision, block))
        else:
            tu_id = block.get("id") if isinstance(block, dict) else getattr(
                block, "id", None)
            denied_results.append({
                "type": "tool_result",
                "tool_use_id": tu_id,
                "is_error": True,
                "content": f"Blocked by Morrison governance "
                           f"[{decision.layer}] {decision.verdict}: "
                           f"{decision.reason}",
            })
    return authorized, denied_results


def claude_guarded_dispatch(
    guard: GovernanceGuard, content: Iterable[Any],
    dispatch: Callable[[str, dict], Any],
) -> list[dict]:
    """Authorize and execute a Claude tool-use message, returning tool_result
    blocks for both halves. The direct analogue of `openai_guarded_dispatch`."""
    kernel = guard._require_kernel("claude_guarded_dispatch")
    blocks: list[dict] = []
    for block in content:
        btype = block.get("type") if isinstance(block, dict) else getattr(
            block, "type", None)
        if btype != "tool_use":
            continue
        call = _claude_block_to_dict(block)
        tu_id = block.get("id") if isinstance(block, dict) else getattr(
            block, "id", None)
        decision, executed, out = kernel.submit(
            call, lambda governed: dispatch(governed["tool"], governed["args"]))
        if guard.audit:
            guard.audit(decision)
        blocks.append({
            "type": "tool_result", "tool_use_id": tu_id,
            "is_error": not executed,
            "content": str(out) if executed else (
                f"Blocked by Morrison governance [{decision.layer}] "
                f"{decision.verdict}: {decision.reason}"),
        })
    return blocks


# ─────────────────────────────────────────────────────────────
# LangChain
# ─────────────────────────────────────────────────────────────

def govern_langchain_tool(guard: GovernanceGuard, tool: Any) -> Any:
    """Wrap a LangChain tool so every invocation runs through the kernel.

    Works with objects exposing `.name` and one of `func` / `_run` / `run` /
    `invoke`. The wrapped callable does not run the original and then record a
    verdict: the original is invoked BY the kernel, as the executor of an
    authorised decision, so a refusal means it was never called.
    """
    name = getattr(tool, "name", getattr(tool, "__name__", "unknown"))
    guard._require_kernel("govern_langchain_tool")

    for attr in ("func", "_run", "run", "invoke"):
        original = getattr(tool, attr, None)
        if original is None or not callable(original):
            continue

        def gated(*args, __orig=original, **kwargs):
            payload = kwargs if kwargs else (args[0] if args else {})
            return _govern_callable(guard, name, payload, __orig, args, kwargs)

        try:
            setattr(tool, attr, gated)
        except (AttributeError, TypeError):
            # Pydantic v2 tools may forbid attribute assignment; fall back
            # to wrapping the callable the caller will actually invoke.
            return _CallableToolProxy(tool, name, guard, original)
        return tool
    return tool


def _govern_callable(guard: GovernanceGuard, name: str, payload: Any,
                     original: Callable, args: tuple, kwargs: dict) -> Any:
    """Run `original` only as the executor of a kernel-authorised decision."""
    decision, executed, out = guard.dispatch(
        name, payload if isinstance(payload, dict) else {"_positional": payload},
        lambda _governed: original(*args, **kwargs))
    if not executed:
        raise GovernanceError(decision)
    return out


class _CallableToolProxy:
    """Last-resort wrapper for immutable tool objects."""

    def __init__(self, tool, name, guard, original):
        self._tool, self.name, self._guard, self._orig = (
            tool, name, guard, original)

    def __call__(self, *a, **kw):
        payload = kw or (a[0] if a else {})
        return _govern_callable(
            self._guard, self.name,
            payload if isinstance(payload, dict) else {"_positional": payload},
            self._orig, a, kw)

    def __getattr__(self, item):
        return getattr(self._tool, item)


class GovernanceCallbackHandler:
    """LangChain-style callback handler. Plug into callbacks=[...]; raises
    GovernanceError from on_tool_start for a blocked tool.

    A callback fires alongside the framework's own execution rather than in
    place of it, so this handler cannot be the veto — it can only raise early
    enough to stop the chain. Use `govern_langchain_tool` for the real gate and
    treat this as defence in depth.
    """

    def __init__(self, guard: GovernanceGuard):
        self.guard = guard

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
        name = (serialized or {}).get("name", "unknown")
        decision = self.guard.preview(name, {"input": input_str})
        if not decision.permitted:
            raise GovernanceError(decision)
        return decision

    # no-ops so the handler satisfies the callback protocol duck-test
    def on_tool_end(self, *a, **k): pass
    def on_tool_error(self, *a, **k): pass
    def on_chain_start(self, *a, **k): pass
    def on_chain_end(self, *a, **k): pass


# ─────────────────────────────────────────────────────────────
# AutoGen
# ─────────────────────────────────────────────────────────────

def autogen_guard_function_call(
    guard: GovernanceGuard, name: str, arguments: dict
) -> Any:
    """Call from an AutoGen function-execution hook. Raises (fail closed) on a
    non-PERMIT verdict when guard.on_block == 'raise'.

    Returns the reserving Decision, which the caller must redeem through
    `guard.execute_authorized`; a hook that only inspects the verdict and then
    calls the function itself is an ungoverned path. Prefer
    `register_autogen_guard`, which wires the kernel in as the executor.
    """
    return guard.authorize(name, arguments)


def register_autogen_guard(agent: Any, guard: GovernanceGuard) -> Any:
    """Wrap every function registered on an AutoGen ConversableAgent's
    `function_map` so the kernel executes it."""
    guard._require_kernel("register_autogen_guard")
    fmap = getattr(agent, "function_map", None)
    if not isinstance(fmap, dict):
        return agent
    for fname, fn in list(fmap.items()):
        def wrapped(*args, __fn=fn, __n=fname, **kwargs):
            payload = kwargs or (args[0] if args else {})
            return _govern_callable(
                guard, __n,
                payload if isinstance(payload, dict) else {"_positional": payload},
                __fn, args, kwargs)
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


def _browser_call(action: str, target: str = "", value: Any = None) -> tuple[str, dict]:
    tool = BROWSER_ACTION_TOOL.get(action, f"browser_{action}")
    args: dict = {"target": target}
    if value is not None:
        args["value"] = value
    if action in ("submit", "upload", "download"):
        args["url"] = target
    return tool, args


def browser_action_guard(
    guard: GovernanceGuard, action: str, target: str = "", value: Any = None
) -> Any:
    """Authorize a single browser-agent action through the kernel.

    Returns the reserving Decision. Use `browser_guarded_action` when the
    adapter should also perform the action.
    """
    tool, args = _browser_call(action, target, value)
    return guard.authorize(tool, args)


def browser_guarded_action(
    guard: GovernanceGuard, action: str, performer: Callable[[dict], Any],
    target: str = "", value: Any = None,
) -> tuple[Any, bool, Any]:
    """Authorize and perform one browser action through the kernel."""
    tool, args = _browser_call(action, target, value)
    return guard.dispatch(tool, args, performer)


# ─────────────────────────────────────────────────────────────
# MCP servers
# ─────────────────────────────────────────────────────────────

def mcp_guard_call_tool(
    guard: GovernanceGuard, name: str, arguments: dict
) -> Any:
    """Authorize at the top of an MCP server's call_tool handler.

    Prefer `wrap_mcp_call_tool`, which makes the kernel the caller of the
    handler rather than trusting the handler to honour a verdict.
    """
    return guard.authorize(name, arguments or {})


def wrap_mcp_call_tool(guard: GovernanceGuard, call_tool: Callable) -> Callable:
    """Decorate an MCP `call_tool(name, arguments)` coroutine/function so the
    kernel executes it. Supports both sync and async handlers.

    The async wrapper authorises, then awaits the handler, then commits the
    reservation — `kernel.execute` takes a synchronous executor, so the commit
    is explicit here rather than implicit. A refusal returns before the handler
    is awaited.
    """
    import asyncio
    import functools

    kernel = guard._require_kernel("wrap_mcp_call_tool")

    if asyncio.iscoroutinefunction(call_tool):
        @functools.wraps(call_tool)
        async def _aw(name, arguments=None, *a, **kw):
            decision = guard.authorize(name, arguments or {})
            if not decision.permitted:
                raise GovernanceError(decision)
            try:
                result = await call_tool(name, arguments, *a, **kw)
            except Exception:
                kernel.release(decision)
                raise
            kernel.record_remote_execution(decision)
            return result
        return _aw

    @functools.wraps(call_tool)
    def _sw(name, arguments=None, *a, **kw):
        decision, executed, out = guard.dispatch(
            name, arguments or {},
            lambda _governed: call_tool(name, arguments, *a, **kw))
        if not executed:
            raise GovernanceError(decision)
        return out
    return _sw


# ─────────────────────────────────────────────────────────────
# Shell execution
# ─────────────────────────────────────────────────────────────

def governed_run(
    guard: GovernanceGuard, command: Any,
    runner: Optional[Callable] = None, tool: str = "shell", **kwargs
):
    """Authorize a shell command, then execute it as the kernel's executor.

    The command never spawns if governance refuses it, and the spawn happens
    inside `kernel.execute` rather than after a verdict the caller could ignore.
    Tool-name synonyms are resolved to one family before classification, so
    passing `tool="run_shell"` does not change the decision.
    """
    text = command if isinstance(command, str) else " ".join(map(str, command))

    def _spawn(_governed: dict):
        run = runner
        if run is None:
            import subprocess
            run = subprocess.run
        return run(command, **kwargs)

    decision, executed, out = guard.dispatch(tool, {"cmd": text}, _spawn)
    if not executed:
        raise GovernanceError(decision)
    return out


# ─────────────────────────────────────────────────────────────
# Enterprise workflows (multi-step DAG / pipeline)
# ─────────────────────────────────────────────────────────────

@dataclass
class WorkflowGovernor:
    """Governs a multi-step workflow.

    `submit` is REASONING: it asks the layer whether the plan as a whole is
    admissible, before anything is authorised. `run` is the VETO: it authorises
    and executes each step through the kernel, in order, so every step is
    decided against what the previous steps actually did.

    Planning ahead does not authorise anything, and a plan that passes `submit`
    is still refused step by step if it turns out unsafe in execution.
    """

    guard: GovernanceGuard

    def submit(self, steps: list[dict]) -> GovernanceResult:
        """Evaluate the entire workflow up-front. Advisory; authorises nothing."""
        return self.guard.check_plan(steps)

    def step_gate(self, step: dict, history: Optional[list[dict]] = None
                  ) -> Any:
        """Authorize one step through the kernel.

        `history` is accepted for call-site compatibility and ignored: the
        kernel holds the real session trajectory, including reserved-but-not-
        yet-executed steps, which a caller-supplied history cannot know about.
        """
        return self.guard.authorize(step["tool"], step.get("args", {}))

    def run(self, steps: list[dict], executor: Callable[[dict], Any],
            stop_on_block: bool = True) -> list[tuple[Any, bool, Any]]:
        """Authorize and execute each step in order through the kernel."""
        outcomes: list[tuple[Any, bool, Any]] = []
        for step in steps:
            decision, executed, out = self.guard.dispatch(
                step["tool"], step.get("args", {}), executor)
            outcomes.append((decision, executed, out))
            if not executed and stop_on_block:
                break
        return outcomes
