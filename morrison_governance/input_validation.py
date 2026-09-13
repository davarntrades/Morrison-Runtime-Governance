"""
Shape validation for governance input, and the refusal verdict it produces.

WHY THIS MODULE EXISTS
──────────────────────
`TrajectoryExtractor` is deliberately permissive: it accepts several vendor
shapes and normalises them into one internal form. That normalisation cannot
fail, and that is the defect documented in INPUT_VALIDATION_FAILURE_REPORT.md.
A missing tool name becomes the string `"unknown"`; unparseable string args
become `{"raw": ...}`. Both substitutes are indistinguishable from real values
by the time the Ω rules run, so the hierarchy evaluates a call the caller never
made and reports the only thing it can: nothing reached Ω.

The fix is not to make the extractor strict — its tolerance is load-bearing for
the adapters, and `{"tool": "shell", "args": "ls -la"}` is a SUPPORTED form
that must keep permitting. The fix is to decide, *before* extraction, whether
the input can be faithfully represented at all, and to refuse it explicitly
when it cannot.

REASON STRINGS ARE EVIDENCE
───────────────────────────
Every reason returned here can end up in an immutable evidence record. So no
validator interpolates user input with `!r`: that would execute an
attacker-controlled `__repr__` inside the audit path, and would persist raw
values that a digest already distinguishes. Reasons carry the type and the
value-free structural shape; `evidence_fingerprint.input_digest` carries the
identity.

MIRRORING, NOT REIMPLEMENTING
─────────────────────────────
The validators resolve `tool` and `args` using the same key precedence the
extractor uses, so validation judges the value extraction will actually
produce. This matters for shapes like `{"tool": None, "name": "transfer"}`,
where `.get("tool", <fallback>)` returns None because the key is *present*,
and the `name` fallback never runs. A validator that merely looked for "some
tool-ish key" would pass that call and let the extractor turn it into
something else.

The precedences differ between extractors and that difference is preserved:
`from_dict` accepts `function` as a tool alias, `from_plan` does not.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Optional

from morrison_governance.evidence_fingerprint import structural_shape

# Layer labels for refusals. Deliberately not Ω layer names ("A_safe", "V2",
# …): a refusal must be distinguishable from a finding in logs and audit, and
# no `omega_domain` is ever set on one.
UNEVALUABLE_INPUT_LAYER = "unevaluable_input"
UNEVALUABLE_RULE_LAYER = "unevaluable_rule"

# Key precedence, mirroring trajectory.py.
_DICT_TOOL_KEYS = ("tool", "name", "function")
_PLAN_TOOL_KEYS = ("tool", "name")
_ARGS_KEYS = ("args", "arguments", "input")

_MISSING = object()


class UnevaluableInput(ValueError):
    """Raised by offline analysis surfaces that have no verdict to return.

    `evaluate()` and friends gate execution, so they refuse with a BLOCK
    verdict. `adversarial_test()` and `estimate_robustness()` do not gate
    anything — they return reports — so there is no verdict for them to carry
    a refusal in. They raise this instead.

    This is the opposite of swallowing the error: it is a typed, deliberate
    refusal naming what could not be evaluated, rather than the incidental
    `AttributeError: 'int' object has no attribute 'upper'` that used to
    surface from wherever the bad value was first touched.
    """


class RuleEvaluationError(RuntimeError):
    """An Ω rule or admissibility check raised while being evaluated.

    Carries the failing predicate's name, so the resulting refusal can say
    which guard broke. Without that, a fail-closed BLOCK is unmaintainable:
    the operator cannot tell a real Ω violation from a crashed rule.
    """

    def __init__(self, rule_name: str, cause: BaseException):
        self.rule_name = rule_name
        self.cause = cause
        super().__init__(
            f"Ω rule {rule_name!r} raised "
            f"{type(cause).__name__}: {cause}"
        )


# ─────────────────────────────────────────────────────────────
# Resolution — mirrors the extractor
# ─────────────────────────────────────────────────────────────

def _resolve(call: Mapping, keys: Sequence[str], default: Any) -> Any:
    """Nested-`.get` fallback, exactly as the extractor spells it.

    `{"tool": None}` resolves to None, NOT to the next alias, because the key
    is present. That is the extractor's behaviour and validation must agree
    with it rather than be more charitable.
    """
    for key in keys:
        if key in call:
            return call[key]
    return default


def resolve_tool(call: Mapping, *, plan: bool = False) -> Any:
    keys = _PLAN_TOOL_KEYS if plan else _DICT_TOOL_KEYS
    return _resolve(call, keys, _MISSING)


def resolve_args(call: Mapping) -> Any:
    return _resolve(call, _ARGS_KEYS, {})


# ─────────────────────────────────────────────────────────────
# Validators. Each returns None when the input is evaluable, or a
# human-readable reason when it is not.
# ─────────────────────────────────────────────────────────────

def _validate_tool_name(tool: Any) -> Optional[str]:
    if tool is _MISSING:
        return ("no tool name: none of 'tool', 'name' or 'function' is "
                "present, and the extractor would substitute the sentinel "
                "\"unknown\", which matches no Ω rule")
    if isinstance(tool, bool) or not isinstance(tool, str):
        return (f"tool name is {type(tool).__name__}, not str "
                f"(shape {structural_shape(tool)}) — rule predicates perform "
                f"string operations on the tool name and silently fail to "
                f"match a non-string")
    if not tool.strip():
        return "tool name is empty"
    return None


def _validate_args(args: Any) -> Optional[str]:
    # A bare string is a SUPPORTED shape, not a malformed one: the extractor
    # json-parses it and falls back to {"raw": <string>}, and
    # test_hardening_v041.py::test_no_false_positive_plain_single_step pins
    # {"tool": "shell", "args": "ls -la"} as PERMIT. Rejecting it here broke
    # three pre-existing tests in an earlier attempt at this fix.
    if isinstance(args, str):
        return None
    if not isinstance(args, Mapping):
        return (f"args is {type(args).__name__}, not a mapping or string "
                f"(shape {structural_shape(args)})")
    # The rules flatten args into the eval dict and the trajectory hash
    # serialises them. A value that cannot be serialised makes the call
    # unrepresentable, and currently raises from inside hashing.
    try:
        json.dumps(args, default=None)
    except (TypeError, ValueError) as exc:
        return f"args is not JSON-serialisable: {exc}"
    return None


def validate_tool_call(call: Any, *, plan: bool = False,
                       where: str = "tool call") -> Optional[str]:
    """Validate one raw tool-call mapping."""
    if not isinstance(call, Mapping):
        return (f"{where} is {type(call).__name__}, not a mapping "
                f"(shape {structural_shape(call)})")
    reason = _validate_tool_name(resolve_tool(call, plan=plan))
    if reason is not None:
        return f"{where}: {reason}"
    reason = _validate_args(resolve_args(call))
    if reason is not None:
        return f"{where}: {reason}"
    return None


def validate_plan(steps: Any) -> Optional[str]:
    """Validate a multi-step plan.

    An EMPTY plan is valid and is not a refusal: a well-formed empty plan
    proposes nothing, so there is nothing to block. That is the one case where
    "nothing reached Ω" is an honest answer, and it is kept distinct from the
    silent-drop cases in the adapters below.
    """
    if isinstance(steps, (str, bytes)) or not isinstance(steps, Sequence):
        return (f"plan is {type(steps).__name__}, not a sequence of steps "
                f"(shape {structural_shape(steps)})")
    for i, step in enumerate(steps):
        reason = validate_tool_call(step, plan=True, where=f"plan step {i}")
        if reason is not None:
            return reason
    return None


def validate_openai_tool_calls(tool_calls: Any) -> Optional[str]:
    """Validate an OpenAI-shaped tool-call list.

    `from_openai` builds its steps with an if/elif and no else: an item
    matching neither branch is DISCARDED. The extractor then returns a shorter
    trajectory — possibly an empty one — and an empty trajectory permits. A
    caller who submitted one unparseable tool call otherwise receives the same
    PERMIT as a caller who submitted nothing at all.

    An empty list is left alone, and the semantics are explicitly:

        "zero proposed actions, therefore there is nothing to withhold
         authority from"

    and NOT "an attempted action disappeared and was treated as empty". The
    distinction is enforced by ordering: validation runs BEFORE extraction, so
    a parse failure is refused and can never arrive at the empty-trajectory
    path to inherit its PERMIT. A batch containing one unparseable item is
    refused as a batch rather than evaluated as the remaining N-1, because a
    verdict on a plan the caller did not submit is not a verdict on their plan.

    FUTURE DESIGN OPTION (deliberately not taken here): the verdict model has
    no NOOP/EMPTY member, so "nothing was proposed" and "something was
    proposed and is allowed" both surface as PERMIT. A distinct no-op result
    would let a caller tell those apart without inspecting the input. That is
    a change to the public verdict model and is out of scope for this fix.
    """
    if isinstance(tool_calls, (str, bytes)) or not isinstance(tool_calls, Sequence):
        return (f"openai tool_calls is {type(tool_calls).__name__}, not a "
                f"sequence (shape {structural_shape(tool_calls)})")
    for i, tc in enumerate(tool_calls):
        where = f"openai tool_call {i}"
        if hasattr(tc, "function"):
            fn = tc.function
            reason = _validate_tool_name(getattr(fn, "name", _MISSING))
            if reason is not None:
                return f"{where}: {reason}"
            args = getattr(fn, "arguments", {})
            reason = _validate_args(args)
            if reason is not None:
                return f"{where}: {reason}"
            continue
        if isinstance(tc, Mapping):
            func = tc.get("function", {})
            if isinstance(func, Mapping) and "name" in func:
                tool, args = func["name"], func.get("arguments", {})
            else:
                tool = tc.get("name", _MISSING)
                args = tc.get("args", {})
            reason = _validate_tool_name(tool)
            if reason is not None:
                return f"{where}: {reason}"
            reason = _validate_args(args)
            if reason is not None:
                return f"{where}: {reason}"
            continue
        return (f"{where} matches neither the OpenAI tool-call object shape "
                f"nor a mapping ({type(tc).__name__}) and would be silently "
                f"discarded by the extractor")
    return None


def validate_langchain_actions(actions: Any) -> Optional[str]:
    """Validate LangChain AgentAction(s).

    Same silent-drop path as `validate_openai_tool_calls`: `from_langchain`
    has an if/elif with no else. A single action is wrapped in a list by the
    extractor, so it is wrapped here too.
    """
    if not isinstance(actions, list):
        actions = [actions]
    for i, action in enumerate(actions):
        where = f"langchain action {i}"
        if hasattr(action, "tool") and hasattr(action, "tool_input"):
            reason = _validate_tool_name(getattr(action, "tool", _MISSING))
            if reason is not None:
                return f"{where}: {reason}"
            reason = _validate_args(getattr(action, "tool_input", {}))
            if reason is not None:
                return f"{where}: {reason}"
            continue
        if isinstance(action, Mapping):
            reason = _validate_tool_name(action.get("tool", _MISSING))
            if reason is not None:
                return f"{where}: {reason}"
            args = action.get("tool_input", action.get("args", {}))
            reason = _validate_args(args)
            if reason is not None:
                return f"{where}: {reason}"
            continue
        return (f"{where} matches neither the LangChain AgentAction shape nor "
                f"a mapping ({type(action).__name__}) and would be silently "
                f"discarded by the extractor")
    return None


def validate_trajectory(trajectory: Any) -> Optional[str]:
    """Validate an ALREADY-EXTRACTED trajectory.

    This is the backstop for callers that build a `Trajectory` themselves and
    call `evaluate_trajectory()` directly — which is how the production kernel
    submits work, since it supplies trusted state as trajectory context.

    It deliberately checks less than the raw-input validators. By this point
    normalisation has already run, so a missing tool name is indistinguishable
    from a tool genuinely called "unknown" — and `integrations.py` produces
    that sentinel legitimately in half a dozen adapters. Rejecting it here
    would break working integrations to catch a case the raw-input validators
    already catch upstream. What remains checkable is structural: the tool
    must be a non-empty string and the args must be a representable mapping.
    """
    states = getattr(trajectory, "states", None)
    if states is None:
        return (f"trajectory is {type(trajectory).__name__}, which exposes no "
                f"states")
    for state in states:
        tool = getattr(state, "tool", _MISSING)
        if isinstance(tool, bool) or not isinstance(tool, str) or not tool.strip():
            return (f"trajectory step {getattr(state, 'step', '?')}: tool is "
                    f"{type(tool).__name__} (shape {structural_shape(tool)}), "
                    f"not a non-empty string")
        reason = _validate_args(getattr(state, "args", {}))
        if reason is not None:
            return f"trajectory step {getattr(state, 'step', '?')}: {reason}"
    return None
