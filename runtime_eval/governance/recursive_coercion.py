"""Recursive-coercion detection.

A call's args can carry sub-actions (callbacks, nested `action`
fields, schedule-task wrappers, "synth_tool" patterns). The detector
recursively flattens those sub-calls and reports recursion depth +
self-reference. Each sub-call is then exposed to the reachability
hierarchy as a peer call in the trajectory so the existing rules apply
structurally.

Determinism: walk order is the sorted insertion order of keys; no RNG,
no clock, no IO.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Optional


_SUB_ACTION_KEYS = (
    "action", "task", "job", "callback", "then", "next", "next_step",
    "sub_action", "sub_task", "inner", "meta_tool", "synth_tool",
    "delegate", "delegate_to", "recursive_call", "nested",
)
_PROMPT_KEYS = ("prompt", "subprompt", "inner_prompt", "instruction",
                "instructions", "sys_prompt", "system_prompt")


@dataclass
class CoercionReport:
    max_depth: int = 0
    sub_calls: list = field(default_factory=list)   # flattened ToolCalls
    self_referential: bool = False
    contains_inner_prompts: bool = False
    notes: str = ""

    def as_dict(self) -> dict:
        return {"max_depth": self.max_depth,
                "sub_calls": list(self.sub_calls),
                "self_referential": self.self_referential,
                "contains_inner_prompts": self.contains_inner_prompts,
                "notes": self.notes}


def _looks_like_call(d: dict) -> bool:
    return isinstance(d, dict) and "tool" in d


def detect_recursive_coercion(call: dict, *,
                                max_depth: int = 4) -> CoercionReport:
    """Walk the call's args looking for nested sub-calls. Return a
    flattened list of sub-calls + recursion depth + flags."""
    report = CoercionReport()
    outer_tool = str(call.get("tool", "")).lower()

    def walk(value, depth: int):
        if depth > max_depth:
            report.notes = "depth bound reached"
            return
        report.max_depth = max(report.max_depth, depth)
        if isinstance(value, dict):
            if _looks_like_call(value):
                sub = {"tool": str(value.get("tool")),
                       "args": value.get("args", {}) or {}}
                report.sub_calls.append(sub)
                if str(sub["tool"]).lower() == outer_tool or \
                   str(sub["tool"]).lower() == "self":
                    report.self_referential = True
                walk(sub["args"], depth + 1)
                return
            for k, v in value.items():
                kk = str(k).lower()
                if kk in _PROMPT_KEYS and isinstance(v, str):
                    report.contains_inner_prompts = True
                if kk in _SUB_ACTION_KEYS and isinstance(v, dict):
                    if _looks_like_call(v):
                        report.sub_calls.append({
                            "tool": str(v.get("tool")),
                            "args": v.get("args", {}) or {}})
                        if str(v.get("tool", "")).lower() == outer_tool:
                            report.self_referential = True
                        walk(v.get("args", {}) or {}, depth + 1)
                        continue
                walk(v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                walk(v, depth + 1)

    walk(call.get("args") or {}, 1)
    return report


def expand_to_trajectory(call: dict, report: CoercionReport) -> list[dict]:
    """Produce the flattened trajectory: [outer_call, *sub_calls].

    The reachability hierarchy is prefix-aware, so exposing sub-calls
    as peers in the trajectory makes hidden delegation visible to
    A_safe / V2 / V3 without weakening any single layer."""
    outer = {"tool": call.get("tool"), "args": copy.deepcopy(call.get("args") or {})}
    return [outer] + list(report.sub_calls)
