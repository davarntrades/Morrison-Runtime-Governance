"""Planner abstraction. A Planner proposes the next batch of tool calls
given an observation and the history of executed calls. Everything else
in the harness — the governance middleware, the sandbox, the replay
writer — speaks only this protocol, so live HF planners,
high-throughput vLLM planners, and deterministic offline stand-ins are
interchangeable."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


ToolCall = dict   # {"tool": str, "args": dict}


@dataclass
class PlannerInfo:
    """Static descriptor of a planner. The harness uses this to label
    replay traces, fix the random seed, and decide whether a run is
    eligible for byte-identical replay."""

    name: str                       # registry key, e.g. "hf.qwen2_5_7b"
    model_id: str = ""              # HF hub id, vLLM endpoint, or "deterministic"
    family: str = ""                # "qwen" | "llama" | "mistral" | "deepseek" | "phi" | "deterministic"
    deterministic: bool = True      # True iff replay is byte-identical
    temperature: float = 0.0
    max_new_tokens: int = 512
    seed: int = 0
    extras: dict = field(default_factory=dict)


@runtime_checkable
class Planner(Protocol):
    """A Planner produces zero-or-more tool-call dicts each turn.

    Contract:
      - propose() MUST be side-effect free except for any internal
        counter the planner keeps to mark progress.
      - propose() returns an EMPTY list when the planner is done.
      - args fields must be JSON-serialisable.
      - When info().deterministic is True, two runs with the same
        observation/history sequence MUST yield byte-identical proposals.
    """

    info: "PlannerInfo"

    def propose(self, observation: dict, history: list[ToolCall]) -> list[ToolCall]: ...
