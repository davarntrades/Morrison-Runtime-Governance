"""Deterministic planners — run anywhere, no GPU, byte-identical replay.

These exist for three reasons: (1) CI / regression tests against the
middleware without a model dependency, (2) a calibration anchor for
live-planner divergence, (3) replay stand-ins when a recorded
trace must be rerun without the original model."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Callable

from runtime_eval.planners.base import Planner, PlannerInfo, ToolCall
from morrison_governance.planners import PLANNER_PROFILES


# ─────────────────────────────────────────────────────────────
# Scripted — fixed list-of-batches, one per turn
# ─────────────────────────────────────────────────────────────

@dataclass
class ScriptedPlanner:
    """Fixed plan, replayed one batch per turn. The harness uses this
    for end-to-end tests of the middleware contract."""

    script: list                                 # list[batch] where batch = list[ToolCall] or ToolCall
    info: PlannerInfo = field(default_factory=lambda: PlannerInfo(
        name="deterministic.scripted",
        model_id="deterministic",
        family="deterministic",
        deterministic=True,
    ))
    _i: int = 0

    def propose(self, observation: dict, history: list[ToolCall]) -> list[ToolCall]:
        if self._i >= len(self.script):
            return []
        batch = self.script[self._i]
        self._i += 1
        return list(batch) if isinstance(batch, list) else [batch]


# ─────────────────────────────────────────────────────────────
# Profile — apply a structural planner-style transform from
# morrison_governance.planners (gpt/claude/qwen/llama/stochastic). One
# proposal, then done. Useful for cross-model invariance tests without
# a GPU.
# ─────────────────────────────────────────────────────────────

@dataclass
class ProfilePlanner:
    """Apply a deterministic structural planner-style transform to a
    base plan. Stands in for live-model planner diversity."""

    base_plan: list                              # list[ToolCall]
    profile: str = "gpt_style"
    seed: int = 0
    info: PlannerInfo = field(default=None)      # set in __post_init__
    _done: bool = False

    def __post_init__(self):
        if self.info is None:
            self.info = PlannerInfo(
                name=f"deterministic.profile.{self.profile}",
                model_id="deterministic",
                family="deterministic",
                deterministic=True,
                seed=self.seed,
                extras={"profile": self.profile},
            )

    def propose(self, observation: dict, history: list[ToolCall]) -> list[ToolCall]:
        if self._done:
            return []
        self._done = True
        transform = PLANNER_PROFILES[self.profile]
        return transform(copy.deepcopy(self.base_plan), self.seed)


# ─────────────────────────────────────────────────────────────
# Callable — wrap an arbitrary function; the live-seam adapter for
# bring-your-own planners (HF + adapters, vLLM, OpenAI-compatible
# endpoints — note: only Hugging Face endpoints are validated here).
# ─────────────────────────────────────────────────────────────

@dataclass
class CallableModelPlanner:
    """`fn(observation, history) -> list[ToolCall]`. Set
    `deterministic=False` if the callable involves model sampling."""

    fn: Callable[[dict, list], list]
    info: PlannerInfo = field(default_factory=lambda: PlannerInfo(
        name="callable",
        model_id="callable",
        family="callable",
        deterministic=False,
    ))

    def propose(self, observation: dict, history: list[ToolCall]) -> list[ToolCall]:
        out = self.fn(observation, history)
        return list(out) if out else []
