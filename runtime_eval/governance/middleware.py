"""RuntimeGovernanceMiddleware — the main loop.

Sits between a Planner and a Sandbox. Every proposed tool call is
evaluated as `history + [call]` (prefix-aware) through the existing
morrison_governance hierarchy (A_safe → V2 → V3 → V4 → V4+ → V5 → V5+).
PERMIT calls are passed to the sandbox; everything else is denied
and recorded. Any exception from the governance path is converted to
BLOCK (fail-closed).

This is the same prefix-aware contract as
morrison_governance.interception.GovernanceInterceptor; this module
wraps it with planner/sandbox lifecycle, structured tracing, and
latency measurement."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer
from runtime_eval.governance.decision_trace import (
    DecisionRecord, DecisionTrace,
)
from runtime_eval.planners.base import Planner, ToolCall
from runtime_eval.sandbox.executor import SandboxExecutor


@dataclass
class StepResult:
    proposed: list
    decisions: list                       # list[DecisionRecord]


@dataclass
class RunResult:
    trace: DecisionTrace
    history: list                         # list[ToolCall] actually executed
    runtime_error: Optional[str] = None
    summary: dict = field(default_factory=dict)


class RuntimeGovernanceMiddleware:
    """Drive a planner→governance→sandbox loop with full audit."""

    def __init__(self, governance: GovernanceLayer,
                 sandbox: SandboxExecutor):
        self.governance = governance
        self.sandbox = sandbox

    # ── single-call gate ─────────────────────────────────────
    def _evaluate_prefix(self, history: list, call: ToolCall):
        """Prefix-aware evaluation. Returns the morrison_governance
        result. Wrapped in try/except to enforce fail-closed semantics
        without leaking the exception to the caller."""
        plan = list(history) + [call]
        try:
            if len(plan) > 1:
                return self.governance.evaluate_plan(plan), None
            return self.governance.evaluate(plan[0]), None
        except Exception as e:                       # noqa: BLE001
            return None, f"{type(e).__name__}: {e}"

    # ── one turn ─────────────────────────────────────────────
    def step(self, planner: Planner, observation: dict,
             history: list[ToolCall], step_idx: int) -> StepResult:
        proposed = planner.propose(observation, history)
        decisions: list[DecisionRecord] = []
        for call in proposed:
            t0 = time.perf_counter()
            result, err = self._evaluate_prefix(history, call)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if err is not None:
                rec = DecisionRecord(
                    step=step_idx, planner=planner.info.name,
                    proposed=dict(call),
                    verdict="BLOCK", layer="fail_closed",
                    reason=f"governance error treated as BLOCK: {err}",
                    latency_ms=elapsed_ms)
                decisions.append(rec)
                continue
            rec = DecisionRecord(
                step=step_idx, planner=planner.info.name,
                proposed=dict(call),
                verdict=result.verdict.value,
                layer=result.layer,
                rule=(result.metadata or {}).get("rule"),
                omega_domain=result.omega_domain,
                reason=result.reason,
                trajectory_hash=result.trajectory_hash,
                reachability_distance=result.reachability_distance,
                metadata=dict(result.metadata or {}),
                latency_ms=elapsed_ms)
            if result.permitted:
                try:
                    self.sandbox.execute(call)
                    rec.executed = True
                    history.append(dict(call))
                except Exception as e:               # noqa: BLE001
                    rec.runtime_error = f"{type(e).__name__}: {e}"
            decisions.append(rec)
        return StepResult(proposed=proposed, decisions=decisions)

    # ── full run ─────────────────────────────────────────────
    def run(self, planner: Planner, observation: Optional[dict] = None,
            max_steps: int = 16) -> RunResult:
        trace = DecisionTrace()
        history: list[ToolCall] = []
        obs = observation or {}
        runtime_error: Optional[str] = None
        for step_idx in range(max_steps):
            sr = self.step(planner, obs, history, step_idx)
            for rec in sr.decisions:
                trace.append(rec)
                if rec.runtime_error:
                    runtime_error = rec.runtime_error
            if not sr.proposed:
                break
            # surface the most recent observation from the sandbox if any
            obs = self.sandbox.last_observation() or obs
            if runtime_error:
                break
        return RunResult(
            trace=trace, history=history, runtime_error=runtime_error,
            summary=trace.summary())
