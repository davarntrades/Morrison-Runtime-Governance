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
from runtime_eval.governance.hardening import (
    HardeningPipeline, HardeningResult,
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
    """Drive a planner→governance→sandbox loop with full audit.

    `hardening` is an OPTIONAL pre-governance pipeline (payload
    decoding, semantic lifting, recursive-coercion flattening, schema
    validation, risk propagation). When None, behaviour is exactly the
    pre-hardening prefix-aware fail-closed contract."""

    def __init__(self, governance: GovernanceLayer,
                 sandbox: SandboxExecutor,
                 hardening: Optional[HardeningPipeline] = None):
        self.governance = governance
        self.sandbox = sandbox
        self.hardening = hardening

    # ── single-call gate ─────────────────────────────────────
    def _evaluate_prefix(self, history: list, call_or_calls):
        """Prefix-aware evaluation. Accepts a single call OR a list of
        peer calls (sub-calls from recursive coercion are evaluated as
        peers in the same trajectory prefix). Wrapped in try/except to
        enforce fail-closed semantics."""
        if isinstance(call_or_calls, dict):
            extension = [call_or_calls]
        else:
            extension = list(call_or_calls)
        plan = list(history) + extension
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

            # ── opt-in hardening pipeline ───────────────────
            hardening_out: Optional[HardeningResult] = None
            evaluation_target = call
            if self.hardening is not None:
                hardening_out = self.hardening.apply(call, history)
                if hardening_out.early_reject:
                    rec = DecisionRecord(
                        step=step_idx, planner=planner.info.name,
                        proposed=dict(call),
                        verdict="BLOCK", layer="hardening",
                        rule="hardening_reject",
                        reason=hardening_out.reject_reason,
                        latency_ms=(time.perf_counter() - t0) * 1000.0,
                        schema_violations=(hardening_out.schema.violations
                                           if hardening_out.schema else []),
                    )
                    decisions.append(rec)
                    continue
                # the lifted + decoded call is what the reachability
                # hierarchy sees; sub-calls are appended as peers in
                # the prefix so recursion is structurally visible.
                evaluation_target = [hardening_out.augmented_call]
                if hardening_out.sub_calls:
                    evaluation_target = (
                        [hardening_out.augmented_call]
                        + list(hardening_out.sub_calls))

            result, err = self._evaluate_prefix(history, evaluation_target)
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
            if hardening_out is not None:
                rec.decode_steps = (
                    [s.as_dict() for s in hardening_out.decode.steps]
                    if hardening_out.decode else [])
                rec.decoded_extracted = (
                    dict(hardening_out.decode.extracted)
                    if hardening_out.decode else {})
                rec.lifted_capabilities = (
                    list(hardening_out.lift.capabilities)
                    if hardening_out.lift else [])
                rec.lifted_canonical_tool = (
                    hardening_out.lift.canonical_tool
                    if hardening_out.lift else None)
                rec.recursion_depth = (hardening_out.coercion.max_depth
                                        if hardening_out.coercion else 0)
                rec.sub_calls_expanded = list(hardening_out.sub_calls)
                rec.schema_violations = (
                    list(hardening_out.schema.violations)
                    if hardening_out.schema else [])
                if hardening_out.risk is not None:
                    rec.cumulative_risk = hardening_out.risk.max_cumulative
                    rec.step_risk = (hardening_out.risk.per_step[-1]
                                      if hardening_out.risk.per_step else 0.0)
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
