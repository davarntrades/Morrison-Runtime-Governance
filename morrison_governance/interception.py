"""
Fail-closed interception harness + cross-model planner seam.

A drop-in middleware that sits in the planner → runtime loop. Every
proposed tool call is evaluated by the governance layer BEFORE the
runtime sees it. The contract is deny-by-default:

  * verdict is not PERMIT          → call dropped, recorded, not executed
  * governance path raises         → call dropped (fail-closed, NOT
                                       fail-open) — a broken guard must
                                       never become an open door
  * runtime raises after a PERMIT  → surfaced, loop stops

The model is not the safety system. To prove that, the planner is an
adapter behind a stable protocol. Offline deterministic backends stand in
for GPT- / Claude- / Qwen- / Llama- / DeepSeek-style planners (reusing the
structural planner profiles). A real client is wired by passing a
callable to `CallableModelPlanner` — no provider SDK is imported here, so
the harness stays dependency-free and deterministic in tests.

Determinism: offline planners/runtime have no RNG, clock, or I/O. Same
(planner, runtime, observation, max_steps) → same transcript.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, runtime_checkable

from morrison_governance.core import GovernanceLayer
from morrison_governance.planners import PLANNER_PROFILES


# ─────────────────────────────────────────────────────────────
# Adapters
# ─────────────────────────────────────────────────────────────

@runtime_checkable
class PlannerAdapter(Protocol):
    """Proposes the next batch of tool calls given an observation and the
    executed history. Implementations must be side-effect free."""

    def propose(self, observation: dict, history: list) -> list: ...


@runtime_checkable
class ToolRuntime(Protocol):
    """Executes a permitted tool call and returns an observation."""

    def execute(self, call: dict) -> dict: ...


@dataclass
class ScriptedPlanner:
    """Emits a fixed plan, one batch per turn. Deterministic stand-in for
    any planner — the harness asserts the *governance* verdict, not the
    plan's origin."""

    script: list
    _i: int = 0

    def propose(self, observation: dict, history: list) -> list:
        if self._i >= len(self.script):
            return []
        batch = self.script[self._i]
        self._i += 1
        return batch if isinstance(batch, list) else [batch]


@dataclass
class ModelPlanner:
    """Offline cross-model planner: takes a base plan and renders it
    through a named structural planner profile (gpt/claude/qwen/llama/
    stochastic) — surface structure differs, intent does not. This is the
    seam where a live model would plug in; here it is deterministic."""

    base_plan: list
    profile: str = "gpt_style"
    seed: int = 0
    _done: bool = False

    def propose(self, observation: dict, history: list) -> list:
        if self._done:
            return []
        self._done = True
        transform = PLANNER_PROFILES[self.profile]
        return transform(self.base_plan, self.seed)


@dataclass
class CallableModelPlanner:
    """Live-seam adapter. `fn(observation, history) -> list[dict]` is the
    ONLY place a real provider client (Anthropic / OpenAI / Qwen / Llama /
    DeepSeek) is invoked. The harness governs whatever it returns; a
    misbehaving or compromised model cannot widen what executes because
    interception is downstream and fail-closed."""

    fn: Callable[[dict, list], list]

    def propose(self, observation: dict, history: list) -> list:
        out = self.fn(observation, history)
        return list(out) if out else []


@dataclass
class RecordingRuntime:
    """Offline runtime: records executed calls, returns a stub observation.
    Optionally raises for a tool name to exercise post-permit failure."""

    raise_on: tuple = ()
    executed: list = field(default_factory=list)

    def execute(self, call: dict) -> dict:
        tool = call.get("tool")
        if tool in self.raise_on:
            raise RuntimeError(f"runtime failure in {tool}")
        self.executed.append(call)
        return {"ok": True, "tool": tool, "n": len(self.executed)}


# ─────────────────────────────────────────────────────────────
# Transcript
# ─────────────────────────────────────────────────────────────

@dataclass
class InterceptedCall:
    step: int
    call: dict
    verdict: str
    layer: str
    reason: str
    executed: bool


@dataclass
class InterceptionTranscript:
    calls: list = field(default_factory=list)
    runtime_error: Optional[str] = None

    @property
    def executed(self) -> list:
        return [c.call for c in self.calls if c.executed]

    @property
    def blocked(self) -> list:
        return [c for c in self.calls if not c.executed]

    @property
    def fail_closed_holds(self) -> bool:
        """Safety invariant: anything that executed was PERMIT (one-way).
        A permitted call that then hit a runtime error simply did not
        execute — that does not violate fail-closed; only a non-PERMIT
        call executing would."""
        return all((not c.executed) or c.verdict == "PERMIT"
                   for c in self.calls)

    def summary(self) -> dict:
        return {
            "total": len(self.calls),
            "executed": len(self.executed),
            "blocked": len(self.blocked),
            "fail_closed": self.fail_closed_holds,
            "runtime_error": self.runtime_error,
        }


# ─────────────────────────────────────────────────────────────
# Interceptor
# ─────────────────────────────────────────────────────────────

class GovernanceInterceptor:
    """Wraps a planner→runtime loop with pre-execution governance."""

    def __init__(self, governance: GovernanceLayer):
        self.governance = governance

    def check(self, call: dict):
        """Single-call gate. Returns (allowed, verdict, layer, reason).
        Any exception in the governance path is converted to a closed
        gate — the guard fails safe, never open."""
        return self.check_prefix([], call)

    def check_prefix(self, history: list, call: dict):
        """Prefix-aware gate. A call is permitted only if the WHOLE
        executed-so-far trajectory plus this call stays out of Ω. This is
        the correct fail-closed semantics for a streamed plan: a benign
        read on turn 1 followed by an egress on turn 2 is one trajectory,
        and isolated per-call checks would wave both through. Any
        exception in the governance path is converted to a closed gate."""
        try:
            prefix = list(history) + [call]
            r = (self.governance.evaluate_plan(prefix) if len(prefix) > 1
                 else self.governance.evaluate(prefix[0]))
            return (r.permitted, r.verdict.value, r.layer, r.reason)
        except Exception as e:  # noqa: BLE001 — fail-closed is the point
            return (False, "BLOCK", "fail_closed",
                    f"governance error treated as BLOCK: {type(e).__name__}")

    def run(self, planner: PlannerAdapter, runtime: ToolRuntime,
            observation: Optional[dict] = None,
            max_steps: int = 16) -> InterceptionTranscript:
        """Drive the loop. Permitted calls are executed; everything else is
        dropped and recorded. Runtime errors stop the loop but never
        retroactively permit a blocked call."""
        transcript = InterceptionTranscript()
        obs = observation or {}
        history: list = []
        step = 0
        for _ in range(max_steps):
            batch = planner.propose(obs, history)
            if not batch:
                break
            for call in batch:
                allowed, verdict, layer, reason = self.check_prefix(
                    history, call)
                rec = InterceptedCall(step, dict(call), verdict, layer,
                                      reason, executed=False)
                if allowed:
                    try:
                        obs = runtime.execute(call)
                    except Exception as e:  # noqa: BLE001
                        transcript.runtime_error = (
                            f"{type(e).__name__}: {e}")
                        transcript.calls.append(rec)
                        return transcript
                    rec.executed = True
                    history.append(call)
                transcript.calls.append(rec)
                step += 1
        return transcript
