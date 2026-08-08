"""
Multi-agent coordination governance.

Per-agent governance is insufficient: each agent's local tool calls can be
individually safe while the *team* reaches Ω. Agent A acquires sensitive
data, hands it to Agent B over a shared channel, Agent B egresses it.
No single agent's trajectory intersects Ω — the *joint* one does.

This module flattens a multi-agent session into ONE causally-ordered
executable trajectory and governs that. Handoffs become explicit steps so
V2 source→sink taint carries provenance across the agent boundary and
delayed cross-agent privilege chains stay visible.

    Safe(agent_i for all i)  ⇏  Safe(joint_team_trajectory)

Deterministic: causal order is the insertion order of steps/handoffs; no
RNG, no clocks. Same session → same flattened trajectory → same verdict.
"""

# Builtin generic annotations (dict[...], list[...]) below are evaluated
# at definition time and need Python 3.9+. Deferring evaluation keeps the
# syntax while restoring importability on older interpreters.
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from morrison_governance.core import GovernanceLayer
from morrison_governance.result import GovernanceResult


@dataclass
class _Event:
    seq: int
    kind: str            # "step" | "handoff"
    agent: str
    call: dict


@dataclass
class MultiAgentSession:
    """Records ordered actions of a cooperating agent team and governs the
    flattened joint trajectory.

        s = MultiAgentSession(governance)
        s.step("researcher", {"tool": "read_file", "args": {"path": ...}})
        s.handoff("researcher", "publisher", payload_ref="rows")
        s.step("publisher", {"tool": "http_request", "args": {"url": ...}})
        r = s.evaluate()          # BLOCK — joint exfiltration
    """

    governance: GovernanceLayer
    agents: set = field(default_factory=set)
    _events: list = field(default_factory=list)
    _seq: int = 0

    def register(self, *names: str) -> None:
        self.agents.update(names)

    def step(self, agent: str, tool_call: dict) -> None:
        """Record one agent performing one tool call."""
        self.agents.add(agent)
        self._events.append(_Event(self._seq, "step", agent, dict(tool_call)))
        self._seq += 1

    def handoff(self, from_agent: str, to_agent: str,
                payload_ref: str = "payload", carries_data: bool = True) -> None:
        """Record a control/data handoff between two agents.

        A handoff that carries data is itself a boundary crossing in the
        joint trajectory — it does not, by itself, sanitise taint.
        """
        self.agents.update((from_agent, to_agent))
        call = {
            "tool": "agent_handoff",
            "args": {
                "from": from_agent, "to": to_agent,
                "payload_ref": payload_ref, "carries_data": carries_data,
            },
        }
        self._events.append(_Event(self._seq, "handoff", from_agent, call))
        self._seq += 1

    # ── flattening ────────────────────────────────────────────────
    def flatten(self) -> list[dict]:
        """Project the session into one causally-ordered plan. Each step
        is annotated with its originating agent so audit/attribution can
        recover which agent contributed each segment, while taint and
        reachability see a single continuous trajectory."""
        plan: list[dict] = []
        for ev in sorted(self._events, key=lambda e: e.seq):
            call = dict(ev.call)
            args = dict(call.get("args", {}))
            args.setdefault("_agent", ev.agent)
            args.setdefault("_seq", ev.seq)
            call["args"] = args
            plan.append(call)
        return plan

    # ── governance ────────────────────────────────────────────────
    def evaluate(self) -> GovernanceResult:
        """Govern the flattened joint trajectory (fail-closed: an empty
        session is treated as nothing to permit, not implicitly safe)."""
        plan = self.flatten()
        if not plan:
            return self.governance.evaluate({"tool": "noop", "args": {}})
        if len(plan) == 1:
            return self.governance.evaluate(plan[0])
        return self.governance.evaluate_plan(plan)

    def attribution(self, result: Optional[GovernanceResult] = None) -> dict:
        """Map each contributing agent to the steps it owns in the joint
        trajectory — so a joint BLOCK can be traced to the colluding set."""
        by_agent: dict[str, list] = {}
        for ev in sorted(self._events, key=lambda e: e.seq):
            by_agent.setdefault(ev.agent, []).append(
                (ev.seq, ev.call.get("tool")))
        out = {"agents": sorted(self.agents), "by_agent": by_agent}
        if result is not None:
            out["verdict"] = result.verdict.value
            out["layer"] = result.layer
        return out
