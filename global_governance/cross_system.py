"""Cross-system trajectory analysis.

Multi-agent environments span *independent* systems that each look
locally safe. System A acquires data; System B (a different service)
egresses it. No single system's trajectory reaches Ω — the joint
cross-system trajectory does. This analyzer records per-system actions
and governs the flattened joint trajectory, the same way
morrison_governance.MultiAgentSession governs an agent team."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer


@dataclass
class CrossSystemResult:
    permitted: bool
    verdict: str
    layer: str
    rule: Optional[str]
    reason: str
    systems: list = field(default_factory=list)
    joint_len: int = 0

    def as_dict(self) -> dict:
        return {"permitted": self.permitted, "verdict": self.verdict,
                "layer": self.layer, "rule": self.rule,
                "reason": self.reason, "systems": list(self.systems),
                "joint_len": self.joint_len}


@dataclass
class _Event:
    seq: int
    system: str
    call: dict


class CrossSystemAnalyzer:
    """Record actions from multiple independent systems; govern the
    flattened, causally-ordered joint trajectory."""

    def __init__(self, governance: GovernanceLayer):
        self.governance = governance
        self.systems: set = set()
        self._events: list = []
        self._seq = 0

    def register_system(self, *names: str) -> None:
        self.systems.update(names)

    def record(self, system: str, call: dict) -> None:
        self.systems.add(system)
        self._events.append(_Event(self._seq, system, dict(call)))
        self._seq += 1

    def handoff(self, from_system: str, to_system: str,
                payload_ref: str = "payload") -> None:
        self.systems.update((from_system, to_system))
        self._events.append(_Event(
            self._seq, from_system,
            {"tool": "system_handoff",
             "args": {"from": from_system, "to": to_system,
                      "payload_ref": payload_ref, "carries_data": True}}))
        self._seq += 1

    def flatten(self) -> list:
        """Project to a clean joint trajectory of the actual executable
        calls in causal order. Handoff events are attribution metadata,
        NOT governed steps, and per-system bookkeeping is kept out of the
        governed args so it cannot perturb the structural analysis. The
        cross-system exfiltration signal lives in the real calls (an
        acquire by one system, an egress by another) regardless of which
        system issued them — that is the point of joint governance."""
        plan = []
        for ev in sorted(self._events, key=lambda e: e.seq):
            if str(ev.call.get("tool")) == "system_handoff":
                continue
            plan.append({"tool": ev.call.get("tool"),
                         "args": dict(ev.call.get("args", {}))})
        return plan

    def attribution(self) -> list:
        """Which system issued each governed step, in causal order."""
        return [(ev.system, ev.call.get("tool"))
                for ev in sorted(self._events, key=lambda e: e.seq)
                if str(ev.call.get("tool")) != "system_handoff"]

    def evaluate_joint(self) -> CrossSystemResult:
        plan = self.flatten()
        if not plan:
            r = self.governance.evaluate({"tool": "noop", "args": {}})
        elif len(plan) == 1:
            r = self.governance.evaluate(plan[0])
        else:
            r = self.governance.evaluate_plan(plan)
        return CrossSystemResult(
            permitted=r.permitted, verdict=r.verdict.value, layer=r.layer,
            rule=(r.metadata or {}).get("rule"), reason=r.reason,
            systems=sorted(self.systems), joint_len=len(plan))
