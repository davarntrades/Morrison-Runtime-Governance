"""Memory-aware governance — long-horizon effects across sessions.

A single session's trajectory may clear governance, but risk
accumulated across many sessions by the same entity is a long-horizon
signal. This wrapper keeps a bounded, decaying, per-entity cumulative
risk score (computed from the existing structural risk-propagation
pass) and ESCALATES — never relaxes — when cross-session risk crosses a
threshold.

Direction discipline: memory can only turn a PERMIT into a BLOCK
(escalate-to-human); it can NEVER turn a governance BLOCK into a
PERMIT. Fail-closed is preserved; the worst case is an over-block that
a human reviews, never an under-block."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer


@dataclass
class MemoryResult:
    entity_id: str
    permitted: bool
    base_verdict: str
    base_layer: str
    session_risk: float
    cumulative_risk: float
    memory_escalated: bool
    reason: str = ""

    def as_dict(self) -> dict:
        return {"entity_id": self.entity_id, "permitted": self.permitted,
                "base_verdict": self.base_verdict,
                "base_layer": self.base_layer,
                "session_risk": round(self.session_risk, 4),
                "cumulative_risk": round(self.cumulative_risk, 4),
                "memory_escalated": self.memory_escalated,
                "reason": self.reason}


class MemoryGovernance:
    def __init__(self, governance: GovernanceLayer,
                 escalate_threshold: float = 2.5, decay: float = 0.7):
        self.governance = governance
        self.escalate_threshold = escalate_threshold
        self.decay = decay
        self.memory: dict = {}              # entity_id → cumulative risk

    def _session_risk(self, plan: list) -> float:
        from runtime_eval.evaluators.risk_propagation import propagate_risk
        norm = [{"tool": s.get("tool"), "args": s.get("args", {})}
                for s in plan]
        _graph, report = propagate_risk(norm)
        return report.max_cumulative

    def evaluate(self, entity_id: str, plan: list) -> MemoryResult:
        base = (self.governance.evaluate_plan(plan) if len(plan) > 1
                else self.governance.evaluate(plan[0]))
        session_risk = self._session_risk(plan)
        prior = self.memory.get(entity_id, 0.0) * self.decay
        cumulative = prior + session_risk
        self.memory[entity_id] = cumulative

        memory_escalated = (base.permitted
                            and cumulative >= self.escalate_threshold)
        permitted = base.permitted and not memory_escalated
        reason = base.reason
        if memory_escalated:
            reason = (f"memory-aware escalation: cross-session cumulative "
                      f"risk {cumulative:.2f} ≥ {self.escalate_threshold} "
                      f"for entity {entity_id} → escalate to human")
        return MemoryResult(
            entity_id=entity_id, permitted=permitted,
            base_verdict=base.verdict.value, base_layer=base.layer,
            session_risk=session_risk, cumulative_risk=cumulative,
            memory_escalated=memory_escalated, reason=reason)
