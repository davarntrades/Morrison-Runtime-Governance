"""Forward risk propagation across an executable trajectory.

A single step's "risk" is a deterministic structural score derived
from its inferred capability set + argument geometry — never from text
classification. The propagation pass walks the trajectory graph and
inherits risk from parents along edges, so a downstream step that
*depends on* a high-risk acquisition step inherits its risk even
before any single rule fires.

The score is BOUNDED, REPLAYABLE, and used only as a *signal* for
branch pruning / decision tracing. It does not replace the
reachability hierarchy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from morrison_governance.forecasting import infer_capabilities
from runtime_eval.evaluators.trajectory_graph import (
    TrajectoryGraph, build_graph,
)


_CAP_WEIGHTS = {
    "acquire": 0.25,
    "egress":  0.40,
    "exec":    0.45,
    "priv":    0.40,
    "defer":   0.20,
    "loop":    0.15,
}


_ARG_RISK_KEYS = {
    "url": 0.20, "uri": 0.20, "endpoint": 0.20, "recipient": 0.15,
    "to": 0.10, "host": 0.15,
    "sql": 0.25, "query": 0.15, "path": 0.10,
    "mode": 0.20, "role": 0.15, "grant": 0.20, "scope": 0.10,
    "category": 0.10, "topic_class": 0.10, "user_state": 0.20,
    "purpose": 0.15, "safety_disabled": 0.30,
}


@dataclass
class RiskReport:
    per_step: list = field(default_factory=list)       # list[float]
    cumulative: list = field(default_factory=list)     # list[float]
    inherited: list = field(default_factory=list)      # list[float]
    max_step: float = 0.0
    max_cumulative: float = 0.0

    def as_dict(self) -> dict:
        return {"per_step": [round(x, 4) for x in self.per_step],
                "cumulative": [round(x, 4) for x in self.cumulative],
                "inherited": [round(x, 4) for x in self.inherited],
                "max_step": round(self.max_step, 4),
                "max_cumulative": round(self.max_cumulative, 4)}


def _step_risk(call: dict) -> float:
    caps = infer_capabilities(call)
    score = sum(_CAP_WEIGHTS.get(c, 0.0) for c in caps)
    args = call.get("args") if isinstance(call.get("args"), dict) else {}
    for k in args:
        score += _ARG_RISK_KEYS.get(str(k).lower(), 0.0)
    if call.get("safety_disabled") is True:
        score += 0.30
    return min(score, 1.0)


def propagate_risk(history: Iterable[dict],
                   *, decay: float = 0.6) -> tuple[TrajectoryGraph,
                                                    RiskReport]:
    """Walk the trajectory graph; return (graph, RiskReport)."""
    graph = build_graph(history)
    n = len(graph.nodes)
    per_step = [0.0] * n
    inherited = [0.0] * n
    cumulative = [0.0] * n
    for i, node in enumerate(graph.nodes):
        per_step[i] = _step_risk({"tool": node.tool, "args": node.args})
        if node.parents:
            inherited[i] = max(cumulative[p] for p in node.parents) * decay
        cumulative[i] = min(per_step[i] + inherited[i], 1.0)
    report = RiskReport(
        per_step=per_step, cumulative=cumulative, inherited=inherited,
        max_step=max(per_step or [0.0]),
        max_cumulative=max(cumulative or [0.0]))
    return graph, report
