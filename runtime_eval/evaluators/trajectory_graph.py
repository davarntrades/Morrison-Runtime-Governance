"""Trajectory dependency graph.

Each executed step is a node. An edge `i → j` exists when step j
*depends* on i — operationally, when j's args reuse data shaped like
i's output (path / id / key overlap), when j reads what i wrote, or
when j is a sub-call exposed by i. The graph is the substrate the
risk-propagation pass walks: risk attached to a node propagates to its
dependents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class TrajectoryNode:
    step: int
    tool: str
    args: dict
    capabilities: list = field(default_factory=list)
    parents: list = field(default_factory=list)        # step indices

    def as_dict(self) -> dict:
        return {"step": self.step, "tool": self.tool,
                "args": dict(self.args),
                "capabilities": list(self.capabilities),
                "parents": list(self.parents)}


@dataclass
class TrajectoryGraph:
    nodes: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"nodes": [n.as_dict() for n in self.nodes]}


# heuristic dependency keys — shared between steps usually means data
# flow.
_DATA_KEYS = ("path", "file", "filepath", "key", "id", "url", "uri",
               "endpoint", "resource", "bucket", "object", "handle",
               "dataset", "table", "record", "ref")


def _shared_data_value(a: dict, b: dict) -> bool:
    av = {str(a.get(k)) for k in _DATA_KEYS if a.get(k)}
    bv = {str(b.get(k)) for k in _DATA_KEYS if b.get(k)}
    return bool(av & bv)


def build_graph(history: Iterable[dict]) -> TrajectoryGraph:
    """Build a deterministic dependency graph over executed steps.

    `history` is an iterable of `{"tool", "args"}` dicts in execution
    order. Edges are computed by structural data-key overlap with the
    nearest prior step. Order is preserved; same input → same output.
    """
    from morrison_governance.forecasting import infer_capabilities

    nodes: list[TrajectoryNode] = []
    for i, call in enumerate(history):
        args = call.get("args") if isinstance(call.get("args"), dict) else {}
        node = TrajectoryNode(
            step=i, tool=str(call.get("tool", "")),
            args=dict(args),
            capabilities=sorted(infer_capabilities(call)),
        )
        for j in range(i - 1, -1, -1):
            if _shared_data_value(args, nodes[j].args):
                node.parents.append(j)
        nodes.append(node)
    return TrajectoryGraph(nodes=nodes)
