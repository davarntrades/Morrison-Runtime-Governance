"""Deterministic graph and verification evidence serialization."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .state import stable_hash


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    state_id: str
    state: dict[str, Any]
    safe: bool
    unsafe_invariants: tuple[str, ...]
    depth: int
    initial: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "state_id": self.state_id,
            "state": self.state,
            "safe": self.safe,
            "unsafe_invariants": list(self.unsafe_invariants),
            "depth": self.depth,
            "initial": self.initial,
        }


@dataclass(frozen=True)
class GraphEdge:
    edge_id: str
    source: str
    destination: str | None
    action: str
    proposed_action: dict[str, Any]
    governance_verdict: str
    executed: bool
    blocked: bool
    layer: str
    reason: str
    rule: str | None = None
    omega_domain: str | None = None
    counterfactual_state_id: str | None = None
    counterfactual_unsafe_invariants: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source": self.source,
            "destination": self.destination,
            "action": self.action,
            "proposed_action": self.proposed_action,
            "governance_verdict": self.governance_verdict,
            "executed": self.executed,
            "blocked": self.blocked,
            "layer": self.layer,
            "reason": self.reason,
            "rule": self.rule,
            "omega_domain": self.omega_domain,
            "counterfactual_state_id": self.counterfactual_state_id,
            "counterfactual_unsafe_invariants": list(
                self.counterfactual_unsafe_invariants
            ),
        }


@dataclass
class GraphEvidence:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[str, GraphEdge] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges[edge.edge_id] = edge

    def merge(self, other: "GraphEvidence") -> None:
        self.nodes.update(other.nodes)
        self.edges.update(other.edges)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [self.nodes[key].to_dict() for key in sorted(self.nodes)],
            "edges": [self.edges[key].to_dict() for key in sorted(self.edges)],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent) + "\n"

    def to_dot(self) -> str:
        lines = ["digraph global_verification {", "  rankdir=LR;"]
        for key in sorted(self.nodes):
            node = self.nodes[key]
            colour = "#b42318" if not node.safe else "#067647"
            shape = "doublecircle" if node.initial else "ellipse"
            lines.append(
                f'  "{node.node_id}" [label="{node.state_id}", color="{colour}", shape={shape}];'
            )
        for key in sorted(self.edges):
            edge = self.edges[key]
            destination = edge.destination
            if destination is None:
                destination = f"blocked-{edge.edge_id}"
                lines.append(
                    f'  "{destination}" [label="BLOCKED", shape=box, color="#b54708"];'
                )
            style = "solid" if edge.executed else "dashed"
            lines.append(
                f'  "{edge.source}" -> "{destination}" '
                f'[label="{edge.action}: {edge.governance_verdict}", style={style}];'
            )
        lines.append("}")
        return "\n".join(lines) + "\n"


def write_json(path: str | Path, value: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def verification_identity(model_hash: str, governance_hash: str, algorithm: str) -> str:
    return "gsv-" + stable_hash(
        {"model_hash": model_hash, "governance_hash": governance_hash, "algorithm": algorithm}
    )[:20]


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_verification_artifact(
    environment: Any,
    governance: Any,
    comparison: Any,
    *,
    algorithm: str,
    limits: Any,
) -> dict[str, Any]:
    """Create an audit-ready artifact without coupling to the audit package."""

    verification_id = verification_identity(
        environment.model_hash, governance.configuration_hash, algorithm
    )
    return {
        "schema_version": "mrg.global-verification.v1",
        "verification_id": verification_id,
        "timestamp": utc_timestamp(),
        "environment": {
            "name": environment.name,
            "version": environment.version,
            "model_hash": environment.model_hash,
            "perturbation": environment.perturbation,
        },
        "governance": {
            "adapter": governance.description,
            "configuration_hash": governance.configuration_hash,
        },
        "initial_state_set": [state.to_dict() for state in environment.initial_states],
        "action_space": {
            "version": environment.version,
            "definitions": [action.definition() for action in environment.actions],
        },
        "unsafe_invariants": [
            invariant.definition() for invariant in environment.unsafe_invariants
        ],
        "traversal": {
            "algorithm": algorithm,
            "limits": {
                "max_states": limits.max_states,
                "max_edges": limits.max_edges,
                "max_depth": limits.max_depth,
                "timeout_seconds": limits.timeout_seconds,
            },
            "complete_enumeration": (
                comparison.control.complete and comparison.governed.complete
            ),
        },
        "control_comparison": comparison.to_dict(include_graph=True),
        "assumptions": list(environment.assumptions),
        "limitations": list(environment.limitations),
        "final_verdict": comparison.verdict,
        "claim": comparison.to_dict(include_graph=False)["claim"],
    }
