"""Deterministic graph and verification evidence serialization."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .provenance import (
    ARTIFACT_SCHEMA,
    VerificationEvidenceLedger,
    artifact_digest,
    verification_identity,
    verifier_identity,
)
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
    # How an ESCALATE was resolved by the declared model ("approve"/"deny"),
    # and the pre-resolution verdict it came from. None for a plain decision.
    escalation_outcome: str | None = None
    escalation_origin_verdict: str | None = None
    # Deterministic provenance back to the GovernanceKernel decision. Both
    # hashes are functions of the action and the ruleset, so the graph export
    # stays reproducible. The per-RUN binding to a retained evidence record is
    # deliberately NOT here -- see TraversalResult.evidence_bindings.
    action_hash: str = ""
    semantic_hash: str = ""

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
            "escalation_outcome": self.escalation_outcome,
            "escalation_origin_verdict": self.escalation_origin_verdict,
            "action_hash": self.action_hash,
            "semantic_hash": self.semantic_hash,
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
            label = f"{edge.action}: {edge.governance_verdict}"
            if edge.escalation_outcome:
                label += f" (escalation {edge.escalation_outcome}d)"
            lines.append(
                f'  "{edge.source}" -> "{destination}" '
                f'[label="{label}", style={style}];'
            )
        lines.append("}")
        return "\n".join(lines) + "\n"


def write_json(path: str | Path, value: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def transition_relation_id(control: Any) -> str:
    """Fingerprint the transition relation AS EXERCISED by the control run.

    The declared model hash covers action names, descriptions and flags, but
    the transitions themselves are Python callables that no declaration can
    capture -- two models could declare identically and behave differently.
    This hashes the (source state, action, successor state) triples the
    ungoverned enumeration actually produced, which is the reachable relation
    itself rather than a description of it.
    """
    nodes = control.graph.nodes
    triples = sorted(
        (
            nodes[edge.source].state_id,
            edge.action,
            (
                nodes[edge.destination].state_id
                if edge.destination is not None
                else edge.counterfactual_state_id
            ),
        )
        for edge in control.graph.edges.values()
    )
    return stable_hash(triples)


def build_verification_artifact(
    environment: Any,
    governance: Any,
    comparison: Any,
    *,
    algorithm: str,
    limits: Any,
    ledger: VerificationEvidenceLedger | None = None,
    repo_root: Any = None,
) -> dict[str, Any]:
    """An artifact a reviewer can check without trusting the run that made it.

    Four classes of evidence are carried side by side and never merged:

    `finite_verification`  what the enumeration established, inside the model;
    `governance_decisions` the real kernel verdicts, per graph edge;
    `evidence_ledger`      the real kernel evidence records those verdicts
                           produced, retained past their branch kernels;
    `artifact_integrity`   whether this document is internally consistent.

    A runtime attestation is a fifth class and is NOT produced here: this
    records what an enumeration did, not what a deployment is running.
    """
    governed = comparison.governed
    admitted = tuple(getattr(governed, "escalation_outcomes_admitted", ()) or ())
    complete = comparison.control.complete and governed.complete

    # Requirement, enforced at the point of writing rather than only on read:
    # an incomplete enumeration may not leave here carrying a SAFE verdict.
    if comparison.verdict == "SAFE_WITHIN_MODEL" and not complete:
        raise ValueError(
            "refusing to build a SAFE_WITHIN_MODEL artifact from an incomplete "
            "enumeration; this is INCONCLUSIVE"
        )

    artifact: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA,
        "verification_id": verification_identity(
            environment.model_hash, governance.configuration_hash, algorithm, admitted
        ),
        "timestamp": utc_timestamp(),
        "verifier": verifier_identity(repo_root),
        "environment": {
            "name": environment.name,
            "version": environment.version,
            "model_hash": environment.model_hash,
            "transition_relation_id": transition_relation_id(comparison.control),
            "perturbation": environment.perturbation,
        },
        "governance": {
            "adapter": governance.description,
            # Kernel integrity hash: binds the ruleset AND the kernel's own
            # configuration. Use it to compare two verifier runs.
            "ruleset_hash": governance.configuration_hash,
            # Logic-binding hash over the RULES alone. This is the formula a
            # deployment publishes about itself, so it is the one to compare a
            # verification against a running service with.
            "rules_logic_hash": getattr(governance, "rules_logic_hash", None),
            "engine_version": getattr(governance, "engine_version", None),
        },
        "initial_state_set": [state.to_dict() for state in environment.initial_states],
        "action_space": {
            "version": environment.version,
            "definitions": [action.definition() for action in environment.actions],
        },
        "prohibited_states": [
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
            "escalation_outcomes_admitted": list(admitted),
            "complete_enumeration": complete,
        },
        "finite_verification": {
            "verdict": comparison.verdict,
            "complete_enumeration": complete,
            "claim": comparison.to_dict(include_graph=False)["claim"],
            "scope": (
                "Established within the declared finite model and its stated "
                "assumptions only. Not a claim about the production "
                "environment, and not a claim of universal safety."
            ),
        },
        "control_comparison": comparison.to_dict(include_graph=True),
        "governance_decisions": {
            "note": (
                "Every edge carries the real GovernanceKernel verdict, its "
                "layer and rule, and the deterministic action and semantic "
                "hashes of the proposal it decided."
            ),
            "edge_evidence_bindings": dict(sorted(governed.evidence_bindings.items())),
        },
        "evidence_ledger": (
            ledger.to_dict() if ledger is not None else {
                "retention_model": "no ledger was attached to this run",
                "record_count": 0, "branch_count": 0,
                "records": [], "chain_segments": {},
            }
        ),
        "assumptions": list(environment.assumptions),
        "limitations": list(environment.limitations) + [
            "The declared model hash covers action declarations, not the "
            "Python transition callables; transition_relation_id fingerprints "
            "the relation the control enumeration actually exercised.",
            "Evidence record hashes are per-run: the kernel timestamps an "
            "executed record with wall-clock time, so records chained after "
            "one differ between runs.",
        ],
    }
    artifact["artifact_integrity"] = {
        "digest_algorithm": "sha256-over-canonical-json",
        "excluded_from_digest": ["timestamp", "artifact_integrity"],
        "artifact_hash": artifact_digest(artifact),
        "model_digest": stable_hash(
            {
                "model_hash": environment.model_hash,
                "transition_relation_id": artifact["environment"]["transition_relation_id"],
                "graph": comparison.governed.graph.to_dict(),
            }
        ),
    }
    return artifact
