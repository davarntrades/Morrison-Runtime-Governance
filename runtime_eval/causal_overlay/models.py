"""Immutable data contracts for the non-authoritative causal overlay.

Latency is deliberately excluded from the semantic seal: wall-clock timing is
not deterministic, while the causal claims and their provenance must be.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


OVERLAY_VERSION = "prototype-0.1"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def _without_wall_clock(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_wall_clock(item)
                for key, item in value.items()
                if key not in {"latency_metrics", "replay_latency_ms"}}
    if isinstance(value, list):
        return [_without_wall_clock(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_without_wall_clock(item) for item in value)
    return value


@dataclass(frozen=True)
class CausalVariable:
    name: str
    value: Any
    source: str
    kind: str
    intervenable: bool
    provenance: tuple[str, ...]
    observation_type: str = "OBSERVED"


@dataclass(frozen=True)
class CausalEdge:
    parent: str
    child: str
    relation: str
    provenance: tuple[str, ...]
    observation_type: str = "DERIVED"


@dataclass(frozen=True)
class CausalIntervention:
    intervention_id: str
    variable: str
    factual_value: Any
    counterfactual_value: Any
    question: str
    operation: str
    target_step: Optional[int] = None
    provenance: tuple[str, ...] = ()


@dataclass(frozen=True)
class StepOutcome:
    original_step: int
    tool: str
    verdict: str
    layer: str
    rule: Optional[str]
    omega_domain: Optional[str]
    executed: bool
    action_hash: str
    evidence_hash: str
    capabilities: tuple[str, ...]
    requirement: str
    destination_external: bool
    authorization_approved: bool
    reason: str


@dataclass(frozen=True)
class ReplayOutcome:
    verdict: str
    omega: tuple[str, ...]
    omega_reachable: bool
    first_blocked_step: Optional[int]
    responsible_layer: str
    reachable_steps: tuple[int, ...]
    constraint_layers: tuple[str, ...]
    steps: tuple[StepOutcome, ...]
    evidence_hashes: tuple[str, ...]
    replay_latency_ms: float = field(default=0.0, compare=False)

    def semantic_dict(self) -> dict:
        return _without_wall_clock(asdict(self))


@dataclass(frozen=True)
class CounterfactualResult:
    intervention: CausalIntervention
    factual_verdict: str
    counterfactual_verdict: str
    factual_omega: tuple[str, ...]
    counterfactual_omega: tuple[str, ...]
    factual_omega_reachable: bool
    counterfactual_omega_reachable: bool
    prevented: bool
    verdict_changed: bool
    omega_reachability_changed: bool
    first_blocked_step_factual: Optional[int]
    first_blocked_step_counterfactual: Optional[int]
    responsible_layer_factual: str
    responsible_layer_counterfactual: str
    reachable_state_changes: tuple[str, ...]
    constraint_changes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    replay_latency_ms: float = field(default=0.0, compare=False)
    observation_type: str = "COUNTERFACTUAL"


@dataclass(frozen=True)
class ContributionTraceEntry:
    variable: str
    intervention_id: str
    necessary_contributor: bool
    sufficient_to_break_trajectory: bool
    verdict_changed: bool
    omega_reachability_changed: bool
    first_blocked_step_change: str
    responsible_layer_change: str
    reachable_state_changes: tuple[str, ...]
    constraint_changes: tuple[str, ...]
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class LatencyMetrics:
    canonical_governance_ms: float = 0.0
    variable_extraction_ms: float = 0.0
    template_construction_ms: float = 0.0
    intervention_generation_ms: float = 0.0
    individual_replay_ms: tuple[float, ...] = ()
    sequential_replay_wall_ms: float = 0.0
    parallel_replay_wall_ms: float = 0.0
    contribution_trace_ms: float = 0.0
    report_construction_ms: float = 0.0
    evidence_sealing_ms: float = 0.0
    total_overlay_ms: float = 0.0
    synchronous_end_to_end_ms: float = 0.0
    async_canonical_governance_ms: float = 0.0

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class CausalAnalysisReport:
    trajectory_id: str
    source_evidence_hash: str
    factual_verdict: str
    factual_omega: tuple[str, ...]
    causal_variables: tuple[CausalVariable, ...]
    causal_edges: tuple[CausalEdge, ...]
    interventions: tuple[CounterfactualResult, ...]
    necessary_contributors: tuple[str, ...]
    sufficient_interventions: tuple[str, ...]
    contribution_trace: tuple[ContributionTraceEntry, ...]
    causal_resolution_score: float
    overlay_version: str = OVERLAY_VERSION
    mode: str = "shadow"
    artifact_hash: str = ""
    latency_metrics: LatencyMetrics = field(
        default_factory=LatencyMetrics, compare=False)

    def semantic_dict(self, include_hash: bool = True) -> dict:
        value = _without_wall_clock(asdict(self))
        if not include_hash:
            value.pop("artifact_hash", None)
        return value

    def deterministic_json(self) -> str:
        """Byte-stable causal claims; excludes inherently variable timings."""
        return canonical_json(self.semantic_dict())

    def to_dict(self) -> dict:
        value = asdict(self)
        value["semantic_determinism"] = {
            "sealed_fields_exclude_wall_clock_latency": True,
            "artifact_hash": self.artifact_hash,
        }
        return value

    def with_seal(self) -> "CausalAnalysisReport":
        from dataclasses import replace
        digest = hashlib.sha256(canonical_json(
            self.semantic_dict(include_hash=False)).encode()).hexdigest()
        return replace(self, artifact_hash=digest)


@dataclass(frozen=True)
class ShadowAnalysisResult:
    canonical_outcome: ReplayOutcome
    report: Optional[CausalAnalysisReport]
    overlay_error: Optional[str] = None
    overlay_enabled: bool = True
