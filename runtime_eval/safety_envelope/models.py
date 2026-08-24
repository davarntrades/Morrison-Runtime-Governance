"""Immutable contracts for bounded, non-authoritative safety claims."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any, Optional


ENVELOPE_VERSION = "prototype-0.1"
BOUNDARY_WARNING = (
    "This claim applies only to the declared tested envelope. "
    "No safety claim is inherited outside that envelope."
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


class SafetyStatus(str, Enum):
    OBSERVED_LOCAL_SAFETY = "OBSERVED_LOCAL_SAFETY"
    LOCAL_SAFETY_VIOLATION = "LOCAL_SAFETY_VIOLATION"
    UNVALIDATED = "UNVALIDATED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class MembershipStatus(str, Enum):
    INSIDE = "INSIDE"
    OUTSIDE = "OUTSIDE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class EvidenceCoverage:
    trajectories_evaluated: int = 0
    baseline_cases: int = 0
    adversarial_cases: int = 0
    causal_analyses: int = 0
    false_positives: Optional[int] = None
    false_negatives: Optional[int] = None
    denominator: Optional[int] = None


@dataclass(frozen=True)
class SafetyEnvelope:
    envelope_id: str
    governance_version: Optional[str]
    canonical_ruleset_hash: Optional[str]
    policy_hash: Optional[str]
    omega_hash: Optional[str]
    causal_overlay_version: Optional[str]
    causal_template_version: Optional[str]
    model_planner_set: tuple[str, ...]
    tool_set: tuple[str, ...]
    capability_set: tuple[str, ...]
    tool_capability_manifest: tuple[str, ...]
    permission_configuration: tuple[tuple[str, str], ...]
    trust_boundary_configuration: tuple[str, ...]
    agent_counts: tuple[int, ...]
    execution_modes: tuple[str, ...]
    trajectory_horizon: Optional[int]
    scenario_families: tuple[str, ...]
    state_variable_schema: tuple[str, ...]
    environmental_assumptions: tuple[str, ...]
    perturbation_families: tuple[str, ...]
    baseline_cases: tuple[str, ...]
    adversarial_cases: tuple[str, ...]
    allowed_state_definition: Optional[str]
    forbidden_state_definition: Optional[str]
    enforcement_point: Optional[str]
    connector_environment_identifiers: tuple[str, ...]
    concurrency_assumptions: tuple[str, ...]
    memory_assumptions: tuple[str, ...]
    network_assumptions: tuple[str, ...]
    evidence_coverage: EvidenceCoverage
    unsupported_untested_regions: tuple[str, ...]
    timestamp: Optional[str]
    source_hashes: tuple[str, ...]
    provenance: tuple[str, ...]
    envelope_version: str = ENVELOPE_VERSION
    evidence_hash: str = ""

    def semantic_dict(self, include_hash: bool = True) -> dict:
        value = asdict(self)
        if not include_hash:
            value.pop("evidence_hash", None)
            value.pop("envelope_id", None)
        return value

    def with_seal(self) -> "SafetyEnvelope":
        value = self.semantic_dict(include_hash=False)
        sealed = digest(value)
        return replace(self, envelope_id=f"se-{sealed[:20]}",
                       evidence_hash=sealed)


@dataclass(frozen=True)
class OperatingConditions:
    canonical_ruleset_hash: Optional[str]
    policy_hash: Optional[str]
    omega_hash: Optional[str]
    model_planners: tuple[str, ...]
    tools: tuple[str, ...]
    capabilities: tuple[str, ...]
    permission_configuration: tuple[tuple[str, str], ...]
    trust_boundary_configuration: tuple[str, ...]
    agent_count: Optional[int]
    execution_mode: Optional[str]
    trajectory_horizon: Optional[int]
    scenario_family: Optional[str]
    perturbation_family: Optional[str]
    connector_environment_identifiers: tuple[str, ...] = ()
    destination_classifications: tuple[str, ...] = ()
    source_hashes: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()


@dataclass(frozen=True)
class MembershipResult:
    status: MembershipStatus
    inside_envelope: Optional[bool]
    boundary_changes: tuple[str, ...]
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True)
class SafetyEvidence:
    safety_property: str
    canonical_verdicts: tuple[str, ...]
    omega_reachable_trajectories: int
    forbidden_state_reached: Optional[bool]
    trajectory_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    source_hashes: tuple[str, ...]
    causal_report_hashes: tuple[str, ...] = ()
    causal_questions_answered: tuple[str, ...] = ()
    sufficient_interventions: tuple[str, ...] = ()
    ineffective_interventions: tuple[str, ...] = ()
    unresolved_intervention_questions: tuple[str, ...] = ()
    causal_template_coverage: tuple[str, ...] = ()
    causal_resolution_score: Optional[float] = None
    causal_evidence_required: bool = False
    causal_resolution_threshold: Optional[float] = None


@dataclass(frozen=True)
class SafetyEnvelopeResult:
    status: SafetyStatus
    envelope_id: str
    safety_property: str
    inside_envelope: Optional[bool]
    canonical_verdict_summary: str
    omega_reachability_summary: str
    causal_analysis_coverage: str
    tested_conditions: tuple[tuple[str, str], ...]
    unsupported_conditions: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    source_hashes: tuple[str, ...]
    claim_text: str
    boundary_warning: str = BOUNDARY_WARNING
    result_hash: str = ""

    def semantic_dict(self, include_hash: bool = True) -> dict:
        value = asdict(self)
        value["status"] = self.status.value
        if not include_hash:
            value.pop("result_hash", None)
        return value

    def with_seal(self) -> "SafetyEnvelopeResult":
        return replace(self, result_hash=digest(
            self.semantic_dict(include_hash=False)))


@dataclass(frozen=True)
class SafetyEvidencePackage:
    safety_envelope: SafetyEnvelope
    result: SafetyEnvelopeResult
    supporting_evidence: SafetyEvidence
    scenario_manifest: tuple[str, ...]
    perturbation_manifest: tuple[str, ...]
    model_planner_manifest: tuple[str, ...]
    tool_capability_manifest: tuple[str, ...]
    test_results: tuple[str, ...]
    failures: tuple[str, ...]
    replay_results: tuple[str, ...]
    unsupported_regions: tuple[str, ...]
    provenance: tuple[str, ...]
    package_hash: str = ""

    def semantic_dict(self, include_hash: bool = True) -> dict:
        value = asdict(self)
        value["result"]["status"] = self.result.status.value
        if not include_hash:
            value.pop("package_hash", None)
        return value

    def with_seal(self) -> "SafetyEvidencePackage":
        return replace(self, package_hash=digest(
            self.semantic_dict(include_hash=False)))

    def deterministic_json(self) -> str:
        return canonical_json(self.semantic_dict())
