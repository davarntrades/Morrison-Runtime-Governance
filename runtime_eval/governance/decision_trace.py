"""Structured per-step governance decisions, deterministic JSON-able."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class DecisionRecord:
    """One governance decision on one proposed tool call.

    The fields here are exactly what the existing GovernanceResult
    exposes plus the planner identity and trajectory prefix index — the
    point of admissibility + reachability evaluation is preserved
    end-to-end, in deterministic JSON, with no semantic interpretation."""

    step: int
    planner: str
    proposed: dict                       # the tool call as proposed
    verdict: str                         # PERMIT | BLOCK | NO_VALID_SOLUTION | ENVIRONMENT_SENSITIVE
    layer: str                           # A_safe | V2 | V3 | V4 | V4+ | V5 | V5+ | fail_closed
    rule: Optional[str] = None
    omega_domain: Optional[str] = None
    reason: str = ""
    trajectory_hash: str = ""
    reachability_distance: Optional[float] = None
    metadata: dict = field(default_factory=dict)
    executed: bool = False               # set by the middleware after sandbox
    runtime_error: Optional[str] = None  # set if executor raised
    latency_ms: float = 0.0

    # ── hardening lineage (set by the HardeningPipeline) ─────
    decode_steps: list = field(default_factory=list)
    decoded_extracted: dict = field(default_factory=dict)
    lifted_capabilities: list = field(default_factory=list)
    lifted_canonical_tool: Optional[str] = None
    recursion_depth: int = 0
    sub_calls_expanded: list = field(default_factory=list)
    schema_violations: list = field(default_factory=list)
    cumulative_risk: float = 0.0
    step_risk: float = 0.0
    omega_proximity: Optional[float] = None
    pruning_rationale: Optional[str] = None
    admissibility_confidence: Optional[float] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)


@dataclass
class DecisionTrace:
    """Ordered sequence of DecisionRecord across one run."""

    records: list = field(default_factory=list)

    def append(self, rec: DecisionRecord) -> None:
        self.records.append(rec)

    @property
    def executed(self) -> list:
        return [r for r in self.records if r.executed]

    @property
    def blocked(self) -> list:
        return [r for r in self.records if not r.executed]

    def fail_closed_holds(self) -> bool:
        """Anything that executed must have verdict == PERMIT."""
        return all((not r.executed) or r.verdict == "PERMIT"
                   for r in self.records)

    def to_jsonl(self) -> str:
        return "\n".join(r.to_json() for r in self.records)

    def summary(self) -> dict:
        return {
            "steps": len(self.records),
            "executed": len(self.executed),
            "blocked": len(self.blocked),
            "fail_closed": self.fail_closed_holds(),
            "runtime_errors": sum(
                1 for r in self.records if r.runtime_error),
        }
