"""Distributed trust architecture — no single point of failure.

N independent governance replicas evaluate the same trajectory. The
consensus rule is DENY-BY-DEFAULT: a trajectory is permitted only if
EVERY replica permits it; any replica that blocks (or errors) forces
BLOCK. This removes the single-point-of-failure: corrupting or
crashing one replica cannot turn a BLOCK into a PERMIT, only the
reverse (which is the safe direction).

Bounded honesty: this models in-process replica diversity + a
deny-by-default quorum. It is NOT a Byzantine-fault-tolerant
cryptographic consensus protocol across a real distributed system —
that infrastructure layer is out of scope. What is implemented and
tested is the governance-side property: safety is preserved as long as
*at least one* honest replica says BLOCK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer


@dataclass
class ReplicaVerdict:
    replica: int
    verdict: str
    layer: str
    errored: bool = False

    def as_dict(self) -> dict:
        return {"replica": self.replica, "verdict": self.verdict,
                "layer": self.layer, "errored": self.errored}


@dataclass
class ConsensusResult:
    permitted: bool
    n_replicas: int
    n_permit: int
    n_block: int
    n_error: int
    agreement: float
    replicas: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"permitted": self.permitted, "n_replicas": self.n_replicas,
                "n_permit": self.n_permit, "n_block": self.n_block,
                "n_error": self.n_error, "agreement": round(self.agreement, 4),
                "replicas": [r.as_dict() for r in self.replicas]}


class DistributedGovernance:
    def __init__(self, replicas: list):
        if not replicas:
            raise ValueError("at least one replica required")
        self.replicas = list(replicas)

    def _eval(self, gov: GovernanceLayer, plan: list):
        return (gov.evaluate_plan(plan) if len(plan) > 1
                else gov.evaluate(plan[0]))

    def evaluate_plan(self, plan: list) -> ConsensusResult:
        verdicts: list[ReplicaVerdict] = []
        for i, gov in enumerate(self.replicas):
            try:
                r = self._eval(gov, plan)
                verdicts.append(ReplicaVerdict(
                    replica=i, verdict=r.verdict.value, layer=r.layer))
            except Exception as e:                       # noqa: BLE001
                # crashed/corrupt replica → treated as BLOCK (fail-closed)
                verdicts.append(ReplicaVerdict(
                    replica=i, verdict="BLOCK", layer="replica_error",
                    errored=True))
        n_permit = sum(1 for v in verdicts if v.verdict == "PERMIT")
        n_block = sum(1 for v in verdicts if v.verdict != "PERMIT"
                      and not v.errored)
        n_error = sum(1 for v in verdicts if v.errored)
        # deny-by-default: permitted iff ALL replicas permit
        permitted = (n_permit == len(verdicts))
        agreement = max(n_permit, len(verdicts) - n_permit) / len(verdicts)
        return ConsensusResult(
            permitted=permitted, n_replicas=len(verdicts),
            n_permit=n_permit, n_block=n_block, n_error=n_error,
            agreement=agreement, replicas=verdicts)
