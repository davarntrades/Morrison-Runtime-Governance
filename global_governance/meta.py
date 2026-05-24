"""MetaGovernance — composes the meta-governance mechanisms into one
deny-by-default pipeline. This is the "closest to global" stack: a
trajectory must clear the hierarchical tiers AND the distributed quorum
AND self-verification, then memory-aware escalation and the
institutional layer are applied. Any layer that blocks → BLOCK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer
from global_governance.hierarchy import HierarchicalGovernance
from global_governance.distributed_trust import DistributedGovernance
from global_governance.self_verifying import SelfVerifyingController
from global_governance.memory_governance import MemoryGovernance
from global_governance.institutional import InstitutionalGovernance


@dataclass
class MetaResult:
    permitted: bool
    blocked_by: Optional[str]
    stages: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"permitted": self.permitted, "blocked_by": self.blocked_by,
                "stages": dict(self.stages)}


class MetaGovernance:
    """Compose all meta-governance mechanisms. The constructor takes the
    primary GovernanceLayer plus optional tier / replica layers; sensible
    defaults reuse the primary layer so the stack runs out of the box."""

    def __init__(self, primary: GovernanceLayer,
                 tiers: Optional[dict] = None,
                 replicas: Optional[list] = None,
                 memory_threshold: float = 2.5):
        self.primary = primary
        self.hierarchy = HierarchicalGovernance(
            tiers or {"local": primary, "regional": primary,
                      "global": primary})
        self.distributed = DistributedGovernance(replicas or [primary])
        self.self_verify = SelfVerifyingController(primary)
        self.memory = MemoryGovernance(primary,
                                       escalate_threshold=memory_threshold)
        self.institutional = InstitutionalGovernance(primary)

    def evaluate(self, plan: list, *, entity_id: str = "anon",
                 authorizations: tuple = (),
                 institutional_veto: bool = False) -> MetaResult:
        stages: dict = {}

        h = self.hierarchy.evaluate_plan(plan)
        stages["hierarchy"] = h.as_dict()
        if not h.permitted:
            return MetaResult(False, "hierarchy", stages)

        d = self.distributed.evaluate_plan(plan)
        stages["distributed"] = d.as_dict()
        if not d.permitted:
            return MetaResult(False, "distributed", stages)

        v = self.self_verify.evaluate_verified(plan)
        stages["self_verify"] = v.as_dict()
        if not v.permitted:
            return MetaResult(False, "self_verify", stages)

        m = self.memory.evaluate(entity_id, plan)
        stages["memory"] = m.as_dict()
        if not m.permitted:
            return MetaResult(False, "memory", stages)

        inst = self.institutional.evaluate(
            plan, authorizations=authorizations,
            institutional_veto=institutional_veto)
        stages["institutional"] = inst.as_dict()
        if not inst.permitted:
            return MetaResult(False, "institutional", stages)

        return MetaResult(True, None, stages)
