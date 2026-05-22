"""Hierarchical governance layers — local + regional + global Ω.

A trajectory must clear EVERY tier. Tiers are ordered (local → regional
→ global) and strict-strengthening: any tier that blocks → the whole
decision is BLOCK (deny-by-default up the hierarchy). All tiers are
evaluated for audit even after the first block."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer


@dataclass
class TierVerdict:
    tier: str
    verdict: str
    layer: str
    rule: Optional[str]
    reason: str

    def as_dict(self) -> dict:
        return {"tier": self.tier, "verdict": self.verdict,
                "layer": self.layer, "rule": self.rule,
                "reason": self.reason}


@dataclass
class HierarchicalResult:
    permitted: bool
    blocking_tier: Optional[str]
    tiers: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"permitted": self.permitted,
                "blocking_tier": self.blocking_tier,
                "tiers": [t.as_dict() for t in self.tiers]}


class HierarchicalGovernance:
    """Compose ordered governance tiers. `tiers` is an ordered dict
    {tier_name: GovernanceLayer}; conventionally
    {"local":..., "regional":..., "global":...}."""

    def __init__(self, tiers: dict):
        if not tiers:
            raise ValueError("at least one tier required")
        self.tiers = dict(tiers)

    def _eval(self, gov: GovernanceLayer, plan: list):
        return (gov.evaluate_plan(plan) if len(plan) > 1
                else gov.evaluate(plan[0]))

    def evaluate_plan(self, plan: list) -> HierarchicalResult:
        verdicts: list[TierVerdict] = []
        blocking: Optional[str] = None
        for name, gov in self.tiers.items():
            try:
                r = self._eval(gov, plan)
                tv = TierVerdict(
                    tier=name, verdict=r.verdict.value, layer=r.layer,
                    rule=(r.metadata or {}).get("rule"), reason=r.reason)
            except Exception as e:                       # noqa: BLE001
                tv = TierVerdict(tier=name, verdict="BLOCK",
                                  layer="tier_error", rule=None,
                                  reason=f"{type(e).__name__}: {e}")
            verdicts.append(tv)
            if tv.verdict != "PERMIT" and blocking is None:
                blocking = name
        return HierarchicalResult(
            permitted=(blocking is None),
            blocking_tier=blocking, tiers=verdicts)
