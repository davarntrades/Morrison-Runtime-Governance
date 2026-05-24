"""Continuous adversarial auditing.

Reality changes; Ω and planners drift. A continuous auditor re-runs an
adversarial corpus, snapshots the per-case verdicts, and diffs against
a baseline snapshot to surface REGRESSIONS (a case that was blocked is
now permitted) and FIXES (a case that was permitted is now blocked).
Deterministic: snapshots are pure functions of (corpus, governance)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class AuditSnapshot:
    verdicts: dict = field(default_factory=dict)        # case_id → verdict

    def as_dict(self) -> dict:
        return {"verdicts": dict(self.verdicts)}


@dataclass
class AuditDiff:
    regressions: list = field(default_factory=list)     # case_ids now PERMIT
    fixes: list = field(default_factory=list)           # case_ids now BLOCK
    stable: int = 0
    total: int = 0

    @property
    def clean(self) -> bool:
        return not self.regressions

    def as_dict(self) -> dict:
        return {"regressions": list(self.regressions),
                "fixes": list(self.fixes),
                "stable": self.stable, "total": self.total,
                "clean": self.clean}


class ContinuousAuditor:
    """`evaluate_fn(plan) -> verdict_str`. Corpus is a list of
    {"id", "plan"} dicts."""

    def snapshot(self, corpus: list, evaluate_fn: Callable) -> AuditSnapshot:
        verdicts = {}
        for case in corpus:
            verdicts[case["id"]] = evaluate_fn(case["plan"])
        return AuditSnapshot(verdicts=verdicts)

    def diff(self, baseline: AuditSnapshot,
             current: AuditSnapshot) -> AuditDiff:
        regressions, fixes, stable = [], [], 0
        ids = set(baseline.verdicts) | set(current.verdicts)
        for cid in sorted(ids):
            b = baseline.verdicts.get(cid)
            c = current.verdicts.get(cid)
            b_blocked = b is not None and b != "PERMIT"
            c_blocked = c is not None and c != "PERMIT"
            if b_blocked and not c_blocked:
                regressions.append(cid)
            elif not b_blocked and c_blocked:
                fixes.append(cid)
            else:
                stable += 1
        return AuditDiff(regressions=regressions, fixes=fixes,
                         stable=stable, total=len(ids))
