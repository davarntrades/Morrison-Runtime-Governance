"""Admissibility-guided branch pruning.

Given a batch of candidate proposals (e.g. stochastic samples from a
high-temperature planner, or perturbation variants of one canonical),
prune to the top-K under a deterministic score that combines:

  - structural risk      (higher → more dangerous, ranks first to
                          be checked — block earliest)
  - admissibility cost   (higher → less likely to be admissible)
  - lexicographic tiebreaker on `(tool, sorted args items)` for
    determinism

The result is a bounded beam over candidates that the middleware can
evaluate in order; once K decisions are made the rest are dropped
with `pruning_rationale`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from runtime_eval.evaluators.risk_propagation import _step_risk


@dataclass
class PruneReport:
    kept: list = field(default_factory=list)         # list[ToolCall]
    dropped: list = field(default_factory=list)      # list[(ToolCall, reason)]
    beam: int = 0

    def as_dict(self) -> dict:
        return {"beam": self.beam,
                "kept": [dict(c) for c in self.kept],
                "dropped": [{"call": dict(c), "reason": r}
                              for c, r in self.dropped]}


def _key(call: dict) -> tuple:
    args = call.get("args") if isinstance(call.get("args"), dict) else {}
    return (str(call.get("tool", "")), tuple(sorted(args.items())))


def prune(candidates: Iterable[dict], *, beam: int = 8,
          risk_threshold: float = 1.01) -> PruneReport:
    """Keep up to `beam` candidates, sorted by descending risk so the
    most dangerous-looking are checked first. `risk_threshold > 1`
    keeps everything; lower it to drop benign-looking noise."""
    scored: list = []
    for c in candidates:
        r = _step_risk(c)
        scored.append((r, _key(c), c))
    # deterministic sort
    scored.sort(key=lambda t: (-t[0], t[1]))
    report = PruneReport(beam=beam)
    for r, _, c in scored:
        if r > risk_threshold:
            continue
        if len(report.kept) < beam:
            report.kept.append(c)
        else:
            report.dropped.append((c, "beyond_beam"))
    return report
