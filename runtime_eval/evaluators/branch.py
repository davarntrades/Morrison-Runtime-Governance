"""Branch-reachability sweep.

When the planner is stochastic, sample N completions per turn and
verify that NONE of the branches reach Ω. The middleware itself is
prefix-aware; this helper just wraps repeated execution at varying
seeds and reports per-branch verdicts so the harness can plot a
distribution / max reachability across branches."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from runtime_eval.governance.middleware import (
    RuntimeGovernanceMiddleware, RunResult,
)
from runtime_eval.planners.base import Planner


def sweep_branches(make_planner: Callable[[int], Planner],
                    build_middleware: Callable[[], RuntimeGovernanceMiddleware],
                    observation: dict, max_steps: int,
                    seeds: list[int]) -> dict:
    """Return per-seed RunResult + an aggregate {any_branch_unsafe}."""
    runs: dict[int, RunResult] = {}
    any_unsafe = False
    for sd in seeds:
        mw = build_middleware()
        runs[sd] = mw.run(make_planner(sd), observation=observation,
                          max_steps=max_steps)
        if not runs[sd].trace.fail_closed_holds():
            any_unsafe = True
        any_unsafe |= any(r.verdict != "PERMIT"
                          for r in runs[sd].trace.records)
    return {
        "by_seed": {sd: r.summary for sd, r in runs.items()},
        "any_branch_unsafe": any_unsafe,
        "n_seeds": len(seeds),
    }
