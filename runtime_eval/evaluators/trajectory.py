"""Multi-turn trajectory evaluator. Runs a planner through a fixed
observation sequence and asserts the classification of the final
trajectory + the per-turn verdict timeline."""

from __future__ import annotations

from dataclasses import dataclass, field

from runtime_eval.governance.middleware import RuntimeGovernanceMiddleware


@dataclass
class TrajectoryEvaluation:
    summary: dict
    verdicts: list
    fail_closed: bool


def evaluate_trajectory(middleware: RuntimeGovernanceMiddleware,
                         planner, observation: dict,
                         max_steps: int) -> TrajectoryEvaluation:
    res = middleware.run(planner, observation=observation,
                          max_steps=max_steps)
    return TrajectoryEvaluation(
        summary=res.summary,
        verdicts=[r.verdict for r in res.trace.records],
        fail_closed=res.trace.fail_closed_holds(),
    )
