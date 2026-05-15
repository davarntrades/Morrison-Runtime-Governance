"""
V4+ — Feasibility / NO_VALID_SAFE_TRAJECTORY detection.

Given a goal predicate and a list of candidate trajectories, V4+ asks:
"is there at least one trajectory among the candidates that (a) clears the
hierarchy A_safe → V2 → V3 → V4 and (b) satisfies the goal?"

If no candidate satisfies both, the layer returns NO_VALID_SOLUTION rather
than letting the caller pick something unsafe by default. This is the
"refuse to guess" surface — important for agentic systems that would
otherwise execute the least-bad infeasible plan.

Determinism: candidates are evaluated in the order supplied; the first
admissible-and-goal-satisfying trajectory wins. No tie-breaking by
randomness.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional

from morrison_governance.result import GovernanceResult, GovernanceVerdict
from morrison_governance.trajectory import Trajectory


# Goal predicate: takes (last_state_dict, full_trajectory) and returns True
# iff the trajectory satisfies the caller's goal.
GoalPredicate = Callable[[dict, Trajectory], bool]


@dataclass
class FeasibilityReport:
    """Per-candidate diagnostic for a feasibility evaluation."""

    candidate_index: int
    trajectory_hash: str
    admissible: bool
    goal_satisfied: bool
    blocking_layer: Optional[str] = None
    blocking_reason: Optional[str] = None


@dataclass
class FeasibilityEvaluator:
    """Selects the first admissible-and-goal-satisfying trajectory.

    `runner` is a callable (typically `GovernanceLayer._run`) that evaluates
    a Trajectory and returns a GovernanceResult. Decoupling this from the
    GovernanceLayer object lets the evaluator be tested in isolation."""

    runner: Callable[[Trajectory], GovernanceResult]

    def find_admissible(
        self,
        candidates: list[Trajectory],
        goal: GoalPredicate,
    ) -> tuple[GovernanceResult, list[FeasibilityReport]]:
        reports: list[FeasibilityReport] = []
        for i, traj in enumerate(candidates):
            result = self.runner(traj)
            admissible = result.permitted
            goal_ok = goal(self._last_state(traj), traj) if admissible else False
            reports.append(FeasibilityReport(
                candidate_index=i,
                trajectory_hash=traj.hash,
                admissible=admissible,
                goal_satisfied=goal_ok,
                blocking_layer=None if admissible else result.layer,
                blocking_reason=None if admissible else result.reason,
            ))
            if admissible and goal_ok:
                # Tag the winning result with V4+ metadata so callers can
                # see this came through feasibility selection.
                result.metadata.setdefault("v4_plus", {})
                result.metadata["v4_plus"] = {
                    "selected_index": i,
                    "candidates_considered": len(reports),
                    "candidates_total": len(candidates),
                }
                return result, reports

        # No candidate cleared both gates.
        admissible_count = sum(1 for r in reports if r.admissible)
        no_solution = GovernanceResult(
            verdict=GovernanceVerdict.NO_VALID_SOLUTION,
            layer="V4+",
            reason=(
                f"No admissible-and-goal-satisfying trajectory among "
                f"{len(candidates)} candidates "
                f"({admissible_count} admissible but goal not met, "
                f"{len(candidates) - admissible_count} blocked by hierarchy)"
            ),
            metadata={
                "v4_plus_reports": [r.__dict__ for r in reports],
                "candidates_total": len(candidates),
                "candidates_admissible": admissible_count,
            },
        )
        return no_solution, reports

    @staticmethod
    def _last_state(traj: Trajectory) -> dict:
        if not traj.states:
            return {}
        return traj.states[-1].to_eval_dict()


# ─────────────────────────────────────────────────────────────
# Goal predicate builders
# ─────────────────────────────────────────────────────────────

def goal_uses_tool(required_tool: str) -> GoalPredicate:
    """Goal: trajectory must invoke `required_tool` at some step."""
    def _g(_last: dict, traj: Trajectory) -> bool:
        return any(s.tool == required_tool for s in traj)
    return _g


def goal_visits_state(predicate: Callable[[dict], bool]) -> GoalPredicate:
    """Goal: at least one state in the trajectory satisfies `predicate`."""
    def _g(_last: dict, traj: Trajectory) -> bool:
        return any(predicate(s.to_eval_dict()) for s in traj)
    return _g


def goal_terminates_with(tool: str) -> GoalPredicate:
    """Goal: the *last* step must invoke `tool`."""
    def _g(last: dict, _traj: Trajectory) -> bool:
        return last.get("tool") == tool
    return _g


def goal_all(*predicates: GoalPredicate) -> GoalPredicate:
    """Conjunction of multiple goal predicates."""
    def _g(last: dict, traj: Trajectory) -> bool:
        return all(p(last, traj) for p in predicates)
    return _g
