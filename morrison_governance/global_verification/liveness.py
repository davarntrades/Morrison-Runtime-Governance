"""Liveness: does governed execution still reach the work it exists to do?

External review (2026-11): several governed finite models collapse to ONE
reachable state. `SAFE_WITHIN_MODEL` was then true for the least interesting
reason available: nothing could happen at all. A governor that refuses every
action is perfectly safe and perfectly useless, and the verdict did not tell
the two apart.

Each scenario now declares the LEGITIMATE goal states it exists to reach. The
verifier reports, per goal:

  reachable      EF goal from every initial state, along executed edges only.
                 A goal state counts only if it is also safe: reaching the goal
                 by violating an invariant is not legitimate completion.
  recoverable    AG EF goal: from every reachable configuration the goal is
                 still reachable. Informational; a model whose actions are
                 one-shot can legitimately strand some configurations.

and the verdict separates the cases:

  SAFE_WITHIN_MODEL   no unsafe state reachable AND every declared goal is
                      reachable from every initial state (or no goal was
                      declared, which the result states explicitly)
  SAFE_BUT_NOT_LIVE   no unsafe state reachable, but some declared goal is not
                      reachable under governance

A goal that is unreachable in the CONTROL model too is a model defect, not a
governance cost; the comparison reports which it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .state import VerificationState

LIVE = "LIVE"
NOT_LIVE = "NOT_LIVE"
NOT_DECLARED = "NOT_DECLARED"
NOT_ASSESSED = "NOT_ASSESSED"     # enumeration incomplete


@dataclass(frozen=True)
class LivenessGoal:
    identifier: str
    description: str
    predicate: Callable[[VerificationState], bool] = field(compare=False, repr=False)

    def evaluate(self, state: VerificationState) -> bool:
        result = self.predicate(state)
        if not isinstance(result, bool):
            raise TypeError(f"liveness goal {self.identifier} did not return bool")
        return result

    def definition(self) -> dict[str, str]:
        return {"identifier": self.identifier, "description": self.description}


def assess(
    goals: tuple[LivenessGoal, ...],
    *,
    complete: bool,
    initial_roots: dict[str, str],
    goal_nodes: dict[str, set[str]],
    shortest: dict[tuple[str, str], int],
    executed_edges: list[tuple[str, str]],
    all_nodes: set[str],
    adversarial_only: str = "",
) -> dict[str, Any]:
    """Build the liveness section of a traversal result.

    `initial_roots` maps initial state id -> root node id; `goal_nodes` maps
    goal id -> nodes that satisfy it safely; `shortest` maps (goal id, initial
    state id) -> shortest executed distance from that root.
    """
    if not goals:
        return {
            "status": NOT_DECLARED,
            "goals": [],
            "note": adversarial_only or (
                "No legitimate goal is declared for this model, so the result "
                "says nothing about whether governed execution can do useful work."
            ),
        }
    if not complete:
        return {"status": NOT_ASSESSED, "goals": [],
                "note": "enumeration incomplete; liveness cannot be established"}

    reverse: dict[str, list[str]] = {}
    for src, dst in executed_edges:
        reverse.setdefault(dst, []).append(src)

    report = []
    live = True
    for goal in goals:
        per_initial = {
            init: shortest.get((goal.identifier, init))
            for init in initial_roots
        }
        reachable = all(d is not None for d in per_initial.values())
        live = live and reachable
        # Backward closure from the goal nodes: every node that can still get
        # there. The rest are stranded.
        can_reach = set(goal_nodes.get(goal.identifier, ()))
        stack = list(can_reach)
        while stack:
            node = stack.pop()
            for prev in reverse.get(node, ()):
                if prev not in can_reach:
                    can_reach.add(prev)
                    stack.append(prev)
        stranded = len(all_nodes - can_reach)
        report.append({
            **goal.definition(),
            "reachable_from_every_initial_state": reachable,
            "shortest_distance_per_initial_state": per_initial,
            "recoverable_from_every_reachable_configuration": stranded == 0,
            "stranded_configurations": stranded,
        })
    return {"status": LIVE if live else NOT_LIVE, "goals": report}
