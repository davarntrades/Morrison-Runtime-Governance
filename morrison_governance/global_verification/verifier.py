"""Exhaustive BFS/DFS reachability over a finite modeled environment."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict

from .counterexample import Counterexample, CounterexampleStep
from .environment import FiniteEnvironment
from .evidence import GraphEdge, GraphEvidence, GraphNode
from .governance import GovernanceAdapter, GovernanceDecision
from .state import VerificationState, stable_hash


SAFE_WITHIN_MODEL = "SAFE_WITHIN_MODEL"
UNSAFE_COUNTEREXAMPLE_FOUND = "UNSAFE_COUNTEREXAMPLE_FOUND"
INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class VerificationLimits:
    max_states: int = 10_000
    max_edges: int = 100_000
    max_depth: int = 64
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.max_states < 1 or self.max_edges < 1 or self.max_depth < 0:
            raise ValueError("verification limits must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")


@dataclass
class TraversalResult:
    mode: str
    verdict: str
    complete: bool
    stop_reason: str | None
    algorithm: str
    explored_configurations: int
    reachable_state_ids: tuple[str, ...]
    reachable_edge_count: int
    proposed_edge_count: int
    blocked_edge_count: int
    blocked_unsafe_edge_count: int
    unsafe_state_ids: tuple[str, ...]
    unsafe_reachable_edge_count: int
    unexplored_frontier_size: int
    graph: GraphEvidence
    counterexample: Counterexample | None = None
    per_initial_state: list[dict[str, Any]] = field(default_factory=list)

    @property
    def reachable_state_count(self) -> int:
        return len(self.reachable_state_ids)

    @property
    def unsafe_reachable_state_count(self) -> int:
        return len(self.unsafe_state_ids)

    @property
    def shortest_unsafe_path(self) -> int | None:
        return self.counterexample.distance if self.counterexample else None

    def to_dict(self, *, include_graph: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "mode": self.mode,
            "verdict": self.verdict,
            "complete_enumeration": self.complete,
            "stop_reason": self.stop_reason,
            "algorithm": self.algorithm,
            "explored_configurations": self.explored_configurations,
            "reachable_state_count": self.reachable_state_count,
            "reachable_state_ids": list(self.reachable_state_ids),
            "reachable_edge_count": self.reachable_edge_count,
            "proposed_edge_count": self.proposed_edge_count,
            "blocked_edge_count": self.blocked_edge_count,
            "blocked_unsafe_edge_count": self.blocked_unsafe_edge_count,
            "unsafe_reachable_state_count": self.unsafe_reachable_state_count,
            "unsafe_state_ids": list(self.unsafe_state_ids),
            "unsafe_reachable_edge_count": self.unsafe_reachable_edge_count,
            "shortest_unsafe_path": self.shortest_unsafe_path,
            "unexplored_frontier_size": self.unexplored_frontier_size,
            "counterexample": self.counterexample.to_dict() if self.counterexample else None,
            "per_initial_state": self.per_initial_state,
        }
        if include_graph:
            result["graph"] = self.graph.to_dict()
        return result


EscalationResolver = Callable[[Dict[str, Any], GovernanceDecision], bool]


class ExhaustiveVerifier:
    """Enumerate every finite executable configuration without sampling."""

    def __init__(
        self,
        environment: FiniteEnvironment,
        governance: GovernanceAdapter | None = None,
        *,
        limits: VerificationLimits | None = None,
        algorithm: str = "bfs",
        escalation_resolver: EscalationResolver | None = None,
    ):
        if algorithm not in {"bfs", "dfs"}:
            raise ValueError("algorithm must be 'bfs' or 'dfs'")
        self.environment = environment
        self.governance = governance
        self.limits = limits or VerificationLimits()
        self.algorithm = algorithm
        self.escalation_resolver = escalation_resolver

    @property
    def mode(self) -> str:
        return "GOVERNED" if self.governance is not None else "CONTROL"

    def verify(self) -> TraversalResult:
        started = time.monotonic()
        graph = GraphEvidence()
        reachable_states: set[str] = set()
        unsafe_states: set[str] = set()
        unsafe_edges = 0
        blocked_edges = 0
        blocked_unsafe_edges = 0
        counterexample: Counterexample | None = None
        per_initial: list[dict[str, Any]] = []
        complete = True
        stop_reason: str | None = None
        frontier_size = 0

        try:
            # Fail before traversal if the declared model is not serializable.
            stable_hash(self.environment.definition())
        except Exception as exc:  # noqa: BLE001 - INCONCLUSIVE is mandatory
            return self._inconclusive(
                graph, f"model serialization failed: {type(exc).__name__}: {exc}"
            )

        for initial_index, initial in enumerate(self.environment.initial_states):
            initial_graph_nodes = len(graph.nodes)
            initial_edges = len(graph.edges)
            initial_unsafe = len(unsafe_states)
            queue: deque[tuple[
                VerificationState,
                tuple[dict[str, Any], ...],
                str,
                int,
                tuple[CounterexampleStep, ...],
            ]] = deque()
            visited: set[str] = set()

            try:
                initial_violations = self.environment.unsafe(initial)
                root_id = self._node_id(initial, (), initial.state_id)
            except Exception as exc:  # noqa: BLE001
                complete = False
                stop_reason = f"initial state evaluation failed: {type(exc).__name__}: {exc}"
                break

            root = GraphNode(
                node_id=root_id,
                state_id=initial.state_id,
                state=initial.to_dict(),
                safe=not initial_violations,
                unsafe_invariants=tuple(item.identifier for item in initial_violations),
                depth=0,
                initial=True,
            )
            graph.add_node(root)
            visited.add(root_id)
            reachable_states.add(initial.state_id)
            queue.append((initial, (), root_id, 0, ()))
            if initial_violations:
                unsafe_states.add(initial.state_id)
                candidate = Counterexample(
                    initial_state=initial.to_dict(),
                    initial_state_id=initial.state_id,
                    steps=(),
                    violated_invariants=tuple(item.definition() for item in initial_violations),
                    final_unsafe_state=initial.to_dict(),
                    final_unsafe_state_id=initial.state_id,
                )
                counterexample = self._prefer(counterexample, candidate)

            while queue:
                if time.monotonic() - started >= self.limits.timeout_seconds:
                    complete = False
                    stop_reason = "timeout_seconds reached before graph exhaustion"
                    frontier_size = len(queue)
                    break

                state, history, source_id, depth, path = (
                    queue.popleft() if self.algorithm == "bfs" else queue.pop()
                )
                try:
                    available = self.environment.available_actions(state)
                except Exception as exc:  # noqa: BLE001
                    complete = False
                    stop_reason = f"action precondition failed: {type(exc).__name__}: {exc}"
                    frontier_size = len(queue)
                    break

                if depth >= self.limits.max_depth and available:
                    complete = False
                    stop_reason = "max_depth reached before graph exhaustion"
                    frontier_size = len(queue) + 1
                    break

                for action in available:
                    if len(graph.edges) >= self.limits.max_edges:
                        complete = False
                        stop_reason = "max_edges reached before graph exhaustion"
                        frontier_size = len(queue) + 1
                        break
                    if time.monotonic() - started >= self.limits.timeout_seconds:
                        complete = False
                        stop_reason = "timeout_seconds reached before graph exhaustion"
                        frontier_size = len(queue) + 1
                        break

                    try:
                        proposal = action.propose(state)
                        stable_hash(proposal)
                        # This is a pure counterfactual preview. A blocked edge is
                        # never added to the reachable queue or executable graph.
                        successor = self.environment.transition(state, action)
                        violations = self.environment.unsafe(successor)
                        decision = self._decision(history, proposal)
                    except Exception as exc:  # noqa: BLE001
                        complete = False
                        stop_reason = (
                            f"verification step {action.name!r} failed: "
                            f"{type(exc).__name__}: {exc}"
                        )
                        frontier_size = len(queue) + 1
                        break

                    execute = self._is_executable(proposal, decision)
                    next_history = history + (proposal,)
                    destination_id: str | None = None
                    if execute:
                        destination_id = self._node_id(
                            successor, next_history, initial.state_id
                        )
                        if (
                            destination_id not in visited
                            and len(graph.nodes) >= self.limits.max_states
                        ):
                            complete = False
                            stop_reason = "max_states reached before graph exhaustion"
                            frontier_size = len(queue) + 1
                            break

                    edge_id = "edge-" + stable_hash(
                        {
                            "source": source_id,
                            "destination": destination_id,
                            "action": action.name,
                            "proposal": proposal,
                            "verdict": decision.verdict,
                        }
                    )[:20]
                    edge = GraphEdge(
                        edge_id=edge_id,
                        source=source_id,
                        destination=destination_id,
                        action=action.name,
                        proposed_action=proposal,
                        governance_verdict=decision.verdict,
                        executed=execute,
                        blocked=not execute,
                        layer=decision.layer,
                        reason=decision.reason,
                        rule=decision.rule,
                        omega_domain=decision.omega_domain,
                        counterfactual_state_id=(successor.state_id if not execute else None),
                        counterfactual_unsafe_invariants=(
                            tuple(item.identifier for item in violations) if not execute else ()
                        ),
                    )
                    graph.add_edge(edge)

                    if not execute:
                        blocked_edges += 1
                        if violations:
                            blocked_unsafe_edges += 1
                        continue

                    reachable_states.add(successor.state_id)
                    if violations:
                        unsafe_states.add(successor.state_id)
                        unsafe_edges += 1

                    step = CounterexampleStep(
                        action=action.name,
                        proposed_action=proposal,
                        governance_verdict=decision.verdict,
                        governance_layer=decision.layer,
                        governance_reason=decision.reason,
                        resulting_state=successor.to_dict(),
                        resulting_state_id=successor.state_id,
                        unsafe_invariants=tuple(item.identifier for item in violations),
                    )
                    next_path = path + (step,)
                    if violations:
                        candidate = Counterexample(
                            initial_state=initial.to_dict(),
                            initial_state_id=initial.state_id,
                            steps=next_path,
                            violated_invariants=tuple(item.definition() for item in violations),
                            final_unsafe_state=successor.to_dict(),
                            final_unsafe_state_id=successor.state_id,
                        )
                        counterexample = self._prefer(counterexample, candidate)

                    if destination_id not in visited:
                        graph.add_node(
                            GraphNode(
                                node_id=destination_id,
                                state_id=successor.state_id,
                                state=successor.to_dict(),
                                safe=not violations,
                                unsafe_invariants=tuple(
                                    item.identifier for item in violations
                                ),
                                depth=depth + 1,
                            )
                        )
                        visited.add(destination_id)
                        queue.append(
                            (successor, next_history, destination_id, depth + 1, next_path)
                        )
                if not complete:
                    break

            per_initial.append(
                {
                    "initial_state_id": initial.state_id,
                    "complete_enumeration": complete,
                    "explored_configurations": len(graph.nodes) - initial_graph_nodes,
                    "proposed_edges": len(graph.edges) - initial_edges,
                    "new_unsafe_states": len(unsafe_states) - initial_unsafe,
                }
            )
            if not complete:
                break

        if not complete:
            verdict = INCONCLUSIVE
        elif unsafe_states:
            verdict = UNSAFE_COUNTEREXAMPLE_FOUND
        else:
            verdict = SAFE_WITHIN_MODEL

        return TraversalResult(
            mode=self.mode,
            verdict=verdict,
            complete=complete,
            stop_reason=stop_reason,
            algorithm=self.algorithm,
            explored_configurations=len(graph.nodes),
            reachable_state_ids=tuple(sorted(reachable_states)),
            reachable_edge_count=sum(1 for edge in graph.edges.values() if edge.executed),
            proposed_edge_count=len(graph.edges),
            blocked_edge_count=blocked_edges,
            blocked_unsafe_edge_count=blocked_unsafe_edges,
            unsafe_state_ids=tuple(sorted(unsafe_states)),
            unsafe_reachable_edge_count=unsafe_edges,
            unexplored_frontier_size=frontier_size,
            graph=graph,
            counterexample=counterexample,
            per_initial_state=per_initial,
        )

    def _decision(
        self, history: tuple[dict[str, Any], ...], proposal: dict[str, Any]
    ) -> GovernanceDecision:
        if self.governance is None:
            return GovernanceDecision(
                verdict="CONTROL_EXECUTE",
                permitted=True,
                layer="control",
                reason="governance intentionally absent in control mode",
            )
        return self.governance.evaluate(history, proposal)

    def _is_executable(
        self, proposal: dict[str, Any], decision: GovernanceDecision
    ) -> bool:
        if self.governance is None:
            return True
        if decision.verdict == "PERMIT":
            if not decision.permitted:
                raise ValueError("governance returned PERMIT with permitted=False")
            return True
        if decision.verdict == "ESCALATE":
            # Unresolved ESCALATE is non-executable. Only an explicit scenario
            # resolver can turn this particular proposal into an execution.
            return bool(
                self.escalation_resolver
                and self.escalation_resolver(proposal, decision)
            )
        if decision.verdict in {
            "BLOCK",
            "NO_VALID_SOLUTION",
            "ENVIRONMENT_SENSITIVE",
        }:
            return False
        raise ValueError(f"unrecognized governance verdict {decision.verdict!r}")

    @staticmethod
    def _node_id(
        state: VerificationState,
        history: tuple[dict[str, Any], ...],
        initial_state_id: str,
    ) -> str:
        return "node-" + stable_hash(
            {
                "initial_state_id": initial_state_id,
                "state": state.to_dict(),
                "executed_history": list(history),
            }
        )[:20]

    def _inconclusive(self, graph: GraphEvidence, reason: str) -> TraversalResult:
        return TraversalResult(
            mode=self.mode,
            verdict=INCONCLUSIVE,
            complete=False,
            stop_reason=reason,
            algorithm=self.algorithm,
            explored_configurations=len(graph.nodes),
            reachable_state_ids=(),
            reachable_edge_count=0,
            proposed_edge_count=len(graph.edges),
            blocked_edge_count=0,
            blocked_unsafe_edge_count=0,
            unsafe_state_ids=(),
            unsafe_reachable_edge_count=0,
            unexplored_frontier_size=0,
            graph=graph,
        )

    @staticmethod
    def _prefer(
        current: Counterexample | None, candidate: Counterexample
    ) -> Counterexample:
        if current is None or candidate.distance < current.distance:
            return candidate
        return current
