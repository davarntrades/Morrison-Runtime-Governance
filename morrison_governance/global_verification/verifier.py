"""Exhaustive BFS/DFS reachability over a finite modeled environment."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable

from .counterexample import Counterexample, CounterexampleStep
from .environment import FiniteEnvironment
from .evidence import GraphEdge, GraphEvidence, GraphNode
from .governance import (
    ESCALATION_APPROVED_AUTHORIZATION,
    PERMIT_AUTHORIZATION,
    ExecutedStep,
    GovernanceAdapter,
    GovernanceDecision,
)
from .state import VerificationState, stable_hash


SAFE_WITHIN_MODEL = "SAFE_WITHIN_MODEL"
UNSAFE_COUNTEREXAMPLE_FOUND = "UNSAFE_COUNTEREXAMPLE_FOUND"
INCONCLUSIVE = "INCONCLUSIVE"

ESCALATION_APPROVE = "approve"
ESCALATION_DENY = "deny"
# Canonical emission order. Deny first keeps edge ordering stable and lets BFS
# reach the cheapest denied frontier before the approved one.
ESCALATION_OUTCOMES = (ESCALATION_DENY, ESCALATION_APPROVE)

NON_EXECUTABLE_VERDICTS = frozenset(
    {"BLOCK", "NO_VALID_SOLUTION", "ENVIRONMENT_SENSITIVE"}
)


@dataclass(frozen=True)
class _Branch:
    """One enumerable resolution of a single proposed action.

    A PERMIT or a BLOCK has exactly one resolution. An ESCALATE has as many as
    the escalation policy declares admissible, and each is a separate edge.
    """

    decision: GovernanceDecision
    executed: bool
    escalation_outcome: str | None = None
    origin_verdict: str | None = None

    @property
    def authorization(self) -> str:
        if self.escalation_outcome == ESCALATION_APPROVE:
            return ESCALATION_APPROVED_AUTHORIZATION
        return PERMIT_AUTHORIZATION


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
    approved_escalation_edge_count: int
    denied_escalation_edge_count: int
    # Which resolutions of an escalation this run actually enumerated. Observed
    # from the graph, never taken on the caller's word, so it cannot be
    # misdeclared in the artifact that carries it.
    escalation_outcomes_admitted: tuple[str, ...]
    unsafe_state_ids: tuple[str, ...]
    unsafe_reachable_edge_count: int
    unexplored_frontier_size: int
    graph: GraphEvidence
    counterexample: Counterexample | None = None
    per_initial_state: list[dict[str, Any]] = field(default_factory=list)
    # edge_id -> record_hash of the REAL kernel evidence record behind it.
    # Per-run, not reproducible across runs: the kernel timestamps an executed
    # record with wall-clock time, so every record chained after one differs
    # between runs. That is production behaviour, not drift, and it is why this
    # binding is kept out of the deterministic graph export.
    evidence_bindings: dict[str, str] = field(default_factory=dict)

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
            "approved_escalation_edge_count": self.approved_escalation_edge_count,
            "denied_escalation_edge_count": self.denied_escalation_edge_count,
            "escalation_outcomes_admitted": list(self.escalation_outcomes_admitted),
            "evidence_bindings": dict(sorted(self.evidence_bindings.items())),
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


# Legacy form: True meant "this proposal may execute". It is still accepted and
# is normalised below, but a bare True now enumerates BOTH resolutions, because
# "approval is possible here" does not mean "approval is certain here".
EscalationResolver = Callable[[Dict[str, Any], GovernanceDecision], bool]
# Current form: return which resolutions of this escalation the model admits,
# as any iterable over {"approve", "deny"}.
EscalationPolicy = Callable[
    [Dict[str, Any], GovernanceDecision], "bool | Iterable[str]"
]


class ExhaustiveVerifier:
    """Enumerate every finite executable configuration without sampling."""

    def __init__(
        self,
        environment: FiniteEnvironment,
        governance: GovernanceAdapter | None = None,
        *,
        limits: VerificationLimits | None = None,
        algorithm: str = "bfs",
        escalation_policy: EscalationPolicy | None = None,
        escalation_resolver: EscalationResolver | None = None,
    ):
        if algorithm not in {"bfs", "dfs"}:
            raise ValueError("algorithm must be 'bfs' or 'dfs'")
        if escalation_policy is not None and escalation_resolver is not None:
            raise ValueError(
                "pass escalation_policy or escalation_resolver, not both"
            )
        self.environment = environment
        self.governance = governance
        self.limits = limits or VerificationLimits()
        self.algorithm = algorithm
        # `escalation_resolver` is the legacy spelling of the same hook.
        self.escalation_policy = escalation_policy or escalation_resolver
        self.escalation_resolver = self.escalation_policy

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
        approved_escalations = 0
        denied_escalations = 0
        evidence_bindings: dict[str, str] = {}
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
                tuple[ExecutedStep, ...],
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
                    try:
                        proposal = action.propose(state)
                        stable_hash(proposal)
                        # This is a pure counterfactual preview. A blocked edge is
                        # never added to the reachable queue or executable graph.
                        successor = self.environment.transition(state, action)
                        violations = self.environment.unsafe(successor)
                        decision = self._decision(history, proposal)
                        branches = self._branches(history, proposal, decision)
                    except Exception as exc:  # noqa: BLE001
                        complete = False
                        stop_reason = (
                            f"verification step {action.name!r} failed: "
                            f"{type(exc).__name__}: {exc}"
                        )
                        frontier_size = len(queue) + 1
                        break

                    for branch in branches:
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

                        execute = branch.executed
                        next_history = history + (
                            ExecutedStep(proposal, branch.authorization),
                        )
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

                        identity: dict[str, Any] = {
                            "source": source_id,
                            "destination": destination_id,
                            "action": action.name,
                            "proposal": proposal,
                            "verdict": branch.decision.verdict,
                        }
                        if branch.escalation_outcome == ESCALATION_APPROVE:
                            # A denied escalation IS the pre-existing blocked
                            # edge and keeps its identity; only the newly
                            # enumerable approve branch needs disambiguating.
                            identity["escalation_outcome"] = ESCALATION_APPROVE
                        edge_id = "edge-" + stable_hash(identity)[:20]
                        edge = GraphEdge(
                            edge_id=edge_id,
                            source=source_id,
                            destination=destination_id,
                            action=action.name,
                            proposed_action=proposal,
                            governance_verdict=branch.decision.verdict,
                            executed=execute,
                            blocked=not execute,
                            layer=branch.decision.layer,
                            reason=branch.decision.reason,
                            rule=branch.decision.rule,
                            omega_domain=branch.decision.omega_domain,
                            counterfactual_state_id=(
                                successor.state_id if not execute else None
                            ),
                            counterfactual_unsafe_invariants=(
                                tuple(item.identifier for item in violations)
                                if not execute
                                else ()
                            ),
                            escalation_outcome=branch.escalation_outcome,
                            escalation_origin_verdict=branch.origin_verdict,
                            action_hash=branch.decision.action_hash,
                            semantic_hash=branch.decision.semantic_hash,
                        )
                        graph.add_edge(edge)
                        if branch.decision.evidence_hash:
                            evidence_bindings[edge_id] = branch.decision.evidence_hash

                        if not execute:
                            blocked_edges += 1
                            if branch.escalation_outcome == ESCALATION_DENY:
                                denied_escalations += 1
                            if violations:
                                blocked_unsafe_edges += 1
                            continue

                        if branch.escalation_outcome == ESCALATION_APPROVE:
                            # Counts approvals that actually carried execution.
                            # An approve branch governance still refuses stays
                            # in blocked_edges, flagged in the graph.
                            approved_escalations += 1
                        reachable_states.add(successor.state_id)
                        if violations:
                            unsafe_states.add(successor.state_id)
                            unsafe_edges += 1

                        step = CounterexampleStep(
                            action=action.name,
                            proposed_action=proposal,
                            governance_verdict=branch.decision.verdict,
                            governance_layer=branch.decision.layer,
                            governance_reason=branch.decision.reason,
                            resulting_state=successor.to_dict(),
                            resulting_state_id=successor.state_id,
                            unsafe_invariants=tuple(
                                item.identifier for item in violations
                            ),
                            escalation_outcome=branch.escalation_outcome,
                        )
                        next_path = path + (step,)
                        if violations:
                            candidate = Counterexample(
                                initial_state=initial.to_dict(),
                                initial_state_id=initial.state_id,
                                steps=next_path,
                                violated_invariants=tuple(
                                    item.definition() for item in violations
                                ),
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
                                (
                                    successor,
                                    next_history,
                                    destination_id,
                                    depth + 1,
                                    next_path,
                                )
                            )
                    if not complete:
                        break
                if not complete:
                    break

            per_initial.append(
                {
                    "initial_state_id": initial.state_id,
                    "complete_enumeration": complete,
                    "explored_configurations": len(graph.nodes) - initial_graph_nodes,
                    "proposed_edges": len(graph.edges) - initial_edges,
                    "new_unsafe_states": len(unsafe_states) - initial_unsafe,
                    "approved_escalations": approved_escalations,
                    "denied_escalations": denied_escalations,
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
            approved_escalation_edge_count=approved_escalations,
            denied_escalation_edge_count=denied_escalations,
            escalation_outcomes_admitted=tuple(
                item for item in ESCALATION_OUTCOMES
                if any(edge.escalation_outcome == item for edge in graph.edges.values())
            ),
            evidence_bindings=evidence_bindings,
            unsafe_state_ids=tuple(sorted(unsafe_states)),
            unsafe_reachable_edge_count=unsafe_edges,
            unexplored_frontier_size=frontier_size,
            graph=graph,
            counterexample=counterexample,
            per_initial_state=per_initial,
        )

    def _escalation_outcomes(
        self, proposal: dict[str, Any], decision: GovernanceDecision
    ) -> tuple[str, ...]:
        """Which resolutions of this escalation the declared model admits.

        With no policy the answer is `deny` alone, which is the standing
        assumption "an unresolved ESCALATE is non-executable" and reproduces
        the pre-existing traversal exactly.
        """
        if self.escalation_policy is None:
            return (ESCALATION_DENY,)
        raw = self.escalation_policy(proposal, decision)
        if isinstance(raw, bool):
            # Legacy bool hook. True says approval is ADMISSIBLE here, not that
            # it is guaranteed, so exhaustiveness requires both resolutions.
            return ESCALATION_OUTCOMES if raw else (ESCALATION_DENY,)
        outcomes = set(raw)
        unknown = sorted(outcomes - set(ESCALATION_OUTCOMES))
        if unknown:
            raise ValueError(f"escalation policy returned unknown outcome(s) {unknown}")
        if not outcomes:
            raise ValueError(
                "escalation policy returned no admissible outcome; an escalation "
                "must resolve to at least one of "
                f"{list(ESCALATION_OUTCOMES)}"
            )
        return tuple(item for item in ESCALATION_OUTCOMES if item in outcomes)

    def _branches(
        self,
        history: tuple[ExecutedStep, ...],
        proposal: dict[str, Any],
        decision: GovernanceDecision,
    ) -> tuple[_Branch, ...]:
        """Expand one governance decision into every edge it licenses."""
        if self.governance is None:
            return (_Branch(decision, True),)
        if decision.verdict == "PERMIT":
            if not decision.permitted:
                raise ValueError("governance returned PERMIT with permitted=False")
            return (_Branch(decision, True),)
        if decision.verdict in NON_EXECUTABLE_VERDICTS:
            return (_Branch(decision, False),)
        if decision.verdict == "ESCALATE":
            branches: list[_Branch] = []
            for outcome in self._escalation_outcomes(proposal, decision):
                if outcome == ESCALATION_DENY:
                    # Unresolved escalation: recorded, never executed.
                    branches.append(
                        _Branch(decision, False, ESCALATION_DENY, decision.verdict)
                    )
                    continue
                approved = self._approve(history, proposal, decision)
                branches.append(
                    _Branch(
                        approved,
                        approved.verdict == "PERMIT" and approved.permitted,
                        ESCALATION_APPROVE,
                        decision.verdict,
                    )
                )
            return tuple(branches)
        raise ValueError(f"unrecognized governance verdict {decision.verdict!r}")

    def _approve(
        self,
        history: tuple[ExecutedStep, ...],
        proposal: dict[str, Any],
        decision: GovernanceDecision,
    ) -> GovernanceDecision:
        """Ask governance what it decides once approval IS presented.

        The verifier never grants authority itself. If the adapter cannot model
        an authorised resolution, that is an error and the run fails closed —
        it is never treated as permission.
        """
        approve = getattr(self.governance, "approve_escalation", None)
        if approve is None:
            raise ValueError(
                "escalation policy admits approval but governance adapter "
                f"{type(self.governance).__name__!r} cannot authorise an "
                "escalation; refusing to execute it"
            )
        approved = approve(history, proposal, decision)
        if not isinstance(approved, GovernanceDecision):
            raise TypeError("approve_escalation did not return a GovernanceDecision")
        if approved.verdict == "PERMIT" and not approved.permitted:
            raise ValueError(
                "approved escalation returned PERMIT with permitted=False"
            )
        # A decision that STILL escalates once a verified approval is in hand is
        # a real outcome, not a failure: this escalation is not resolvable by
        # approval at all (an unknown tool, for instance, declares no capability
        # for an approval to satisfy). It is recorded, and it does not execute.
        return approved

    def _decision(
        self, history: tuple[ExecutedStep, ...], proposal: dict[str, Any]
    ) -> GovernanceDecision:
        if self.governance is None:
            return GovernanceDecision(
                verdict="CONTROL_EXECUTE",
                permitted=True,
                layer="control",
                reason="governance intentionally absent in control mode",
            )
        return self.governance.evaluate(history, proposal)

    @staticmethod
    def _node_id(
        state: VerificationState,
        history: tuple[ExecutedStep, ...],
        initial_state_id: str,
    ) -> str:
        """Identity of a trajectory, not of a state.

        The executed proposal sequence alone still determines the trajectory:
        a given action contributes at most ONE executed successor per node, so
        adding the approve branch cannot collide two distinct paths here.
        """
        return "node-" + stable_hash(
            {
                "initial_state_id": initial_state_id,
                "state": state.to_dict(),
                "executed_history": [step.proposal for step in history],
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
            approved_escalation_edge_count=0,
            denied_escalation_edge_count=0,
            escalation_outcomes_admitted=(),
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
