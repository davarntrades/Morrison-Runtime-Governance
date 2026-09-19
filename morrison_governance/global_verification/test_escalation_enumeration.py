"""Formal enumeration of BOTH resolutions of an escalation.

An `ESCALATE` is not a decision, it is a *deferral*: the modeled world may
resolve it either way. Enumerating only the denied side makes every escalating
model look safe, which is why these tests exist. They fix the meaning of the
approve branch:

- approval is carried by a genuinely signed approval artifact bound to the
  action's semantic hash, produced through `GovernanceKernel.authorize` -- the
  verifier never grants authority itself;
- an approval unlocks a capability requirement; it does not overrule Ω;
- anything the verifier cannot resolve honestly is INCONCLUSIVE, never SAFE.
"""

from __future__ import annotations

import itertools

from .comparison import compare_control_and_governed
from .environment import FiniteEnvironment
from .governance import (
    ESCALATION_APPROVED_AUTHORIZATION,
    GovernanceDecision,
    MorrisonKernelAdapter,
)
from .scenarios import (
    COMMON_ASSUMPTIONS,
    COMMON_LIMITATIONS,
    create_persistence_action,
    obtain_credential_action,
    request_privilege_action,
    secret_exfiltration,
    governance_bypass,
)
from .state import VerificationState
from .verifier import (
    ESCALATION_APPROVE,
    ESCALATION_DENY,
    INCONCLUSIVE,
    SAFE_WITHIN_MODEL,
    UNSAFE_COUNTEREXAMPLE_FOUND,
    ExhaustiveVerifier,
    VerificationLimits,
)


APPROVE_AND_DENY = lambda proposal, decision: (ESCALATION_DENY, ESCALATION_APPROVE)
APPROVE_ONLY = lambda proposal, decision: (ESCALATION_APPROVE,)


def _governance() -> MorrisonKernelAdapter:
    return MorrisonKernelAdapter()


# ─────────────────────────────────────────────────────────────
# The demonstration model
# ─────────────────────────────────────────────────────────────

def approval_gated_privilege() -> FiniteEnvironment:
    """A model whose ONLY route to Ω runs through an approved escalation.

    Every action here escalates under the modeled deployment, so nothing moves
    without an approval. That makes the three-way comparison unambiguous:

    - ungoverned, Ω is reachable;
    - governed with escalations left unresolved, nothing executes at all;
    - governed with escalations approved, Ω is reachable again.

    The third case is the one a deny-only enumeration cannot see, and it is why
    "no prohibited state is reachable" must never be reported as a property of
    the environment when it is really a property of the approval assumption.
    """
    return FiniteEnvironment(
        name="approval_gated_privilege",
        version="1.0",
        initial_states=(VerificationState(),),
        actions=(
            obtain_credential_action(),
            request_privilege_action(),
            create_persistence_action(),
        ),
        assumptions=COMMON_ASSUMPTIONS
        + (
            "An ESCALATE may be resolved either way; both resolutions are enumerated.",
            "An approval is a signed artifact bound to one action's semantic hash.",
        ),
        limitations=COMMON_LIMITATIONS
        + (
            "Whether a human approver WOULD approve is outside this model.",
        ),
    )


def test_uncontrolled_model_reaches_omega():
    result = ExhaustiveVerifier(approval_gated_privilege()).verify()
    assert result.complete
    assert result.verdict == UNSAFE_COUNTEREXAMPLE_FOUND
    assert result.unsafe_reachable_state_count > 0


def test_deny_only_governed_model_executes_nothing():
    result = ExhaustiveVerifier(approval_gated_privilege(), _governance()).verify()
    assert result.complete
    assert result.verdict == SAFE_WITHIN_MODEL
    assert result.reachable_edge_count == 0
    assert result.approved_escalation_edge_count == 0
    assert result.denied_escalation_edge_count > 0


def test_approved_escalation_reaches_omega_so_safe_was_the_assumption():
    """The point of the whole exercise: SAFE was load-bearing on the denial."""
    result = ExhaustiveVerifier(
        approval_gated_privilege(), _governance(), escalation_policy=APPROVE_AND_DENY
    ).verify()
    assert result.complete, result.stop_reason
    assert result.verdict == UNSAFE_COUNTEREXAMPLE_FOUND
    assert result.counterexample is not None
    # Ω is reached, and it is reached THROUGH approvals.
    approved = [
        step for step in result.counterexample.steps
        if step.escalation_outcome == ESCALATION_APPROVE
    ]
    assert approved, "the counterexample must depend on an approved escalation"
    assert len(approved) == len(result.counterexample.steps)
    assert all(step.governance_verdict == "PERMIT" for step in approved)
    assert "U2_UNAUTHORISED_PRIVILEGE_ESCALATION" in {
        item["identifier"] for item in result.counterexample.violated_invariants
    }


def test_escalation_alone_does_not_make_an_environment_safe():
    """Control reaches Ω; approved-governed reaches Ω; only denial hides it."""
    environment = approval_gated_privilege()
    governance = _governance()
    control = ExhaustiveVerifier(environment).verify()
    denied = ExhaustiveVerifier(environment, governance).verify()
    approved = ExhaustiveVerifier(
        environment, governance, escalation_policy=APPROVE_AND_DENY
    ).verify()
    assert control.complete and denied.complete and approved.complete
    assert control.verdict == UNSAFE_COUNTEREXAMPLE_FOUND
    assert denied.verdict == SAFE_WITHIN_MODEL
    assert approved.verdict == UNSAFE_COUNTEREXAMPLE_FOUND
    # The governed unsafe set is non-empty once approval is admissible, so the
    # SAFE verdict above is not a property of the environment.
    assert approved.unsafe_reachable_state_count > 0


# ─────────────────────────────────────────────────────────────
# Executability of each branch
# ─────────────────────────────────────────────────────────────

def test_denied_escalations_never_execute():
    for environment in (approval_gated_privilege(), secret_exfiltration()):
        result = ExhaustiveVerifier(
            environment, _governance(), escalation_policy=APPROVE_AND_DENY
        ).verify()
        assert result.complete, result.stop_reason
        denied = [
            edge for edge in result.graph.edges.values()
            if edge.escalation_outcome == ESCALATION_DENY
        ]
        assert denied
        for edge in denied:
            assert edge.executed is False
            assert edge.blocked is True
            assert edge.destination is None
            assert edge.governance_verdict == "ESCALATE"
            assert edge.escalation_origin_verdict == "ESCALATE"


def test_approved_escalations_execute_under_a_real_permit():
    result = ExhaustiveVerifier(
        approval_gated_privilege(), _governance(), escalation_policy=APPROVE_AND_DENY
    ).verify()
    executed = [
        edge for edge in result.graph.edges.values()
        if edge.escalation_outcome == ESCALATION_APPROVE and edge.executed
    ]
    assert executed
    for edge in executed:
        # Authority came from the kernel re-deciding with an approval in hand,
        # not from the verifier overriding the verdict.
        assert edge.governance_verdict == "PERMIT"
        assert edge.escalation_origin_verdict == "ESCALATE"
        assert edge.destination is not None


def test_every_escalation_emits_exactly_one_edge_per_admissible_outcome():
    result = ExhaustiveVerifier(
        approval_gated_privilege(), _governance(), escalation_policy=APPROVE_AND_DENY
    ).verify()
    per_source: dict[tuple[str, str], set[str | None]] = {}
    for edge in result.graph.edges.values():
        if edge.escalation_origin_verdict != "ESCALATE":
            continue
        key = (edge.source, edge.action)
        assert edge.escalation_outcome not in per_source.setdefault(key, set())
        per_source[key].add(edge.escalation_outcome)
    assert per_source
    for outcomes in per_source.values():
        assert outcomes == {ESCALATION_DENY, ESCALATION_APPROVE}


def test_approved_prefix_is_replayed_as_approved():
    """The prefix keeps its authority, so trajectory analysis still applies."""
    governance = _governance()
    result = ExhaustiveVerifier(
        approval_gated_privilege(), governance, escalation_policy=APPROVE_AND_DENY
    ).verify()
    assert result.complete
    # Re-evaluating a second step on an approved prefix must not raise: this is
    # precisely what the old resolver could not do.
    from .actions import proposal as _proposal
    from .governance import ExecutedStep
    first = _proposal("obtain_credential", {"credential": "admin-token"})(None)
    history = (ExecutedStep(first, ESCALATION_APPROVED_AUTHORIZATION),)
    decision = governance.evaluate(
        history, _proposal("request_privilege", {"role": "root", "scope": "host"})(None)
    )
    assert isinstance(decision, GovernanceDecision)
    assert decision.verdict in {"PERMIT", "ESCALATE", "BLOCK"}


# ─────────────────────────────────────────────────────────────
# Approval is not omnipotent
# ─────────────────────────────────────────────────────────────

def test_approval_does_not_override_omega():
    """Approving the read does not approve the egress it enables."""
    result = ExhaustiveVerifier(
        secret_exfiltration(), _governance(), escalation_policy=APPROVE_AND_DENY
    ).verify()
    assert result.complete, result.stop_reason
    assert result.verdict == SAFE_WITHIN_MODEL
    assert result.approved_escalation_edge_count > 0
    blocked = [
        edge for edge in result.graph.edges.values()
        if edge.action == "send_external_message" and edge.blocked
    ]
    assert blocked, "egress after an approved secret read must still be refused"


def test_unapprovable_escalation_stays_non_executable():
    """An undeclared tool declares no capability, so no approval can satisfy it."""
    result = ExhaustiveVerifier(
        governance_bypass(), _governance(), escalation_policy=APPROVE_AND_DENY
    ).verify()
    assert result.complete, result.stop_reason
    bypass = [
        edge for edge in result.graph.edges.values()
        if edge.action == "bypass_governance"
        and edge.escalation_outcome == ESCALATION_APPROVE
    ]
    assert bypass
    for edge in bypass:
        assert edge.executed is False
        assert edge.governance_verdict == "ESCALATE"


# ─────────────────────────────────────────────────────────────
# Fail-closed
# ─────────────────────────────────────────────────────────────

class _NoApprovalAdapter:
    configuration_hash = "no-approval-adapter"
    description = "adapter that cannot authorise an escalation"

    def evaluate(self, executed_history, proposal):
        return GovernanceDecision(
            verdict="ESCALATE", permitted=False, layer="test",
            reason="test escalation",
        )


def test_adapter_that_cannot_approve_fails_closed():
    result = ExhaustiveVerifier(
        approval_gated_privilege(), _NoApprovalAdapter(),
        escalation_policy=APPROVE_AND_DENY,
    ).verify()
    assert result.verdict == INCONCLUSIVE
    assert result.complete is False
    assert "cannot authorise an escalation" in result.stop_reason
    assert result.reachable_edge_count == 0


def test_empty_escalation_policy_fails_closed():
    result = ExhaustiveVerifier(
        approval_gated_privilege(), _governance(),
        escalation_policy=lambda proposal, decision: (),
    ).verify()
    assert result.verdict == INCONCLUSIVE
    assert "no admissible outcome" in result.stop_reason


def test_unknown_escalation_outcome_fails_closed():
    result = ExhaustiveVerifier(
        approval_gated_privilege(), _governance(),
        escalation_policy=lambda proposal, decision: ("maybe",),
    ).verify()
    assert result.verdict == INCONCLUSIVE
    assert "unknown outcome" in result.stop_reason


def test_safe_is_unreachable_from_an_incomplete_branch():
    """No limit configuration may turn a truncated approve branch into SAFE."""
    governance = _governance()
    environments = (approval_gated_privilege(), secret_exfiltration(), governance_bypass())
    checked = 0
    for environment, policy, states, edges, depth, algorithm in itertools.product(
        environments, (APPROVE_AND_DENY, APPROVE_ONLY, None),
        (1, 2, 5, 10_000), (1, 2, 5, 100_000), (0, 1, 2, 64), ("bfs", "dfs"),
    ):
        result = ExhaustiveVerifier(
            environment, governance,
            limits=VerificationLimits(states, edges, depth, 30.0),
            algorithm=algorithm, escalation_policy=policy,
        ).verify()
        checked += 1
        if result.verdict == SAFE_WITHIN_MODEL:
            assert result.complete is True
            assert result.stop_reason is None
        if not result.complete:
            assert result.verdict == INCONCLUSIVE
    assert checked == 3 * 3 * 4 * 4 * 4 * 2


def test_traversal_terminates_and_exhausts_the_frontier():
    for policy in (None, APPROVE_AND_DENY, APPROVE_ONLY):
        result = ExhaustiveVerifier(
            approval_gated_privilege(), _governance(), escalation_policy=policy
        ).verify()
        assert result.complete, result.stop_reason
        assert result.stop_reason is None
        assert result.unexplored_frontier_size == 0
        # One-shot actions bound the trajectory tree: no branch can exceed the
        # number of declared actions in depth.
        assert max(node.depth for node in result.graph.nodes.values()) <= len(
            approval_gated_privilege().actions
        )


# ─────────────────────────────────────────────────────────────
# Backwards compatibility
# ─────────────────────────────────────────────────────────────

def test_default_policy_is_deny_only_and_unchanged():
    for environment in (secret_exfiltration(), governance_bypass()):
        result = ExhaustiveVerifier(environment, _governance()).verify()
        assert result.complete
        assert result.approved_escalation_edge_count == 0
        for edge in result.graph.edges.values():
            assert edge.escalation_outcome in (None, ESCALATION_DENY)
            if edge.governance_verdict == "ESCALATE":
                assert edge.executed is False


def test_legacy_bool_resolver_enumerates_both_resolutions():
    result = ExhaustiveVerifier(
        approval_gated_privilege(), _governance(),
        escalation_resolver=lambda proposal, decision: True,
    ).verify()
    assert result.complete, result.stop_reason
    assert result.approved_escalation_edge_count > 0
    assert result.denied_escalation_edge_count > 0


def test_policy_and_resolver_are_mutually_exclusive():
    try:
        ExhaustiveVerifier(
            approval_gated_privilege(), _governance(),
            escalation_policy=APPROVE_AND_DENY,
            escalation_resolver=lambda proposal, decision: True,
        )
    except ValueError as exc:
        assert "not both" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_comparison_reports_unsafe_when_approval_is_admissible():
    comparison = compare_control_and_governed(
        approval_gated_privilege(), _governance(),
        escalation_policy=APPROVE_AND_DENY,
    )
    assert comparison.verdict == UNSAFE_COUNTEREXAMPLE_FOUND
    assert comparison.metrics["unsafe_states_governed"] > 0
    assert comparison.metrics["unsafe_reachability_eliminated"] is False
