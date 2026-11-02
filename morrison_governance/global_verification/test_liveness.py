"""Liveness: SAFE_BUT_NOT_LIVE is reported distinctly from SAFE_WITHIN_MODEL.

External review (2026-11): several governed finite models collapsed to one
reachable state and were reported SAFE_WITHIN_MODEL, i.e. safe because nothing
could happen. These tests pin the distinction and the evidence behind it.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from .comparison import compare_control_and_governed
from .governance import GovernanceDecision, MorrisonKernelAdapter
from .liveness import LIVE, NOT_DECLARED, NOT_LIVE, LivenessGoal
from .pipeline import ALL_OPTIONS, STAGES, enterprise_pipeline
from .scenarios import SCENARIOS, perturbation_matrix, secret_exfiltration
from .tla_export import crosscheck_explicit, render_tla, write_bundle
from .verifier import (
    SAFE_BUT_NOT_LIVE,
    SAFE_WITHIN_MODEL,
    UNSAFE_COUNTEREXAMPLE_FOUND,
    ExhaustiveVerifier,
)

APPROVE_AND_DENY = (lambda proposal, decision: ("deny", "approve"))


class DenyAll:
    """The degenerate governor: refuses everything. Perfectly safe, useless."""

    configuration_hash = "deny-all"
    description = "refuses every proposal"

    def evaluate(self, _executed_history, _proposal):
        return GovernanceDecision("BLOCK", False, "deny_all", "refuse everything")


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_scenario_declares_goals_or_says_why_not(name):
    env = SCENARIOS[name]()
    assert env.goals or env.adversarial_only, name


def test_every_perturbation_inherits_a_liveness_declaration():
    for env in perturbation_matrix():
        assert env.goals or env.adversarial_only, env.name


def test_deny_all_is_safe_but_not_live():
    """The reviewer's case, directly: refusing everything is not SAFE_WITHIN_MODEL."""
    result = ExhaustiveVerifier(enterprise_pipeline(), DenyAll()).verify()
    assert result.unsafe_reachable_state_count == 0
    assert result.reachable_state_count == 1
    assert result.verdict == SAFE_BUT_NOT_LIVE
    assert result.liveness["status"] == NOT_LIVE


def test_collapsed_scenarios_are_reported_not_live():
    comparison = compare_control_and_governed(secret_exfiltration(), MorrisonKernelAdapter())
    assert comparison.verdict == SAFE_BUT_NOT_LIVE
    goals = {g["identifier"]: g for g in comparison.metrics["liveness"]["goals"]}
    assert goals["LG_SECRET_USED_INSIDE_BOUNDARY"]["attribution"] == "removed_by_governance"
    assert goals["LG_NETWORK_AVAILABLE"]["attribution"] == "live"
    assert "legitimate goal" in comparison.to_dict(include_graph=False)["claim"]


def test_approval_restores_liveness_without_unsafety():
    comparison = compare_control_and_governed(
        secret_exfiltration(), MorrisonKernelAdapter(), escalation_policy=APPROVE_AND_DENY)
    assert comparison.verdict == SAFE_WITHIN_MODEL
    assert comparison.governed.liveness["status"] == LIVE


def test_adversarial_only_model_states_that_liveness_is_not_declared():
    result = ExhaustiveVerifier(SCENARIOS["governance_bypass"](), MorrisonKernelAdapter()).verify()
    assert result.verdict == SAFE_WITHIN_MODEL
    assert result.liveness["status"] == NOT_DECLARED
    assert "nothing about whether governed execution can do useful work" in \
        result.liveness["note"]


def test_a_goal_reached_only_unsafely_does_not_count():
    """Reaching the goal by violating an invariant is not legitimate completion."""
    unsafe_goal = LivenessGoal("LG_SECRET_SENT", "a goal only an unsafe state meets",
                               lambda s: s.secret_externalized)
    env = replace(secret_exfiltration(), goals=(unsafe_goal,))
    result = ExhaustiveVerifier(env).verify()            # control: no governance
    assert result.unsafe_reachable_state_count > 0
    assert result.liveness["goals"][0]["reachable_from_every_initial_state"] is False


def test_goal_unreachable_in_the_model_is_attributed_to_the_model():
    never = LivenessGoal("LG_NEVER", "no state satisfies this", lambda s: False)
    env = replace(secret_exfiltration(), goals=(never,))
    comparison = compare_control_and_governed(env, MorrisonKernelAdapter())
    goal = comparison.metrics["liveness"]["goals"][0]
    assert goal["attribution"] == "unreachable_in_model"
    assert comparison.verdict == SAFE_BUT_NOT_LIVE


def test_liveness_requires_the_goal_from_every_initial_state():
    """secret_exfiltration has two initial states; distances are per state."""
    result = ExhaustiveVerifier(secret_exfiltration(), MorrisonKernelAdapter(),
                                escalation_policy=APPROVE_AND_DENY).verify()
    for goal in result.liveness["goals"]:
        assert len(goal["shortest_distance_per_initial_state"]) == 2


def test_stranded_configurations_are_reported():
    result = ExhaustiveVerifier(enterprise_pipeline(), MorrisonKernelAdapter()).verify()
    completed = next(g for g in result.liveness["goals"]
                     if g["identifier"] == "LG_PIPELINE_COMPLETED")
    # Governed paths through enrich_internal_api dead-end at the review stage
    # (V2 multi-step heuristic): the goal is reachable, but not from everywhere.
    assert completed["reachable_from_every_initial_state"] is True
    assert completed["recoverable_from_every_reachable_configuration"] is False
    assert completed["stranded_configurations"] > 0


# ── the larger scenario ───────────────────────────────────────────────────

def test_enterprise_pipeline_is_large_safe_and_live():
    comparison = compare_control_and_governed(enterprise_pipeline(), MorrisonKernelAdapter())
    assert comparison.control.complete and comparison.governed.complete
    assert comparison.control.reachable_state_count >= 500
    assert comparison.control.unsafe_reachable_state_count > 0
    assert comparison.governed.unsafe_reachable_state_count == 0
    assert comparison.verdict == SAFE_WITHIN_MODEL
    assert comparison.governed.liveness["status"] == LIVE


def test_enterprise_pipeline_with_approvals_finds_the_counterexample():
    comparison = compare_control_and_governed(
        enterprise_pipeline(), MorrisonKernelAdapter(), escalation_policy=APPROVE_AND_DENY)
    assert comparison.verdict == UNSAFE_COUNTEREXAMPLE_FOUND
    assert comparison.governed.counterexample is not None


def test_pipeline_table_is_well_formed():
    names = [o.name for o in ALL_OPTIONS]
    assert len(names) == len(set(names))
    assert all(len(opts) == 3 for _, opts in STAGES)
    assert {o.intent for o in ALL_OPTIONS} == {"legitimate", "approval", "prohibited"}


# ── TLA+ export and cross-check ───────────────────────────────────────────

@pytest.mark.parametrize("escalations", ["deny", "deny-and-approve"])
def test_second_implementation_agrees_with_the_verifier(tmp_path, escalations):
    data = write_bundle(tmp_path, escalations)
    model = json.loads((tmp_path / "model.json").read_text())
    expected = data["expected"]
    for mode, governed in (("control", False), ("governed", True)):
        second = crosscheck_explicit(model, governed)
        assert second["states"] == expected[f"{mode}_states"], mode
        assert second["unsafe_reachable"] == expected[f"{mode}_unsafe_reachable"], mode
        assert second["goals"] == expected[f"{mode}_goals"], mode


def test_cross_check_notices_a_wrong_oracle(tmp_path):
    """A cross-check nobody has seen disagree is not evidence."""
    data = write_bundle(tmp_path, "deny")
    model = json.loads((tmp_path / "model.json").read_text())
    model["permitted"] = model["permitted"][:-3]
    second = crosscheck_explicit(model, governed=True)
    assert second["states"] != data["expected"]["governed_states"]


def test_tla_bundle_is_complete(tmp_path):
    write_bundle(tmp_path, "deny")
    spec = (tmp_path / "EnterprisePipeline.tla").read_text()
    assert spec.startswith("---- MODULE EnterprisePipeline ----")
    assert spec.rstrip().endswith("====")
    for option in ALL_OPTIONS:
        assert f"A_{option.name} ==" in spec
    cfgs = {p.stem for p in tmp_path.glob("*.cfg")}
    assert {"control_count", "control_safety", "governed_safety"} <= cfgs
    assert all("CHECK_DEADLOCK FALSE" in p.read_text() for p in tmp_path.glob("*.cfg"))


def test_tla_render_is_deterministic():
    assert render_tla([]) == render_tla([])
