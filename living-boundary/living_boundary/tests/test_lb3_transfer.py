"""Unit tests for the LB-3 machinery: roles, grammars, retention, invariance.

These check the parts in isolation, on small hand-built inputs where the right
answer is obvious. The end-to-end module checks what they add up to.
"""

from __future__ import annotations

import pytest

from living_boundary.experiments.lb3_generator import build_corpus
from living_boundary.experiments.lb3_worlds import (
    DISCOVERY_ENV, TRANSFER_ENVIRONMENTS, PlannedStep, label_plan,
)
from living_boundary.transfer import invariance
from living_boundary.transfer.evaluator import (
    MAX_ALIGNMENT_COST, evaluate_environment,
)
from living_boundary.transfer.freeze import freeze
from living_boundary.transfer.grammars import (
    VOCABULARY_BOUND_FAMILIES, grammar_fn, relational_features,
    surface_features, typed_features,
)
from living_boundary.transfer.retention import (
    MIN_DISCOVERY_LIFT, aggregate, baseline_f1, lift, retention,
)
from living_boundary.transfer.roles import (
    ROLE_COUNT, align, alignment_cost, induce_roles, observe_statistics,
)

SEED = 42


@pytest.fixture(scope="module")
def discovery():
    return build_corpus(SEED, DISCOVERY_ENV, "unit", count=400)


@pytest.fixture(scope="module")
def reference(discovery):
    model = induce_roles(DISCOVERY_ENV.env_id, discovery.trajectories)
    model.alignment = align(model, model)
    return model


# ── the hidden rule (harness-side, checked so the corpus means what it says) ──

def test_the_hidden_rule_needs_all_four_conditions():
    from living_boundary.experiments.lb3_worlds import (
        EGRESS, MUTATE, OBSERVE, VERIFY,
    )

    hazard = [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
              PlannedStep(EGRESS, 0, 0, outside=True)]
    assert label_plan(hazard) == "unsafe"

    # each of these is exactly one edit away and every one of them is safe
    assert label_plan([PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
                       PlannedStep(EGRESS, 0, 0, outside=False)]) == "safe"
    assert label_plan([PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
                       PlannedStep(EGRESS, 1, 0, outside=True)]) == "safe"
    assert label_plan([PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
                       PlannedStep(EGRESS, 0, 1, outside=True)]) == "safe"
    assert label_plan([PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
                       PlannedStep(VERIFY, 0, 0),
                       PlannedStep(EGRESS, 0, 0, outside=True)]) == "safe"


def test_the_verification_exemption_is_identity_scoped():
    """The distinction the over-approximation probe exists to test."""
    from living_boundary.experiments.lb3_worlds import (
        EGRESS, MUTATE, OBSERVE, VERIFY,
    )

    by_self = [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
               PlannedStep(VERIFY, 0, 0),
               PlannedStep(EGRESS, 0, 0, outside=True)]
    by_other = [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
                PlannedStep(VERIFY, 1, 0),
                PlannedStep(EGRESS, 0, 0, outside=True)]
    assert label_plan(by_self) == "safe"
    assert label_plan(by_other) == "unsafe"


def test_every_environment_labels_the_same_plan_by_its_own_rule():
    from living_boundary.experiments.lb3_worlds import (
        EGRESS, MUTATE, OBSERVE, RULE_IDENTITY_SPLIT, RULE_SUBJECT_MISMATCH,
    )

    hazard = [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
              PlannedStep(EGRESS, 0, 0, outside=True)]
    assert label_plan(hazard, RULE_IDENTITY_SPLIT) == "safe"
    assert label_plan(hazard, RULE_SUBJECT_MISMATCH) == "safe"


# ── role induction ──────────────────────────────────────────────────────

def test_statistics_are_computed_per_step_type(discovery):
    statistics = observe_statistics(discovery.trajectories)
    assert statistics
    assert all(len(vector) == 8 for vector in statistics.values())
    crossing = statistics["send_crm_update"][0]
    internal = statistics["read_customer_profile"][0]
    assert crossing > 0.9 and internal == 0.0


def test_roles_separate_the_step_types_that_do_different_things(reference):
    members = reference.as_dict()["members"]
    groups = {frozenset(names) for names in members.values()}
    assert len(members) == ROLE_COUNT
    # the three egress tools land together, and apart from the customer reads
    assert frozenset({"send_crm_update", "post_partner_webhook",
                      "notify_external_processor"}) in groups
    assert frozenset({"read_customer_profile",
                      "open_customer_record"}) in groups


def test_roles_align_across_a_complete_vocabulary_change(reference):
    """No symbol is shared between these two environments."""
    corpus = build_corpus(SEED, TRANSFER_ENVIRONMENTS[0], "unit", count=400)
    model = induce_roles(corpus.env_id, corpus.trajectories)
    model.alignment = align(reference, model)
    cost = alignment_cost(reference, model, model.alignment)
    assert cost < MAX_ALIGNMENT_COST

    reference_members = reference.as_dict()["members"]
    moved_members = model.as_dict()["members"]
    assert set(reference_members) == set(moved_members)
    egress_role = next(role for role, names in reference_members.items()
                       if "send_crm_update" in names)
    assert "dispatch_vendor_bundle" in moved_members[egress_role]


def test_induction_is_deterministic(discovery):
    first = induce_roles("x", discovery.trajectories).assignment
    again = induce_roles("x", discovery.trajectories).assignment
    assert first == again


# ── grammars ────────────────────────────────────────────────────────────

def test_typed_is_surface_minus_the_vocabulary_bound_families(discovery):
    trajectory = discovery.trajectories[0]
    surface = surface_features(trajectory)
    typed = typed_features(trajectory)
    assert typed < surface
    dropped = {name.partition("::")[0] for name in surface - typed}
    assert dropped <= VOCABULARY_BOUND_FAMILIES


def test_relational_features_contain_no_vocabulary(discovery, reference):
    names = relational_features(discovery.trajectories[0], reference)
    assert names
    blob = " ".join(names)
    for token in ("customer", "payment", "comms", "provider-", "read_",
                  "send_", "identity."):
        assert token not in blob


def test_the_relational_grammar_needs_a_role_model():
    with pytest.raises(ValueError):
        grammar_fn("relational")


def test_an_unknown_grammar_is_refused():
    with pytest.raises(ValueError):
        grammar_fn("something_else")


# ── retention ───────────────────────────────────────────────────────────

def test_the_baseline_is_the_better_trivial_predictor():
    """And it is always the always-unsafe one, which is a documented wart.

    Under F1 the never-unsafe predictor scores 0 by construction, so the
    maximum can never fall to it. This test pins that behaviour so the
    docstring in `retention.py` cannot quietly stop being true.
    """
    assert baseline_f1([True] * 8 + [False] * 2)[1] == "always_unsafe"
    assert baseline_f1([False] * 20) == (0.0, "always_unsafe")
    assert baseline_f1([])[0] == 0.0


def test_the_baseline_tracks_class_balance():
    """Which is the whole reason retention is a lift ratio rather than an F1."""
    balanced = baseline_f1([True] * 5 + [False] * 5)[0]
    skewed = baseline_f1([True] * 1 + [False] * 9)[0]
    assert balanced > skewed


def test_a_perfect_transfer_retains_one():
    measure = retention("env_x", 0.5, 0.5)
    assert measure.defined
    assert measure.raw == pytest.approx(1.0)
    assert measure.clipped == pytest.approx(1.0)


def test_a_worthless_transfer_retains_nothing():
    measure = retention("env_x", 0.5, 0.0)
    assert measure.clipped == 0.0


def test_a_transfer_worse_than_the_baseline_is_reported_negative():
    """Clipped for the gate, raw for the reader — both, never one."""
    measure = retention("env_x", 0.5, -0.2)
    assert measure.raw < 0
    assert measure.clipped == 0.0


def test_retention_is_undefined_when_there_was_nothing_to_retain():
    measure = retention("env_x", MIN_DISCOVERY_LIFT / 2, 0.4)
    assert not measure.defined
    assert "not reported" in measure.reason


def test_aggregation_reports_the_minimum_not_the_mean():
    rows = [retention("a", 0.5, 0.5), retention("b", 0.5, 0.5),
            retention("c", 0.5, 0.0)]
    summary = aggregate(rows)
    assert summary["minimum"] == 0.0
    assert summary["worst_environment"] == "c"
    assert summary["mean"] > summary["minimum"]


def test_lift_measures_against_the_environments_own_balance():
    labels = [True] * 3 + [False] * 7
    perfect = lift(labels, labels)
    assert perfect["f1"] == 1.0
    assert perfect["lift"] > 0


# ── freezing ────────────────────────────────────────────────────────────

def test_a_seal_survives_a_round_trip():
    candidate = freeze("C", "typed", "v1", ("b", "a"), "env_00",
                       {"t": 1}, "rule", {"f1": 1.0})
    candidate.verify()
    assert candidate.literals == ("a", "b")
    assert candidate.as_dict()["production_authority"] == "none"


def test_a_candidate_predicts_by_conjunction_with_negation():
    candidate = freeze("C", "typed", "v1", ("a", "NOT b"), "env_00", {},
                       "rule", {})
    assert candidate.predict({"a"}) is True
    assert candidate.predict({"a", "b"}) is False
    assert candidate.predict({"b"}) is False


def test_an_empty_candidate_never_fires():
    assert freeze("C", "typed", "v1", (), "env_00", {}, "r", {}).predict(
        {"anything"}) is False


# ── invariance transforms ───────────────────────────────────────────────

def test_preserving_transforms_keep_the_step_count_or_grow_it(discovery):
    trajectory = discovery.trajectories[3]
    for name, transform in invariance.PRESERVING:
        moved = transform(trajectory)
        assert len(moved.events) >= len(trajectory.events), name


def test_destructive_transforms_are_deterministic(discovery):
    trajectory = discovery.trajectories[3]
    for name, transform in invariance.DESTRUCTIVE:
        first = [e.action for e in transform(trajectory).events]
        again = [e.action for e in transform(trajectory).events]
        assert first == again, name


def test_fragmenting_identities_destroys_every_identity_relation(discovery):
    moved = invariance.fragment_identities(discovery.trajectories[3])
    assert len({e.identity_id for e in moved.events}) == len(moved.events)


def test_hoisting_the_crossing_puts_it_first(discovery):
    from living_boundary.observer.normalizer import BOUNDARY_INTERNAL

    crossing = [t for t in discovery.trajectories
                if any(e.trust_boundary != BOUNDARY_INTERNAL for e in t.events)
                and t.events[0].trust_boundary == BOUNDARY_INTERNAL]
    moved = invariance.hoist_crossing_to_front(crossing[0])
    assert moved.events[0].trust_boundary != BOUNDARY_INTERNAL


def test_agreement_and_extinction_measure_different_things():
    assert invariance.agreement([True, False], [True, False]) == 1.0
    assert invariance.agreement([True, False], [False, False]) == 0.5
    assert invariance.extinction([True, True], [False, False]) == 1.0
    # extinction is measured only over the trajectories that fired
    assert invariance.extinction([True, False], [True, True]) == 0.0
    assert invariance.extinction([False, False], [False, False]) == 0.0


# ── the evaluator ───────────────────────────────────────────────────────

def test_a_candidate_that_cannot_be_stated_abstains(discovery, reference):
    """A mangled role model must produce an abstention, not a score."""
    import dataclasses

    corpus = build_corpus(SEED, TRANSFER_ENVIRONMENTS[0], "unit", count=200)
    candidate = freeze("C", "relational", "v1", ("rr_has::role_0@internal",),
                       "env_00", {}, "rule", {})
    broken = dataclasses.replace(reference,
                                 centroids=tuple((99.0,) * 8 for _ in range(5)))
    result = evaluate_environment(candidate, corpus, broken, 0.5)
    assert result.outcome == "ABSTAINED"
    assert "did not hold" in result.reason


def test_evaluation_does_not_touch_the_candidate(discovery, reference):
    corpus = build_corpus(SEED, TRANSFER_ENVIRONMENTS[0], "unit", count=200)
    candidate = freeze("C", "relational", "v1", ("rr_has::role_0@internal",),
                       "env_00", {}, "rule", {})
    before = candidate.structure_hash
    evaluate_environment(candidate, corpus, reference, 0.5)
    assert candidate.structure_hash == before
    candidate.verify()
