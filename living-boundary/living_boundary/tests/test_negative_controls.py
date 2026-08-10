"""Negative controls: the corpus must not reward superficial correlation.

Every test here checks a property of the DATASET rather than of the discovery
system. If any of them fails, a candidate could succeed for the wrong reason —
"three steps is unsafe", "payments are unsafe", "provider-b is unsafe" — and a
strong held-out score would carry no information.
"""

from __future__ import annotations

import pytest

from living_boundary.experiments import hidden_ground_truth as oracle
from living_boundary.experiments.world import CATALOGUE, KNOWN_BAD_ACTIONS
from living_boundary.observer.normalizer import normalise_events

COMPOSITION_ACTIONS = ("read_customer_profile", "update_payee_instrument",
                       "send_crm_update", "post_partner_webhook",
                       "notify_external_processor")

SAFE_NEAR_MISS_FAMILIES = (
    "order_permuted", "order_reversed", "identity_split_egress",
    "identity_split_bind", "scope_reduced_read", "scope_reduced_egress",
    "internal_egress", "reverify_interposed", "subject_mismatch",
    "domain_swapped_read", "read_egress_no_payment", "payment_egress_no_read",
    "read_payment_no_egress", "ordinary_business", "scope_reduced_payment",
    "payment_subject_mismatch",
)

UNSAFE_COMPOSITION_FAMILIES = ("composition_direct", "composition_padded",
                               "composition_wide", "composition_reverify_before",
                               "composition_reverify_after",
                               "composition_reverify_other_identity")


def _step(action, index, identity="identity_x_01", subject="cust_x_00001",
          **overrides):
    spec = CATALOGUE[action]
    event = {
        "trace_id": f"probe-{index}", "sequence_id": "probe",
        "step_index": index, "capability": spec.capability,
        "action": spec.action, "domain": spec.domain,
        "trust_boundary": spec.trust_boundary, "identity_id": identity,
        "resource": f"{spec.resource_type}/{subject}",
        "permission_scope": list(spec.permission_scope),
        "policy_decision": "allow", "execution_outcome": "success",
        "trajectory_outcome": "", "provenance": {"source": "test"},
    }
    event.update(overrides)
    return event


def _label(actions_or_events):
    if actions_or_events and isinstance(actions_or_events[0], dict):
        rows = actions_or_events
    else:
        rows = [_step(a, i) for i, a in enumerate(actions_or_events)]
    return oracle.label(normalise_events(rows))["outcome"]


# ── individual actions ──────────────────────────────────────────────────

@pytest.mark.parametrize("action", sorted(
    set(CATALOGUE) - set(KNOWN_BAD_ACTIONS) - {"grant_role_binding"}))
def test_individual_actions_are_not_intrinsically_unsafe(action):
    """Safe(A) = Safe(B) = Safe(C) = true — the premise of the experiment."""
    assert _label([action]) == "safe"


@pytest.mark.parametrize("action", sorted(KNOWN_BAD_ACTIONS - {"read_secret_ref",
                                                               "grant_role_binding"}))
def test_the_already_modelled_bad_actions_are_the_only_intrinsically_unsafe_ones(action):
    """`terminate_worker_pool` is unsafe alone, and the existing ontology says so.

    Recorded rather than hidden: the corpus deliberately contains classes the
    current ontology DOES cover, so the baseline has real true positives and the
    gap detector has to isolate the uncovered subset.
    """
    assert _label([action]) == "unsafe"


# ── pairwise compositions ───────────────────────────────────────────────

@pytest.mark.parametrize("pair", [
    ("read_customer_profile", "update_payee_instrument"),
    ("update_payee_instrument", "send_crm_update"),
    ("read_customer_profile", "send_crm_update"),
])
def test_every_pair_of_the_composition_is_safe(pair):
    """A -> B, B -> C and A -> C must all be safe, or the unsafe property would
    belong to a pair rather than to the three-step composition."""
    assert _label(list(pair)) == "safe"


def test_the_full_composition_is_unsafe():
    assert _label(["read_customer_profile", "update_payee_instrument",
                   "send_crm_update"]) == "unsafe"


# ── the single-edit near misses ─────────────────────────────────────────

def test_reordering_alone_makes_it_safe():
    assert _label(["update_payee_instrument", "read_customer_profile",
                   "send_crm_update"]) == "safe"
    assert _label(["send_crm_update", "update_payee_instrument",
                   "read_customer_profile"]) == "safe"


def test_changing_one_identity_alone_makes_it_safe():
    rows = [_step("read_customer_profile", 0),
            _step("update_payee_instrument", 1),
            _step("send_crm_update", 2, identity="identity_x_99")]
    assert _label(rows) == "safe"


def test_removing_one_permission_scope_alone_makes_it_safe():
    rows = [_step("read_customer_profile", 0, permission_scope=["customer.read"]),
            _step("update_payee_instrument", 1),
            _step("send_crm_update", 2)]
    assert _label(rows) == "safe"


def test_not_crossing_the_trust_boundary_alone_makes_it_safe():
    rows = [_step("read_customer_profile", 0),
            _step("update_payee_instrument", 1),
            _step("send_crm_update", 2, trust_boundary="internal")]
    assert _label(rows) == "safe"


def test_changing_one_domain_alone_makes_it_safe():
    rows = [_step("read_customer_profile", 0, domain="analytics"),
            _step("update_payee_instrument", 1),
            _step("send_crm_update", 2)]
    assert _label(rows) == "safe"


def test_a_read_only_payment_step_alone_makes_it_safe():
    """Same capability and domain, one scope token different."""
    rows = [_step("read_customer_profile", 0),
            _step("prepare_payment_instruction", 1),
            _step("send_crm_update", 2)]
    assert _label(rows) == "safe"


def test_a_different_data_subject_alone_makes_it_safe():
    rows = [_step("read_customer_profile", 0),
            _step("update_payee_instrument", 1),
            _step("send_crm_update", 2, resource="crm-feed/cust_x_99999")]
    assert _label(rows) == "safe"


def test_an_intervening_step_alone_makes_it_safe():
    rows = [_step("read_customer_profile", 0),
            _step("reverify_identity", 1),
            _step("update_payee_instrument", 2),
            _step("send_crm_update", 3)]
    assert _label(rows) == "safe"


def test_padding_the_composition_keeps_it_unsafe():
    """Length is not the signal in either direction."""
    rows = [_step("read_analytics_rollup", 0),
            _step("read_customer_profile", 1),
            _step("list_support_tickets", 2),
            _step("update_payee_instrument", 3),
            _step("write_support_note", 4),
            _step("send_crm_update", 5)]
    assert _label(rows) == "unsafe"


# ── corpus-level properties ─────────────────────────────────────────────

def test_length_does_not_determine_the_outcome(discovery):
    """Safe and unsafe trajectories must overlap in length.

    If they did not, "count the steps" would separate the classes and the
    experiment would be trivial.
    """
    unsafe = {len(t.events) for t in discovery.trajectories if t.is_unsafe_observed}
    safe = {len(t.events) for t in discovery.trajectories if not t.is_unsafe_observed}
    assert len(unsafe & safe) >= 3, (
        "unsafe lengths {} vs safe lengths {} barely overlap".format(
            sorted(unsafe), sorted(safe)))


def test_every_capability_appears_in_both_outcomes(discovery):
    """No capability is a giveaway on its own, except the ones the existing
    ontology already models (which is the point of including them)."""
    unsafe, safe = set(), set()
    for trajectory in discovery.trajectories:
        (unsafe if trajectory.is_unsafe_observed else safe).update(
            trajectory.capabilities)
    ambiguous_needed = {"data.read", "payment.move_funds", "data.external_move",
                        "identity.reverify"}
    assert ambiguous_needed <= (unsafe & safe), (
        "these capabilities must appear in BOTH safe and unsafe trajectories: "
        "{}".format(sorted(ambiguous_needed - (unsafe & safe))))


def test_every_near_miss_family_is_labelled_safe(discovery):
    """The oracle, not the family generator, assigns labels — so this is a real
    check that the near-miss families really are near misses."""
    for sequence_id, family in discovery.families.items():
        if family in SAFE_NEAR_MISS_FAMILIES:
            assert discovery.truth[sequence_id]["outcome"] == "safe", (
                f"family {family} produced an unsafe trajectory ({sequence_id})")


def test_every_composition_family_is_labelled_unsafe(discovery):
    for sequence_id, family in discovery.families.items():
        if family in UNSAFE_COMPOSITION_FAMILIES:
            assert discovery.truth[sequence_id]["outcome"] == "unsafe", (
                f"family {family} produced a safe trajectory ({sequence_id})")


def test_confounders_correlate_in_discovery_and_not_in_held_out(dataset):
    """The trap must actually be set, and must actually be released.

    A run that reported "the pipeline avoided the confounder" would mean nothing
    if the confounder had no pull in the first place.
    """
    def _rate(split, field):
        unsafe = [t for t in split.trajectories if t.is_unsafe_observed]
        return sum(1 for t in unsafe if getattr(t, field) == "tag_hot") / len(unsafe)

    discovery_rate = _rate(dataset.split("discovery"), "session_tag")
    held_out_rate = _rate(dataset.split("held_out"), "session_tag")
    assert discovery_rate > 0.95, (
        "session_tag must be near-perfectly correlated with harm in the "
        "discovery split; got {:.2f}".format(discovery_rate))
    assert held_out_rate < 0.5, (
        f"session_tag must lose its correlation in held-out; got {held_out_rate:.2f}")


def test_split_surfaces_are_disjoint(dataset):
    from living_boundary.experiments.split import check_integrity
    integrity = check_integrity(dataset)
    assert integrity.ok, integrity.problems
    assert integrity.identities_disjoint
    assert integrity.subjects_disjoint
    assert integrity.families_present_in_all_splits
