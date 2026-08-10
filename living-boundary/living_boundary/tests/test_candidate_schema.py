"""The candidate primitive must be executable, inspectable and non-promotable."""

from __future__ import annotations

import json

import pytest

from living_boundary.discovery.features import (
    FEATURE_FAMILIES, build_literals, feature_set, literal_from_name,
    make_literal, masks_for, predicate_for,
)
from living_boundary.ontology.candidate_schema import (
    AuthorityBoundaryError, CandidatePrimitive, CandidateStatus,
    TERMINAL_LB0_STATUS,
)


def test_a_literal_without_a_predicate_refuses_to_evaluate():
    """A candidate loaded from JSON can be inspected but not run.

    Silently returning False would make a deserialised candidate look like a
    predicate that never fires, and its metrics would be quietly wrong.
    """
    from living_boundary.ontology.candidate_schema import Literal
    literal = Literal(name="x", family="x", description="x")
    with pytest.raises(ValueError):
        literal.evaluate(object())


def test_every_feature_family_round_trips_through_its_name(discovery):
    """A frozen candidate must be evaluable on trajectories that did not exist
    when it was discovered, so name -> predicate has to be total."""
    trajectory = discovery.trajectories[0]
    seen = set()
    for split in discovery.trajectories[:200]:
        for name in feature_set(split):
            family = name.partition("::")[0]
            if family in seen:
                continue
            seen.add(family)
            predicate_for(name)(trajectory)
    assert seen == set(FEATURE_FAMILIES), (
        f"families never exercised: {set(FEATURE_FAMILIES) - seen}")


def test_unparseable_feature_names_are_rejected():
    with pytest.raises(ValueError):
        predicate_for("not_a_family::x")


def test_negation_inverts_the_predicate(discovery):
    trajectory = discovery.trajectories[0]
    name = sorted(feature_set(trajectory))[0]
    assert make_literal(name).evaluate(trajectory)
    assert not make_literal(name, negated=True).evaluate(trajectory)
    assert literal_from_name(f"NOT {name}").negated


def test_support_filtering_keeps_both_branches_informative(discovery):
    trajectories = discovery.trajectories[:400]
    literals, masks, _ = build_literals(trajectories, min_support=25)
    assert literals
    total = len(trajectories)
    for literal in literals:
        count = bin(masks[literal.name]).count("1")
        assert 25 <= count <= total - 25, (
            "literal {} covers {} of {} — one branch is too rare to support a "
            "claim about structure".format(literal.name, count, total)
        )


def test_masks_for_reuses_the_original_literal_vocabulary(dataset):
    """Scoring on a second corpus must use the SAME literals, not re-derive them."""
    fit = dataset.split("discovery").trajectories[:300]
    guard = dataset.split("validation").trajectories[:300]
    literals, masks, _ = build_literals(fit, min_support=15)
    names = [literal.name for literal in literals]
    guard_masks = masks_for(guard, names)
    assert set(names) <= set(guard_masks)
    assert set(names) <= set(masks)


def test_candidate_is_experimental_and_cannot_be_promoted():
    candidate = CandidatePrimitive(candidate_id="CP-TEST", name="t",
                                   description="t")
    assert candidate.status == CandidateStatus.DISCOVERED
    for status in (CandidateStatus.HYPOTHESISED, CandidateStatus.TESTING,
                   CandidateStatus.VALIDATED, TERMINAL_LB0_STATUS):
        candidate.advance(status)
    for forbidden in (CandidateStatus.APPROVED, CandidateStatus.SHADOW,
                      CandidateStatus.ENFORCED):
        with pytest.raises(AuthorityBoundaryError):
            candidate.advance(forbidden)
    assert candidate.status == TERMINAL_LB0_STATUS, (
        "a refused transition must not partially apply")


def test_unknown_status_is_rejected():
    candidate = CandidatePrimitive(candidate_id="CP-TEST", name="t",
                                   description="t")
    with pytest.raises(ValueError):
        candidate.advance("PRODUCTION")


def test_empty_candidate_never_predicts_unsafe(discovery):
    candidate = CandidatePrimitive(candidate_id="CP-TEST", name="t",
                                   description="t")
    assert not any(candidate.matches(t) for t in discovery.trajectories[:50])


def test_structure_hash_depends_only_on_the_literal_set():
    left = CandidatePrimitive(
        candidate_id="A", name="a", description="a",
        literals=(make_literal("has_cap::data.read"),
                  make_literal("scope::customer.read.pii")))
    right = CandidatePrimitive(
        candidate_id="B", name="b", description="b",
        literals=(make_literal("scope::customer.read.pii"),
                  make_literal("has_cap::data.read")))
    assert left.structure_hash == right.structure_hash
    other = CandidatePrimitive(
        candidate_id="C", name="c", description="c",
        literals=(make_literal("has_cap::data.read"),))
    assert other.structure_hash != left.structure_hash


def test_candidate_serialises_without_carrying_authority():
    candidate = CandidatePrimitive(candidate_id="CP-TEST", name="t",
                                   description="t",
                                   literals=(make_literal("has_cap::data.read"),))
    payload = json.loads(json.dumps(candidate.as_dict()))
    assert payload["production_authority"] == "none"
    assert payload["status"] in (CandidateStatus.DISCOVERED,
                                 CandidateStatus.HYPOTHESISED)
    assert payload["literals"][0]["name"] == "has_cap::data.read"
