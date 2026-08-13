"""Unit tests for the adequacy machinery.

The four-way discrimination is tested here against SYNTHETIC collision and
probe inputs rather than against corpora. That is deliberate: the end-to-end
test shows the pipeline reaches the right verdicts on six worlds, and these
show the decision rule itself is correct and would still be correct on inputs
those worlds happen not to produce.
"""

from __future__ import annotations

import pytest

from living_boundary.experiments.replay_probe import ProbeResult
from living_boundary.representation.adequacy import (
    AdequacyVerdict, assess_representation,
)
from living_boundary.representation.collisions import (
    CollisionGroup, CollisionReport, find_collisions, signature_of,
)
from living_boundary.representation.extensions import (
    EXTENSION_POOL, localise_inadequacy,
)
from living_boundary.representation.refit import fit_conjunction


# ── collisions ──────────────────────────────────────────────────────────

def _report(trajectories=1000, colliding_groups=4, minority=200,
            group_size=100, minority_per_group=50):
    groups = [
        CollisionGroup(
            signature=f"sig{i}", size=group_size,
            outcome_counts={"unsafe": group_size - minority_per_group,
                            "safe": minority_per_group},
            sequence_ids=tuple(f"s{i}-{j}" for j in range(group_size)))
        for i in range(colliding_groups)]
    return CollisionReport(
        trajectories=trajectories, groups=120,
        colliding_groups=colliding_groups,
        trajectories_in_colliding_groups=group_size * colliding_groups,
        minority_total=minority, top_groups=groups)


def test_signature_is_order_independent():
    assert signature_of(["b", "a"]) == signature_of(["a", "b"])
    assert signature_of(["a"]) != signature_of(["a", "b"])


def test_irreducible_error_is_a_real_lower_bound(dataset):
    """The bound must actually bound: no predicate over the features can beat it.

    Checked by construction rather than by assertion — a conjunction fitted
    with full knowledge of the labels still cannot get below the floor.
    """
    from living_boundary.discovery.features import feature_set
    from living_boundary.experiments.lb1_environment import TIMING
    from living_boundary.experiments.lb1_generator import (
        generate_dataset, label_corpus,
    )

    lb1 = generate_dataset(5)
    labelled = label_corpus(lb1.corpus("discovery"), TIMING, 5)
    report = find_collisions(labelled)
    assert report.irreducible_error_rate > 0

    labels = [t.is_unsafe_observed for t in labelled]
    refit = fit_conjunction(labelled, labels, feature_set)
    errors = sum(1 for t, y in zip(labelled, labels)
                 if refit.predict(feature_set(t)) != y)
    achieved = errors / len(labelled)
    assert achieved >= report.irreducible_error_rate - 1e-9, (
        f"a fitted predicate achieved {achieved:.4f} error, below the claimed "
        f"floor of {report.irreducible_error_rate:.4f} — the bound is wrong")


def test_no_collisions_when_the_representation_separates(dataset):
    from living_boundary.experiments.lb1_environment import ADEQUATE
    from living_boundary.experiments.lb1_generator import (
        generate_dataset, label_corpus,
    )

    lb1 = generate_dataset(5)
    labelled = label_corpus(lb1.corpus("discovery"), ADEQUATE, 5)
    report = find_collisions(labelled)
    assert report.colliding_groups == 0
    assert report.irreducible_error_rate == 0.0


def test_mean_minority_fraction_separates_noise_from_mixture():
    thin = _report(minority=40, minority_per_group=10)     # ~0.10, noise-like
    mixed = _report(minority=200, minority_per_group=50)   # ~0.50, mixture-like
    assert thin.mean_minority_fraction < 0.2
    assert mixed.mean_minority_fraction > 0.4


# ── the four-way discrimination ─────────────────────────────────────────

def _probe(record_rate=0.0, self_rate=0.0, sampled=200):
    return ProbeResult(
        sampled=sampled,
        record_disagreements=int(record_rate * sampled),
        self_disagreements=int(self_rate * sampled))


def test_no_collisions_yields_adequate():
    assessment = assess_representation(
        _report(colliding_groups=0, minority=0,
                trajectories=1000, group_size=0, minority_per_group=0),
        _probe())
    assert assessment.verdict == AdequacyVerdict.ADEQUATE
    assert not assessment.is_inadequate


def test_a_reproducible_world_with_a_faithful_record_yields_inadequate():
    assessment = assess_representation(_report(), _probe())
    assert assessment.verdict == AdequacyVerdict.INADEQUATE
    assert "reproducible" in " ".join(assessment.eliminations)
    assert "faithful" in " ".join(assessment.eliminations)


def test_an_unfaithful_record_yields_noise_limited():
    assessment = assess_representation(_report(), _probe(record_rate=0.12))
    assert assessment.verdict == AdequacyVerdict.NOISE_LIMITED


def test_a_non_reproducible_world_yields_stochastic():
    assessment = assess_representation(
        _report(), _probe(record_rate=0.18, self_rate=0.17))
    assert assessment.verdict == AdequacyVerdict.STOCHASTIC


def test_stochasticity_is_tested_before_record_fidelity():
    """Order matters: if the world does not repeat, nothing else can be
    concluded, so a run that is BOTH stochastic and noisy must say STOCHASTIC."""
    assessment = assess_representation(
        _report(), _probe(record_rate=0.40, self_rate=0.30))
    assert assessment.verdict == AdequacyVerdict.STOCHASTIC


def test_noise_verdict_still_reports_residual_structure():
    """A corpus can be noisy AND missing a concept.

    Stopping at "it's noise" would hide the second finding behind the first, so
    the residual is computed and reported in every verdict.
    """
    assessment = assess_representation(
        _report(minority=200, minority_per_group=50), _probe(record_rate=0.03))
    assert assessment.verdict == AdequacyVerdict.NOISE_LIMITED
    assert assessment.residual_beyond_noise["unexplained_by_noise"] is True
    assert "may ALSO be present" in assessment.reason


def test_verdicts_are_serialisable_and_carry_their_reasoning():
    assessment = assess_representation(_report(), _probe())
    payload = assessment.as_dict()
    assert payload["status"] == "experimental"
    assert payload["eliminations"]
    assert payload["reason"]
    assert payload["collision"]["colliding_groups"] == 4


# ── localisation ────────────────────────────────────────────────────────

def test_localisation_ranks_the_pool_and_can_decline():
    """Nothing resolves a report built from groups the pool cannot see."""
    from living_boundary.experiments.lb1_environment import UNLOCALISED
    from living_boundary.experiments.lb1_generator import (
        generate_dataset, label_corpus,
    )

    lb1 = generate_dataset(5)
    labelled = label_corpus(lb1.corpus("discovery"), UNLOCALISED, 5)
    report = find_collisions(labelled)
    localisation = localise_inadequacy(labelled, report)

    assert report.colliding_groups > 0
    assert len(localisation.results) == len(EXTENSION_POOL)
    assert not localisation.localised, (
        "the pool contains no family that reads the action name, so nothing "
        "should clear the resolution bar")
    assert localisation.best is not None, (
        "a declined localisation must still report its best attempt, so a "
        "reviewer can see how close the pool got")


def test_localisation_finds_the_observable_when_the_pool_contains_it():
    from living_boundary.experiments.lb1_environment import TIMING
    from living_boundary.experiments.lb1_generator import (
        generate_dataset, label_corpus,
    )

    lb1 = generate_dataset(5)
    labelled = label_corpus(lb1.corpus("discovery"), TIMING, 5)
    localisation = localise_inadequacy(labelled, find_collisions(labelled))
    assert localisation.localised
    assert localisation.best.observable == "timestamp"
    assert localisation.best.resolution >= 0.8


def test_localisation_is_a_no_op_without_collisions():
    localisation = localise_inadequacy(
        [], _report(colliding_groups=0, minority=0, group_size=0,
                    minority_per_group=0))
    assert not localisation.localised
    assert localisation.results == []


@pytest.mark.parametrize("family", EXTENSION_POOL, ids=lambda f: f.name)
def test_every_extension_family_is_total(family, dataset):
    """Each family must return a set for any trajectory, including odd shapes."""
    for trajectory in dataset.split("discovery").trajectories[:60]:
        assert isinstance(family.features(trajectory), set)
    assert isinstance(family.as_dict()["observable"], str)


# ── refit ───────────────────────────────────────────────────────────────

def test_refit_with_no_signal_predicts_nothing():
    from living_boundary.discovery.features import feature_set

    refit = fit_conjunction([], [], feature_set)
    assert refit.literals == ()
    assert refit.predict({"anything"}) is False
