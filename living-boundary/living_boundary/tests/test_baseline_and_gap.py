"""The baseline must be honest, and the gap must be a representation gap."""

from __future__ import annotations

from living_boundary.discovery.gap_detector import (
    detect_gap, residual_trajectories,
)
from living_boundary.evaluation.evaluator import (
    baseline_predictor, evaluate_predictor,
)
from living_boundary.experiments import hidden_ground_truth as oracle
from living_boundary.ontology.baseline import (
    BASELINE_ONTOLOGY, STRENGTHENED_ONTOLOGY,
)
from living_boundary.ontology.versions import BASELINE_PRIMITIVE_NAMES


def test_baseline_ontology_declares_the_expected_primitives():
    assert set(BASELINE_ONTOLOGY.primitive_names()) == set(BASELINE_PRIMITIVE_NAMES)


def test_baseline_never_fires_on_a_per_action_policy_decision(discovery):
    """Every step in the corpus is `allow`, so `unauthorised_transfer` cannot
    fire. That is the experiment's premise, asserted rather than assumed."""
    for trajectory in discovery.trajectories:
        assert trajectory.all_steps_allowed
        decision = BASELINE_ONTOLOGY.evaluate(trajectory)
        assert "unauthorised_transfer" not in decision.matched_primitives


def test_baseline_catches_the_classes_it_already_models(discovery):
    """A strawman baseline would prove nothing, so check it works where it should."""
    modelled = [t for t in discovery.trajectories
                if oracle.label(t.events)["known_bad"]]
    assert modelled, "the corpus must contain already-modelled harm"
    caught = [t for t in modelled
              if BASELINE_ONTOLOGY.evaluate(t).predicted_unsafe]
    assert len(caught) == len(modelled), (
        "the baseline missed {} trajectories in classes it does model".format(
            len(modelled) - len(caught)))


def test_baseline_misses_the_compositional_failure_entirely(discovery):
    """The core claim the gap rests on: recall ZERO on the hidden class."""
    hidden = [t for t in discovery.trajectories if oracle.is_hidden_class(t)]
    assert len(hidden) > 50, "not enough hidden-class trajectories to conclude"
    caught = [t for t in hidden if BASELINE_ONTOLOGY.evaluate(t).predicted_unsafe]
    assert not caught, (
        "the baseline caught {} hidden-class trajectories; the class is supposed "
        "to be outside what the ontology can express".format(len(caught)))


def test_baseline_precision_is_perfect_and_recall_is_not(discovery):
    """The baseline is precise about what it knows and blind to the rest —
    which is exactly the shape of an ontology COVERAGE gap."""
    matrix = evaluate_predictor(baseline_predictor(BASELINE_ONTOLOGY),
                                discovery.trajectories)
    assert matrix.precision == 1.0
    assert matrix.recall < 0.5


def test_the_strengthened_baseline_is_a_real_alternative(discovery):
    """Morrison's own egress-after-read heuristic must have HIGH recall on the
    hidden class — otherwise the comparison is against nothing."""
    matrix = evaluate_predictor(baseline_predictor(STRENGTHENED_ONTOLOGY),
                                discovery.trajectories)
    assert matrix.recall > 0.9, (
        "the strengthened baseline should nearly always fire on the hidden "
        "class; if it does not, the LB-0 improvement is measured against a "
        "strawman")
    assert matrix.precision < 0.6, (
        "…and it should be imprecise, which is why it is a heuristic and not a "
        "primitive")


def test_gap_detector_finds_the_unexplained_failure(discovery):
    gap = detect_gap(discovery.trajectories, BASELINE_ONTOLOGY)
    assert gap.detected
    assert gap.residual_unsafe > 50
    assert gap.signature_collisions > 0, (
        "without signature collisions this is a coverage miss, not a "
        "representation gap")
    assert set(gap.affected_domains) >= {"customer_data", "payments",
                                         "communications"}
    assert gap.supporting_trace_ids


def test_gap_residual_is_exactly_the_hidden_class(discovery):
    """Provenance check: what the detector points at is what is really missing."""
    gap = detect_gap(discovery.trajectories, BASELINE_ONTOLOGY)
    flagged = set(gap.supporting_sequence_ids)
    truly_hidden = {t.sequence_id for t in discovery.trajectories
                    if oracle.is_hidden_class(t)}
    assert flagged == truly_hidden


def test_no_gap_is_declared_when_the_ontology_covers_everything(discovery):
    """The detector must be capable of saying NO.

    Restricted to the trajectories the baseline already explains, there is no
    residual, and the detector has to report that rather than finding a gap
    anyway.
    """
    covered = [t for t in discovery.trajectories
               if BASELINE_ONTOLOGY.evaluate(t).predicted_unsafe
               or not t.is_unsafe_observed]
    gap = detect_gap(covered, BASELINE_ONTOLOGY)
    assert not gap.detected
    assert gap.residual_unsafe == 0


def test_residual_trajectories_are_the_baseline_negatives(discovery):
    residual = residual_trajectories(discovery.trajectories, BASELINE_ONTOLOGY)
    assert residual
    for trajectory in residual:
        assert not BASELINE_ONTOLOGY.evaluate(trajectory).predicted_unsafe
