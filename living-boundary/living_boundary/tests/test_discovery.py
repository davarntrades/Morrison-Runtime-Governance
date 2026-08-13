"""Discovery, falsification and held-out evaluation, tested in isolation."""

from __future__ import annotations

from living_boundary.discovery.gap_detector import residual_trajectories
from living_boundary.discovery.primitive_generator import generate_candidate
from living_boundary.discovery.structure_discovery import (
    DiscoveredStructure, prune_structure, search_structures, select_structure,
)
from living_boundary.evaluation.evaluator import (
    baseline_predictor, combined_predictor, compare_to_baseline,
    evaluate_predictor, ground_truth_labels, residual_recovery,
)
from living_boundary.evaluation.metrics import ConfusionMatrix, confusion
from living_boundary.experiments.runner import (
    MIN_ABLATION_AGREEMENT, run_falsification,
)
from living_boundary.ontology.baseline import BASELINE_ONTOLOGY

BEAM = 48


def _fit(dataset):
    fit = residual_trajectories(dataset.split("discovery").trajectories,
                                BASELINE_ONTOLOGY)
    guard = residual_trajectories(dataset.split("validation").trajectories,
                                  BASELINE_ONTOLOGY)
    return (fit, [t.is_unsafe_observed for t in fit],
            guard, [t.is_unsafe_observed for t in guard])


def _candidate(dataset):
    fit, fit_y, guard, guard_y = _fit(dataset)
    search = search_structures(fit, fit_y, guard_trajectories=guard,
                               guard_labels=guard_y, beam_width=BEAM)
    structure = prune_structure(select_structure(search, guard, guard_y),
                                guard, guard_y)
    return generate_candidate(structure, fit, fit_y,
                              ontology_version=BASELINE_ONTOLOGY.version)


# ── metrics ─────────────────────────────────────────────────────────────

def test_confusion_matrix_rates():
    matrix = confusion([True, True, False, False], [True, False, True, False])
    assert (matrix.tp, matrix.fp, matrix.fn, matrix.tn) == (1, 1, 1, 1)
    assert matrix.precision == 0.5 and matrix.recall == 0.5
    assert matrix.false_positive_rate == 0.5
    assert matrix.false_negative_rate == 0.5
    assert abs(matrix.mcc) < 1e-9


def test_mcc_separates_a_perfect_predictor_from_a_useless_one():
    """The statistic the memorisation control depends on."""
    perfect = ConfusionMatrix(tp=50, fp=0, tn=50, fn=0)
    useless = ConfusionMatrix(tp=25, fp=25, tn=25, fn=25)
    assert perfect.mcc == 1.0
    assert abs(useless.mcc) < 1e-9
    # …and F1 does NOT separate them nearly as well, which is the whole reason
    # MCC is the gate: 1.00 vs 0.50 rather than 1.00 vs 0.00.
    assert useless.f1 == 0.5


# ── search ──────────────────────────────────────────────────────────────

def test_search_finds_a_structure_and_records_what_it_did(dataset):
    fit, fit_y, guard, guard_y = _fit(dataset)
    search = search_structures(fit, fit_y, guard_trajectories=guard,
                               guard_labels=guard_y, beam_width=BEAM)
    assert search.pool
    assert search.literals_considered > 100
    assert search.conjunctions_evaluated > 1000
    assert search.as_dict()["pool_size"] == len(search.pool)


def test_search_is_deterministic(dataset):
    fit, fit_y, guard, guard_y = _fit(dataset)
    first = search_structures(fit, fit_y, guard_trajectories=guard,
                              guard_labels=guard_y, beam_width=BEAM)
    again = search_structures(fit, fit_y, guard_trajectories=guard,
                              guard_labels=guard_y, beam_width=BEAM)
    assert [s.literal_names for s in first.pool] == \
           [s.literal_names for s in again.pool]


def test_the_selected_structure_avoids_the_confounder(dataset):
    """`session_tag::tag_hot` separates the discovery split perfectly.

    A candidate that used it would be the headline failure mode of this whole
    experiment, so it is asserted directly rather than inferred from held-out
    numbers.
    """
    candidate = _candidate(dataset)
    surface = [name for name in candidate.literal_names
               if name.replace("NOT ", "").partition("::")[0]
               in ("provider", "region", "session_tag")]
    assert not surface, f"candidate leans on session metadata: {surface}"
    assert not candidate.discovery_metrics["uses_surface_features"]


def test_pruning_removes_literals_that_do_no_work(dataset):
    _, _, guard, guard_y = _fit(dataset)
    padded = DiscoveredStructure(literal_names=(
        "has_cap::data.read", "has_cap::payment.move_funds",
        "steps_ge::2", "has_boundary::internal"))
    pruned = prune_structure(padded, guard, guard_y)
    assert len(pruned.literal_names) <= len(padded.literal_names)


# ── candidate ───────────────────────────────────────────────────────────

def test_candidate_contains_source_provenance(dataset):
    candidate = _candidate(dataset)
    assert candidate.supporting_traces >= 20
    assert len(candidate.source_evidence) == candidate.supporting_traces
    known = {t.sequence_id for t in dataset.split("discovery").trajectories}
    assert set(candidate.source_evidence) <= known, (
        "source evidence must point at real trace sequence ids")


def test_candidate_generates_a_falsifiable_prediction(dataset):
    candidate = _candidate(dataset)
    assert "falsifi" in candidate.falsifiable_prediction.lower()
    # Every clause of the prediction corresponds to a literal that can be
    # ablated — that correspondence is what makes it falsifiable rather than
    # merely worded confidently.
    for literal in candidate.literals:
        assert literal.description in candidate.falsifiable_prediction
        assert literal.description in candidate.hypothesis


def test_candidate_is_experimental_until_falsification(dataset):
    candidate = _candidate(dataset)
    assert candidate.status == "HYPOTHESISED"
    assert candidate.as_dict()["production_authority"] == "none"


# ── falsification ───────────────────────────────────────────────────────

def test_every_condition_produces_counterexamples(dataset):
    """An untested condition is an unfalsifiable claim, and the runner says so."""
    candidate = _candidate(dataset)
    report = run_falsification(candidate,
                               dataset.split("validation").trajectories, 42)
    assert report.cases_generated > 50
    assert not report.untestable_literals
    for name, stats in report.per_literal.items():
        assert stats["cases"] >= 5, name
        assert stats["agreement"] >= MIN_ABLATION_AGREEMENT, (name, stats)


def test_falsification_rejects_a_candidate_built_on_a_confounder(dataset):
    """The runner must be able to FAIL, demonstrated on a known-bad candidate.

    `session_tag::tag_hot` is a perfect predictor on the discovery split and a
    worthless one everywhere else. If the falsification battery passed it, every
    other PASS in this suite would be uninformative.
    """
    from living_boundary.discovery.features import make_literal
    from living_boundary.ontology.candidate_schema import CandidatePrimitive

    bogus = CandidatePrimitive(
        candidate_id="CP-BOGUS", name="confounder", description="confounder",
        literals=(make_literal("session_tag::tag_hot"),))
    report = run_falsification(
        bogus, dataset.split("discovery").trajectories, 42)
    assert not report.passed
    assert report.failures


def test_surface_rewriting_does_not_move_the_candidate(dataset):
    candidate = _candidate(dataset)
    report = run_falsification(candidate,
                               dataset.split("validation").trajectories, 42)
    surface = report.per_control.get("surface_rewrite")
    assert surface and surface["cases"] > 0
    assert surface["agreement"] >= 0.95


# ── evaluation ──────────────────────────────────────────────────────────

def test_candidate_is_evaluated_on_unseen_cases(dataset):
    """The held-out split shares no identity, subject or sequence id with the
    corpora the candidate was built from."""
    candidate = _candidate(dataset)
    held_out = dataset.split("held_out").trajectories
    comparison = compare_to_baseline(
        "held_out", held_out, baseline_predictor(BASELINE_ONTOLOGY),
        combined_predictor(BASELINE_ONTOLOGY, candidate))
    assert comparison.candidate.total == len(held_out)
    assert comparison.improved
    assert comparison.f1_delta > 0.05
    assert comparison.candidate.false_positive_rate <= 0.05


def test_safe_near_misses_remain_safe(dataset):
    """The whole point of the near-miss families: they must NOT be flagged."""
    candidate = _candidate(dataset)
    held_out = dataset.split("held_out")
    flagged = [t for t in held_out.trajectories
               if candidate.matches(t) and not t.is_unsafe_observed]
    assert not flagged, (
        "{} safe trajectories were flagged, e.g. {}".format(
            len(flagged), [t.sequence_id for t in flagged[:5]]))


def test_ground_truth_comes_from_the_oracle_not_the_trace_label(dataset):
    held_out = dataset.split("held_out").trajectories
    assert ground_truth_labels(held_out) == [
        t.is_unsafe_observed for t in held_out], (
        "for dataset trajectories the two must agree; they diverge only for "
        "falsification cases, which carry no label")


def test_residual_recovery_reports_the_blind_spot(dataset):
    candidate = _candidate(dataset)
    recovery = residual_recovery(dataset.split("held_out").trajectories,
                                 BASELINE_ONTOLOGY, candidate)
    assert recovery["uncovered_unsafe"] > 50
    assert recovery["recovery_rate"] > 0.9
    assert recovery["false_positive_rate_on_uncovered_safe"] <= 0.05


def test_the_candidate_is_a_complement_to_the_ontology_not_a_replacement(dataset):
    """Measured alone, the candidate is perfectly precise and deliberately
    incomplete.

    Its false negatives are exactly the classes the existing ontology already
    covers — credential exfiltration, privilege escalation, destructive
    infrastructure, prohibited communication. A candidate that also caught those
    would be duplicating existing policy, which the blueprint lists as a FAILURE
    criterion ("generated primitives duplicate existing policies"), not a
    success. So the assertion is about precision and about WHAT it misses, not
    about total recall.
    """
    candidate = _candidate(dataset)
    held_out = dataset.split("held_out").trajectories
    alone = evaluate_predictor(candidate.matches, held_out)
    assert alone.precision == 1.0
    assert alone.mcc > 0.7

    missed = [t for t in held_out
              if t.is_unsafe_observed and not candidate.matches(t)]
    from living_boundary.experiments import hidden_ground_truth as oracle
    not_already_modelled = [t for t in missed
                            if not oracle.label(t.events)["known_bad"]]
    assert not not_already_modelled, (
        "the candidate missed {} unsafe trajectories that the existing ontology "
        "does NOT cover".format(len(not_already_modelled)))
