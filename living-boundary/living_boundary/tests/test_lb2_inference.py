"""The observational machinery, unit-tested away from the corpora.

The end-to-end test shows eight scenarios land on the right rung. These show the
ladder itself is correct, the arithmetic underneath it is correct, and both
would still be correct on inputs those eight scenarios happen not to produce.
"""

from __future__ import annotations

import pytest

from living_boundary.observational.archive import (
    canonical_record, feature_signature, record_signature,
)
from living_boundary.observational.inference import Lb2Verdict, assess
from living_boundary.observational.strata import stratify
from living_boundary.observational.temporal import TemporalConsistency
from living_boundary.observational.uncertainty import (
    Association, StratumCounts, agreement, mantel_haenszel, wilson,
)


# ── uncertainty arithmetic ──────────────────────────────────────────────

def test_wilson_stays_inside_the_unit_interval_at_the_extremes():
    """The reason Wilson and not the normal approximation.

    At 0/12 the normal interval runs below zero, which is not a proportion.
    Small strata with extreme rates are the common case here, not the corner.
    """
    for successes, total in ((0, 12), (12, 12), (1, 3), (0, 1)):
        interval = wilson(successes, total)
        assert 0.0 <= interval.lower <= interval.upper <= 1.0


def test_wilson_narrows_with_evidence():
    assert wilson(5, 10).width > wilson(50, 100).width > wilson(500, 1000).width


def test_wilson_on_no_data_is_maximally_uncertain():
    interval = wilson(0, 0)
    assert (interval.lower, interval.upper) == (0.0, 1.0)


def test_mantel_haenszel_ignores_strata_with_one_arm():
    """A stratum with no comparison contributes no evidence for one."""
    strata = [StratumCounts("a", exposed_total=10, exposed_unsafe=10),
              StratumCounts("b", unexposed_total=10, unexposed_unsafe=0)]
    association = mantel_haenszel(strata)
    assert association.strata_total == 2
    assert association.strata_informative == 0
    assert not association.significant


def test_mantel_haenszel_recovers_a_clean_effect():
    strata = [StratumCounts(f"s{i}", exposed_total=20, exposed_unsafe=20,
                            unexposed_total=20, unexposed_unsafe=0)
              for i in range(6)]
    association = mantel_haenszel(strata, exposure="x", observable="timestamp")
    assert association.pooled_risk_difference == pytest.approx(1.0)
    assert association.significant


def test_mantel_haenszel_reports_no_effect_when_there_is_none():
    strata = [StratumCounts(f"s{i}", exposed_total=40, exposed_unsafe=20,
                            unexposed_total=40, unexposed_unsafe=20)
              for i in range(6)]
    association = mantel_haenszel(strata)
    assert association.pooled_risk_difference == pytest.approx(0.0)
    assert not association.significant


def test_pooling_does_not_manufacture_an_effect_from_stratum_imbalance():
    """Simpson's paradox, in miniature.

    Each stratum shows no effect; the arms are wildly unbalanced between
    strata, and the strata have very different base rates. A naive pooled
    comparison would report a large effect. The MH estimate must not.
    """
    strata = [
        StratumCounts("high", exposed_total=90, exposed_unsafe=81,
                      unexposed_total=10, unexposed_unsafe=9),
        StratumCounts("low", exposed_total=10, exposed_unsafe=1,
                      unexposed_total=90, unexposed_unsafe=9),
    ]
    naive_exposed = (81 + 1) / (90 + 10)
    naive_unexposed = (9 + 9) / (10 + 90)
    assert naive_exposed - naive_unexposed > 0.6
    assert mantel_haenszel(strata).pooled_risk_difference == pytest.approx(0.0)


def test_agreement_detects_collinearity():
    assert agreement([True, False, True], [True, False, True]) == 1.0
    assert agreement([True, False, True], [False, True, False]) == 0.0


# ── record identity ─────────────────────────────────────────────────────

def test_record_identity_ignores_which_customer_it_was(dataset):
    """Two sessions of the same shape on different subjects are one event.

    Without this the archive would contain no repeats at all and every
    observational method here would have nothing to compare.
    """
    from living_boundary.experiments.lb2_builder import DISCOVERY, build_archive
    from living_boundary.experiments.lb2_scenarios import ADEQUATE

    trajectories = list(build_archive(3, ADEQUATE, DISCOVERY).archive.trajectories)
    signatures = {record_signature(t) for t in trajectories}
    assert len(signatures) < len(trajectories) / 4, (
        "record signatures barely repeat; observational matching would be "
        "impossible on this corpus")


def test_the_record_determines_the_features(dataset):
    """The nesting property the whole decomposition rests on."""
    from living_boundary.experiments.lb2_builder import DISCOVERY, build_archive
    from living_boundary.experiments.lb2_scenarios import MISSING_OBSERVABLE

    trajectories = list(
        build_archive(3, MISSING_OBSERVABLE, DISCOVERY).archive.trajectories)
    by_record = {}
    for trajectory in trajectories:
        by_record.setdefault(record_signature(trajectory), set()).add(
            feature_signature(trajectory))
    for record, features in by_record.items():
        assert len(features) == 1, (
            f"record {record} maps to {len(features)} feature signatures; "
            f"record-level collisions would no longer be a subset of "
            f"feature-level ones and the decomposition would be unsound")


def test_masking_removes_only_the_named_observable(dataset):
    from living_boundary.experiments.lb2_builder import DISCOVERY, build_archive
    from living_boundary.experiments.lb2_scenarios import ADEQUATE

    trajectory = list(
        build_archive(3, ADEQUATE, DISCOVERY).archive.trajectories)[0]
    full = canonical_record(trajectory)
    masked = canonical_record(trajectory, mask=("timestamp",))
    assert all(row["offset"] is None for row in masked)
    assert all(row["offset"] is not None for row in full)
    assert ([row["capability"] for row in masked]
            == [row["capability"] for row in full])
    assert [row["actor"] for row in masked] == [row["actor"] for row in full]


# ── the ladder ──────────────────────────────────────────────────────────

class _Cohorts:
    def __init__(self, supported=(), collinear=()):
        self.supported = list(supported)
        self.collinear_groups = list(collinear)

    def as_dict(self):
        return {"exposures_supported": len(self.supported)}


class _Exposure:
    def __init__(self, name="x", observable="timestamp", family="elapsed"):
        self.name = name
        self.observable = observable
        self.family = family
        self.matching = "exact"
        self.association = Association(exposure=name, observable=observable,
                                       strata_informative=8,
                                       matched_trajectories=400,
                                       pooled_risk_difference=0.5,
                                       lower=0.3, upper=0.7)


class _Strata:
    def __init__(self, trajectories=900, collisions=300, minority=120,
                 record_minority=0):
        self._inner = None
        self.trajectories = trajectories
        self.feature_minority = minority
        self.record_minority = record_minority
        self._collisions = collisions

    @property
    def collision_rate(self):
        return wilson(self._collisions, self.trajectories)

    @property
    def resolvable_fraction(self):
        return wilson(max(0, self.feature_minority - self.record_minority),
                      self.feature_minority)

    @property
    def irreducible_error_rate(self):
        return self.feature_minority / self.trajectories

    @property
    def feature_colliding(self):
        return 20

    def as_dict(self):
        return {"trajectories": self.trajectories}


_INTACT = {"seal_failure_rate": 0.0, "field_incompleteness_rate": 0.0,
           "sequences_with_step_gaps": 0}


def test_broken_seals_stop_everything():
    assessment = assess({"seal_failure_rate": 0.05,
                         "field_incompleteness_rate": 0.0,
                         "sequences_with_step_gaps": 0},
                        _Strata(), _Cohorts(), {}, {})
    assert assessment.verdict == Lb2Verdict.TELEMETRY_LIMITED
    assert assessment.abstained


def test_incomplete_fields_stop_everything():
    assessment = assess({"seal_failure_rate": 0.0,
                         "field_incompleteness_rate": 0.20,
                         "sequences_with_step_gaps": 0},
                        _Strata(), _Cohorts(), {}, {})
    assert assessment.verdict == Lb2Verdict.TELEMETRY_LIMITED


def test_a_small_archive_cannot_certify_anything():
    assessment = assess(_INTACT, _Strata(trajectories=90, collisions=30,
                                         minority=12), _Cohorts(), {}, {})
    assert assessment.verdict == Lb2Verdict.INCONCLUSIVE
    assert "too few" in assessment.reason


def test_no_collisions_yields_adequate():
    assessment = assess(_INTACT, _Strata(collisions=2, minority=1),
                        _Cohorts(), {}, {})
    assert assessment.verdict == Lb2Verdict.ADEQUATE
    assert not assessment.claims["representation_is_insufficient"]


def test_disagreement_the_record_cannot_explain_is_beyond_telemetry():
    assessment = assess(_INTACT,
                        _Strata(minority=120, record_minority=118),
                        _Cohorts(), {}, {})
    assert assessment.verdict == Lb2Verdict.BEYOND_TELEMETRY
    assert "stochastic" in assessment.reason
    assert "never recorded" in assessment.reason
    assert not assessment.claims["representation_is_insufficient"]


def test_a_split_verdict_abstains():
    """Half explained by the record, half not: the archive does not settle it."""
    assessment = assess(_INTACT, _Strata(minority=120, record_minority=55),
                        _Cohorts(), {}, {})
    assert assessment.verdict == Lb2Verdict.INCONCLUSIVE


def test_a_reversing_association_abstains():
    check = TemporalConsistency(exposure="x", testable=True, consistent=False,
                               reason="it reverses.")
    assessment = assess(_INTACT, _Strata(), _Cohorts(supported=[_Exposure()]),
                        {"x": check}, {})
    assert assessment.verdict == Lb2Verdict.INCONCLUSIVE
    assert "reverses" in assessment.reason


def test_no_supported_exposure_yields_unlocalised():
    assessment = assess(_INTACT, _Strata(), _Cohorts(), {}, {})
    assert assessment.verdict == Lb2Verdict.INADEQUATE_UNLOCALISED
    assert assessment.claims["representation_is_insufficient"]
    assert not assessment.claims["specific_observable_is_missing"]


def test_collinear_candidates_prevent_localisation():
    """Two observables that move together cannot be told apart, ever."""
    first = _Exposure(name="a", observable="timestamp")
    second = _Exposure(name="b", observable="actor_id")
    assessment = assess(
        _INTACT, _Strata(),
        _Cohorts(supported=[first, second], collinear=[("a", "b")]), {}, {})
    assert assessment.verdict == Lb2Verdict.INADEQUATE_UNLOCALISED
    assert assessment.localisation["reason"] == "collinear candidates"
    assert assessment.localisation["collinear_observables"] == [
        "actor_id", "timestamp"]


_REPLICATED = {"x": {"supported": True, "sign_flipped": False,
                     "detail": "validation risk difference +0.48"}}


def test_a_clean_case_localises():
    assessment = assess(_INTACT, _Strata(), _Cohorts(supported=[_Exposure()]),
                        {}, {}, replication=_REPLICATED)
    assert assessment.verdict == Lb2Verdict.INADEQUATE_LOCALISED
    assert assessment.claims["specific_observable_is_missing"]
    assert assessment.localisation["observable"] == "timestamp"


def test_a_candidate_that_does_not_replicate_is_not_localised():
    """Selection over many candidates finds something whether or not anything
    is there; a second archive is what catches that."""
    assessment = assess(_INTACT, _Strata(), _Cohorts(supported=[_Exposure()]),
                        {}, {}, replication={"x": {"supported": False,
                                                   "detail": "null"}})
    assert assessment.verdict == Lb2Verdict.INADEQUATE_UNLOCALISED
    assert assessment.localisation["reason"] == "no replication"
    assert assessment.claims["representation_is_insufficient"]
    assert not assessment.claims["specific_observable_is_missing"]


def test_a_missing_replication_estimate_is_not_localised():
    assessment = assess(_INTACT, _Strata(), _Cohorts(supported=[_Exposure()]),
                        {}, {})
    assert assessment.verdict == Lb2Verdict.INADEQUATE_UNLOCALISED


def test_a_replication_that_points_the_other_way_is_not_localised():
    assessment = assess(
        _INTACT, _Strata(), _Cohorts(supported=[_Exposure()]), {}, {},
        replication={"x": {"supported": True, "sign_flipped": True,
                           "detail": "validation risk difference -0.41"}})
    assert assessment.verdict == Lb2Verdict.INADEQUATE_UNLOCALISED
    assert assessment.localisation["reason"] == "replication sign flip"


def test_causation_is_never_claimed():
    for assessment in (
            assess(_INTACT, _Strata(), _Cohorts(supported=[_Exposure()]), {}, {},
                   replication=_REPLICATED),
            assess(_INTACT, _Strata(collisions=2, minority=1), _Cohorts(), {}, {}),
            assess(_INTACT, _Strata(minority=120, record_minority=118),
                   _Cohorts(), {}, {})):
        assert assessment.claims["causation_established"] is False
        assert assessment.as_dict()["causal_claim"] == "none"


def test_every_verdict_carries_its_eliminations():
    assessment = assess(_INTACT, _Strata(), _Cohorts(supported=[_Exposure()]),
                        {}, {}, replication=_REPLICATED)
    assert len(assessment.eliminations) >= 3
    assert any("intact" in e for e in assessment.eliminations)


def test_stratify_on_a_uniform_corpus_finds_nothing(dataset):
    from living_boundary.experiments.lb2_builder import DISCOVERY, build_archive
    from living_boundary.experiments.lb2_scenarios import ADEQUATE

    strata = stratify(list(
        build_archive(3, ADEQUATE, DISCOVERY).archive.trajectories))
    assert strata.feature_minority == 0
    assert strata.irreducible_error_rate == 0.0
    assert strata.telemetry_floor == 0.0
