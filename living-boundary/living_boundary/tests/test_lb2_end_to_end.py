"""The full LB-2 experiment: eight worlds, no replay, three kinds of abstention.

Asserts on the discrimination and the invariants rather than on exact metric
values, for the same reason the LB-0 and LB-1 end-to-end tests do.
"""

from __future__ import annotations

import json

import pytest

from living_boundary.evidence.lb2_report import (
    lb2_console_report, lb2_markdown_report,
)
from living_boundary.observational.inference import Lb2Verdict
from living_boundary.run_lb2 import (
    MIN_ADEQUATE_BASELINE_F1, MIN_SIMULATED_F1_GAIN, main, run,
)

SEED = 42


@pytest.fixture(scope="module")
def result():
    return run(seed=SEED, persist=False)


def test_lb2_is_supported_by_the_evidence(result):
    failed = [c["criterion"] for c in result["verdict"]["criteria"]
              if not c["passed"]]
    assert result["verdict"]["decision"] == "SUPPORTED", (
        f"criteria that failed: {failed}")


def test_every_scenario_receives_the_verdict_it_was_built_for(result):
    for name, record in result["scenarios"].items():
        expected = record["expectations"]["expected_verdict"]
        assert record["assessment"]["verdict"] == expected, name


def test_inadequacy_is_detected_without_any_replay(result):
    """The headline claim of the phase."""
    assert result["replay_used"] is False
    record = result["scenarios"]["missing_observable"]
    assert record["assessment"]["verdict"] == Lb2Verdict.INADEQUATE_LOCALISED
    assert record["assessment"]["claims"]["representation_is_insufficient"]
    assert record["assessment"]["localisation"]["observable"] == "timestamp"


def test_the_detector_can_still_say_no(result):
    adequate = result["scenarios"]["adequate"]
    assert adequate["assessment"]["verdict"] == Lb2Verdict.ADEQUATE
    assert adequate["strata"]["feature_minority"] == 0
    assert adequate["proposal"] is None
    assert adequate["base_refit"]["held_out"]["f1"] >= MIN_ADEQUATE_BASELINE_F1


def test_stochasticity_and_an_unrecorded_cause_are_reported_as_one_verdict(result):
    """The price of losing replay, asserted as a property of the run.

    LB-1 separated these two by re-running. LB-2 cannot, and the honest
    behaviour is to give them the same verdict rather than to guess. If this
    test ever starts failing because the two diverge, the mechanism that
    separated them needs explaining before it is believed.
    """
    stochastic = result["scenarios"]["stochastic"]["assessment"]
    unobserved = result["scenarios"]["unobserved_driver"]["assessment"]
    assert stochastic["verdict"] == unobserved["verdict"] == \
        Lb2Verdict.BEYOND_TELEMETRY
    assert not stochastic["claims"]["representation_is_insufficient"]
    assert not unobserved["claims"]["representation_is_insufficient"]
    assert "never recorded" in stochastic["reason"]


def test_telemetry_damage_stops_inference_rather_than_biasing_it(result):
    record = result["scenarios"]["telemetry_degraded"]
    assert record["assessment"]["verdict"] == Lb2Verdict.TELEMETRY_LIMITED
    assert record["assessment"]["abstained"]
    assert record["integrity"]["seals_broken"] > 0
    assert record["proposal"] is None


def test_an_archive_too_small_to_settle_the_question_abstains(result):
    record = result["scenarios"]["small_sample"]
    assert record["assessment"]["verdict"] == Lb2Verdict.INCONCLUSIVE
    assert record["proposal"] is None
    # The gap is REAL in this scenario — abstention is not the easy answer,
    # it is the correct one on this much evidence.
    assert record["expectations"]["missing_observable"] == "timestamp"


def test_a_reversing_association_abstains(result):
    record = result["scenarios"]["temporal_drift"]
    assert record["assessment"]["verdict"] == Lb2Verdict.INCONCLUSIVE
    assert record["assessment"]["localisation"]["reason"] == "temporal reversal"
    assert record["proposal"] is None


def test_collinear_observables_prevent_a_localisation_claim(result):
    record = result["scenarios"]["collinear_confounding"]
    assessment = record["assessment"]
    assert assessment["verdict"] == Lb2Verdict.INADEQUATE_UNLOCALISED
    assert assessment["claims"]["representation_is_insufficient"] is True
    assert assessment["claims"]["specific_observable_is_missing"] is False
    assert assessment["localisation"]["reason"] == "collinear candidates"
    assert set(assessment["localisation"]["collinear_observables"]) == {
        "timestamp", "actor_id"}
    assert record["proposal"] is None


def test_causation_is_never_claimed_anywhere(result):
    for name, record in result["scenarios"].items():
        assert record["assessment"]["claims"]["causation_established"] is False, name
        assert record["assessment"]["causal_claim"] == "none", name


def test_the_run_abstains_on_a_material_share_of_scenarios(result):
    """A pipeline that never abstains has not been tested on the hard cases."""
    assert result["verdict"]["abstention_rate"] >= 0.25
    assert result["verdict"]["classification_accuracy"] == 1.0


def test_the_simulated_extension_improves_held_out_without_executing(result):
    recovery = result["scenarios"]["missing_observable"]["simulated_recovery"]
    assert recovery["f1_gain"] >= MIN_SIMULATED_F1_GAIN
    assert recovery["executed_anything"] is False


def test_error_floors_are_reported_at_both_levels(result):
    """Two different bounds, and the difference between them is the finding."""
    strata = result["scenarios"]["missing_observable"]["strata"]
    assert strata["irreducible_error_rate_current_grammar"] > 0
    assert strata["telemetry_floor"] == 0.0
    beyond = result["scenarios"]["stochastic"]["strata"]
    assert beyond["telemetry_floor"] > 0


def test_authority_and_grammar_invariants_hold(result):
    assert result["authority"]["production_authority_reachable"] is False
    assert result["grammar_immutability"]["unchanged"] is True
    assert result["production_fingerprint"]["unchanged"] is True


# ── reproducibility and evidence ────────────────────────────────────────

def test_run_is_reproducible_from_seed():
    first = run(seed=88, persist=False)
    again = run(seed=88, persist=False)
    assert first["run_id"] == again["run_id"]
    assert first["evidence"]["chain"]["head"] == again["evidence"]["chain"]["head"]
    for name in first["scenarios"]:
        assert (first["scenarios"][name]["assessment"]["verdict"]
                == again["scenarios"][name]["assessment"]["verdict"])


def test_the_discrimination_holds_on_another_seed():
    other = run(seed=1234, persist=False)
    assert other["verdict"]["decision"] == "SUPPORTED"


def test_evidence_chain_seals_every_scenario(result):
    chain = result["evidence"]["chain"]
    assert chain["verified"] is True
    assert chain["problems"] == []
    stages = [entry["stage"] for entry in result["evidence"]["stages"]]
    for name in result["scenarios"]:
        assert f"scenario:{name}" in stages
    assert "authority" in stages and "verdict" in stages


def test_persisting_writes_the_required_artifacts():
    from pathlib import Path

    persisted = run(seed=SEED, persist=True)
    directory = Path(persisted["artifact_dir"])
    assert directory.parent.name == "lb2"
    for name in ("run_manifest.json", "dataset_manifest.json",
                 "observational_cohorts.json", "collision_analysis.json",
                 "uncertainty_analysis.json", "candidate_extensions.json",
                 "falsification_results.json", "held_out_metrics.json",
                 "provenance.json", "report.md"):
        assert (directory / name).exists(), name
    manifest = json.loads((directory / "run_manifest.json").read_text())
    assert manifest["verdict"]["decision"] == persisted["verdict"]["decision"]


# ── reporting ───────────────────────────────────────────────────────────

def test_console_report_shows_abstention_and_eliminations(result):
    text = lb2_console_report(result)
    assert "LB-2 Observational Representation Adequacy" in text
    assert "Abstention rate:" in text
    assert "Replay used:             False" in text
    assert "Production authority reachable:    NO" in text
    for criterion in result["verdict"]["criteria"]:
        assert criterion["criterion"] in text
    assert "the evidence is intact" in text


def test_markdown_report_is_complete(result):
    text = lb2_markdown_report(result)
    assert "**RESULT:" in text
    assert "## Verdict per scenario" in text
    assert "## Authority" in text
    assert "## Acceptance criteria" in text
    assert "Replay used: False" in text


def test_cli_runs(capsys):
    assert main(["--seed", "5", "--no-persist"]) == 0
    assert "LB-2 Observational" in capsys.readouterr().out


def test_cli_require_supported(capsys):
    code = main(["--seed", "42", "--no-persist", "--require-supported"])
    capsys.readouterr()
    assert code == 0
