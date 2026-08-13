"""The full LB-1 experiment, end to end.

Asserts on the discrimination and the invariants rather than on exact metric
values, for the same reason the LB-0 end-to-end test does: pinning numbers
would turn an experiment into a golden file, and a future corpus that made the
problem harder would read as a regression.
"""

from __future__ import annotations

import json

import pytest

from living_boundary.evidence.lb1_report import (
    lb1_console_report, lb1_markdown_report,
)
from living_boundary.representation.adequacy import AdequacyVerdict
from living_boundary.run_lb1 import (
    MIN_ADEQUATE_BASELINE_F1, MIN_RECOVERY_F1_GAIN, main, run,
)

SEED = 42


@pytest.fixture(scope="module")
def result():
    return run(seed=SEED, persist=False)


def test_lb1_is_supported_by_the_evidence(result):
    failed = [c["criterion"] for c in result["verdict"]["criteria"]
              if not c["passed"]]
    assert result["verdict"]["decision"] == "SUPPORTED", (
        f"criteria that failed: {failed}")


def test_every_environment_receives_the_verdict_it_was_built_for(result):
    for name, record in result["environments"].items():
        expected = record["environment_expectations"]["expected_verdict"]
        assert record["assessment"]["verdict"] == expected, name


def test_the_detector_can_say_no(result):
    """The negative control. A detector that never returns ADEQUATE is not a
    detector — it is a machine for generating work."""
    adequate = result["environments"]["adequate"]
    assert adequate["assessment"]["verdict"] == AdequacyVerdict.ADEQUATE
    assert adequate["collision"]["colliding_groups"] == 0
    assert adequate["proposal"] is None
    assert adequate["base_refit"]["held_out"]["f1"] >= MIN_ADEQUATE_BASELINE_F1


def test_collisions_alone_do_not_separate_the_environments(result):
    """The central methodological claim, asserted as a property of the run.

    If collision rate alone were sufficient, the probe would be decoration. It
    is not: environments with different verdicts produce comparable collision
    rates, and only the probe columns distinguish them.
    """
    environments = result["environments"]
    inadequate = environments["inadequate_timing"]["collision"]["collision_rate"]
    stochastic = environments["stochastic"]["collision"]["collision_rate"]
    assert abs(inadequate - stochastic) < 0.10, (
        "these two collide at similar rates and receive different verdicts; if "
        "they diverged here, collisions alone would be doing the work")
    assert (environments["inadequate_timing"]["assessment"]["verdict"]
            != environments["stochastic"]["assessment"]["verdict"])


def test_the_probe_is_what_separates_them(result):
    environments = result["environments"]
    assert environments["stochastic"]["probe"]["self_disagreement_rate"] > 0.05
    assert environments["noise_limited"]["probe"]["record_disagreement_rate"] > 0.05
    assert environments["noise_limited"]["probe"]["self_disagreement_rate"] <= 0.02
    for name in ("inadequate_timing", "inadequate_delegation",
                 "inadequate_unlocalised"):
        probe = environments[name]["probe"]
        assert probe["self_disagreement_rate"] <= 0.02, name
        assert probe["record_disagreement_rate"] <= 0.02, name


def test_inadequacy_is_localised_to_the_withheld_observable(result):
    for name, expected in (("inadequate_timing", "timestamp"),
                           ("inadequate_delegation", "actor_id")):
        localisation = result["environments"][name]["localisation"]
        assert localisation["localised"], name
        assert localisation["best"]["observable"] == expected, name


def test_an_inadequacy_outside_the_pool_is_reported_as_unlocalised(result):
    """The control that keeps localisation honest."""
    record = result["environments"]["inadequate_unlocalised"]
    assert record["assessment"]["verdict"] == AdequacyVerdict.INADEQUATE
    assert not record["localisation"]["localised"]
    assert record["proposal"] is None
    assert record["localisation"]["best"] is not None


def test_reading_the_nominated_observable_recovers_the_outcome(result):
    for name in ("inadequate_timing", "inadequate_delegation"):
        recovery = result["environments"][name]["recovery"]
        assert recovery["f1_gain"] >= MIN_RECOVERY_F1_GAIN, name
        assert (recovery["extended_held_out"]["f1"]
                > recovery["base_held_out"]["f1"]), name


def test_proposals_are_experimental_and_carry_no_authority(result):
    proposals = [record["proposal"] for record in result["environments"].values()
                 if record["proposal"]]
    assert proposals
    for proposal in proposals:
        assert proposal["status"] == "REVIEW_REQUIRED"
        assert proposal["production_authority"] == "none"
        assert proposal["grammar_mutation_authority"] == "none"
        assert proposal["demonstrated_recovery"]
        assert proposal["evidence"]["collision"]
        assert proposal["evidence"]["probe"]


def test_no_proposal_where_the_representation_is_fine(result):
    for name in ("adequate", "noise_limited", "stochastic",
                 "inadequate_unlocalised"):
        assert result["environments"][name]["proposal"] is None, name


def test_authority_and_grammar_invariants_hold(result):
    assert result["authority"]["production_authority_reachable"] is False
    assert result["grammar_immutability"]["unchanged"] is True
    assert result["production_fingerprint"]["unchanged"] is True


# ── reproducibility and evidence ────────────────────────────────────────

def test_run_is_reproducible_from_seed():
    first = run(seed=77, persist=False)
    again = run(seed=77, persist=False)
    assert first["dataset"]["corpus_hash"] == again["dataset"]["corpus_hash"]
    assert first["run_id"] == again["run_id"]
    assert first["evidence"]["chain"]["head"] == again["evidence"]["chain"]["head"]
    for name in first["environments"]:
        assert (first["environments"][name]["assessment"]["verdict"]
                == again["environments"][name]["assessment"]["verdict"])


def test_the_discrimination_holds_on_another_seed():
    other = run(seed=123, persist=False)
    assert other["verdict"]["decision"] == "SUPPORTED"


def test_evidence_chain_seals_every_environment(result):
    chain = result["evidence"]["chain"]
    assert chain["verified"] is True
    assert chain["problems"] == []
    stages = [entry["stage"] for entry in result["evidence"]["stages"]]
    assert "corpus" in stages and "authority" in stages and "verdict" in stages
    for name in result["environments"]:
        assert f"environment:{name}" in stages


def test_persisting_writes_a_complete_evidence_package():
    from pathlib import Path

    persisted = run(seed=SEED, persist=True)
    directory = Path(persisted["artifact_dir"])
    for name in ("run_manifest.json", "corpus_manifest.json",
                 "adequacy_assessments.json", "collisions.json", "probes.json",
                 "proposals.json", "authority.json", "evidence_chain.jsonl",
                 "report.md"):
        assert (directory / name).exists(), name
    manifest = json.loads((directory / "run_manifest.json").read_text())
    assert manifest["verdict"]["decision"] == persisted["verdict"]["decision"]


# ── reporting ───────────────────────────────────────────────────────────

def test_console_report_shows_the_eliminations(result):
    text = lb1_console_report(result)
    assert "LB-1 Representation Adequacy Experiment" in text
    assert "Production authority reachable:   NO" in text
    assert "Feature grammar mutated by LB-1:  NO" in text
    for criterion in result["verdict"]["criteria"]:
        assert criterion["criterion"] in text
    # The verdict is reached by elimination, so the eliminations have to be
    # visible or the reader has a conclusion rather than an argument.
    assert "the world is reproducible" in text
    assert "the record is faithful" in text


def test_markdown_report_is_complete(result):
    text = lb1_markdown_report(result)
    assert "**RESULT:" in text
    assert "## Verdict per environment" in text
    assert "## Authority" in text
    assert "## Acceptance criteria" in text
    assert "UNLOCALISED" in text or "inadequate_unlocalised" in text


def test_cli_runs(capsys):
    assert main(["--seed", "11", "--no-persist"]) == 0
    assert "LB-1 Representation Adequacy" in capsys.readouterr().out


def test_cli_require_supported(capsys):
    code = main(["--seed", "42", "--no-persist", "--require-supported"])
    capsys.readouterr()
    assert code == 0
