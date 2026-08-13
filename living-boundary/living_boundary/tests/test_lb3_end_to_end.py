"""The full LB-3 experiment: nine environments, three grammars, ten rivals.

Asserts on the DISCRIMINATIONS and the invariants rather than on exact metric
values, for the same reason the LB-0, LB-1 and LB-2 end-to-end tests do. The
one place this module does pin a specific outcome is the verdict, because the
verdict is PARTIALLY_SUPPORTED and the reason it is not SUPPORTED is a measured
finding that must not silently disappear.
"""

from __future__ import annotations

import json

import pytest

from living_boundary.evidence.lb3_report import (
    lb3_console_report, lb3_markdown_report,
)
from living_boundary.run_lb3 import (
    MIN_ADVANTAGE_OVER_COMPETITORS, TRANSFER_EXPECTED, main, run,
)
from living_boundary.transfer.evaluator import (
    COLLAPSED, DEGRADED, MIN_RETENTION_FOR_TRANSFER, TRANSFERRED,
)

SEED = 42


@pytest.fixture(scope="module")
def result():
    return run(seed=SEED, persist=False)


def _cells(result, grammar):
    return result["grammars"][grammar]["transfer"]


# ── the headline ────────────────────────────────────────────────────────

def test_the_verdict_is_partially_supported_and_says_why(result):
    """Transfer holds, but not everything that was asked of it does.

    If this ever flips to SUPPORTED, something either improved or stopped being
    measured, and the failing criterion below says which to check first.
    """
    verdict = result["verdict"]
    assert verdict["decision"] == "PARTIALLY_SUPPORTED"
    assert set(verdict["failed"]) == {
        "survives_semantics_preserving_transformations",
        "reproduces_across_seeds"}
    # Both failures are the same underlying fact seen twice: the role
    # re-alignment under `pad_trace` sits at the abstention ceiling, and which
    # side of it a seed lands on decides the verdict.


def test_the_relational_encoding_is_the_one_that_transfers(result):
    assert result["primary_grammar"] == "relational"
    summary = result["grammars"]["relational"]["expected_transfer_summary"]
    assert summary["defined"]
    assert summary["minimum"] >= MIN_RETENTION_FOR_TRANSFER
    for env_id in TRANSFER_EXPECTED:
        assert _cells(result, "relational")[env_id]["outcome"] == TRANSFERRED, env_id


def test_the_vocabulary_bound_encodings_do_not_survive_a_taxonomy_change(result):
    """The finding that makes the phase worth running.

    `surface` and `typed` keep working when only the tool names change, and
    stop working the moment the capability and domain labels change with them.
    That is the boundary of the claim, located.
    """
    for grammar in ("surface", "typed"):
        cells = _cells(result, grammar)
        assert cells["env_01"]["outcome"] == TRANSFERRED, grammar
        assert cells["env_02"]["outcome"] == COLLAPSED, grammar
        assert cells["env_03"]["outcome"] == COLLAPSED, grammar


def test_surface_and_typed_found_the_same_structure(result):
    """The confounder was available and the search did not take it.

    `surface` can express provider, region and session tag; `typed` cannot. They
    produce an identical candidate, so the discovery search declined the surface
    correlation on its own. That is a result about the SEARCH, not about
    transfer, and it is why the two rows of the matrix are identical.
    """
    assert (result["grammars"]["surface"]["candidate"]["structure_hash"]
            == result["grammars"]["typed"]["candidate"]["structure_hash"])
    literals = result["grammars"]["surface"]["candidate"]["literals"]
    for family in ("provider::", "region::", "session_tag::", "scope::"):
        assert not any(family in literal for literal in literals), family


# ── the controls ────────────────────────────────────────────────────────

def test_inverting_the_relation_collapses_the_candidate(result):
    """env_05 keeps the discovery vocabulary and negates identity continuity."""
    cell = _cells(result, "relational")["env_05"]
    assert cell["outcome"] == COLLAPSED
    assert cell["retention"]["retention"] < 0.25


def test_the_negative_control_does_not_falsely_support_transfer(result):
    """env_07 is built to look like the discovery world and is not it."""
    cell = _cells(result, "relational")["env_07"]
    assert cell["outcome"] in (COLLAPSED, DEGRADED)
    assert cell["retention"]["retention"] < MIN_RETENTION_FOR_TRANSFER


def test_partial_invariance_is_reported_as_partial(result):
    """env_06 removes one clause of the rule and keeps the rest."""
    cell = _cells(result, "relational")["env_06"]
    assert cell["outcome"] == DEGRADED
    assert 0.25 <= cell["retention"]["retention"] < MIN_RETENTION_FOR_TRANSFER


def test_breaking_the_perimeter_encoding_breaks_everything(result):
    """env_08 renames the token that marks the inside of the trust boundary.

    The load-bearing assumption, measured rather than asserted. Note what does
    NOT happen: the alignment cost rises by two orders of magnitude and still
    does not clear the abstention ceiling, so LB-3 collapses here instead of
    declining to answer. That is a miscalibrated gate and it is recorded as a
    known weakness rather than retuned after the fact.
    """
    cell = _cells(result, "relational")["env_08"]
    assert cell["outcome"] == COLLAPSED
    assert cell["alignment_cost"] > 20 * _cells(result, "relational")["env_01"][
        "alignment_cost"]
    assert cell["outcome"] != "ABSTAINED"


# ── competing explanations ──────────────────────────────────────────────

def test_no_rival_explains_the_result_as_well(result):
    summary = result["grammars"]["relational"]["expected_transfer_summary"]
    rivals = result["competing_hypotheses"]
    best = max(row["expected_transfer_summary"].get("mean", 0.0)
               for row in rivals.values())
    assert summary["mean"] - best >= MIN_ADVANTAGE_OVER_COMPETITORS


def test_every_rival_is_actually_fitted_and_transferred(result):
    rivals = result["competing_hypotheses"]
    assert len(rivals) == 10
    for name, row in rivals.items():
        assert row["discovery"]["f1"] >= 0.0, name
        assert set(row["per_environment"]) >= set(TRANSFER_EXPECTED), name


def test_the_session_metadata_trap_is_baited_and_fails_to_transfer(result):
    """It fits the discovery world well and carries none of it across."""
    row = result["competing_hypotheses"]["session_metadata"]
    assert row["discovery"]["lift"] > 0.2
    assert row["expected_transfer_summary"].get("mean", 0.0) == 0.0


def test_nearest_neighbour_retains_more_than_zero_and_that_is_explained(result):
    """A finding worth stating rather than a leak.

    Jaccard similarity over the LB-0 feature set is not zero across a complete
    vocabulary change, because that grammar contains vocabulary-free families —
    step counts, boundary crossings, single-identity. The crudest possible
    model therefore transfers partially, and the margin over it is what the
    acceptance gate actually tests.
    """
    row = result["competing_hypotheses"]["nearest_neighbour"]
    assert 0.0 < row["expected_transfer_summary"]["mean"] < 0.8


# ── invariance and falsification ────────────────────────────────────────

def test_the_candidate_is_invariant_to_every_renaming(result):
    battery = result["grammars"]["relational"]["invariance"]
    for name in ("alpha_rename_identities", "rename_tools",
                 "substitute_provider", "substitute_vocabulary",
                 "translate_timestamps", "perturb_irrelevant_fields"):
        assert battery["preserving"][name]["agreement"] == 1.0, name


def test_padding_breaks_the_alignment_not_the_candidate(result):
    """The measured reason the verdict is not SUPPORTED.

    Padding every trajectory with copies of an existing step type skews that
    step type's statistics, the induced roles move, and the candidate is
    evaluated through a mapping that no longer means what it did. The
    re-alignment cost says so directly, which is why it is reported per
    transform.
    """
    battery = result["grammars"]["relational"]["invariance"]
    padded = battery["preserving"]["pad_trace"]
    assert padded["agreement"] < 0.95
    assert padded["realignment_would_have_abstained"] is True


def test_destroying_the_relation_stops_the_candidate_firing(result):
    battery = result["grammars"]["relational"]["invariance"]
    assert battery["destructive_passes"] is True
    for name, row in battery["destructive"].items():
        assert row["extinction"] >= 0.8, name


def test_the_ungated_transform_is_still_measured(result):
    """Removed from the gate, not from the run."""
    battery = result["grammars"]["relational"]["invariance"]
    assert "drop_last_step" in battery["partially_destructive_ungated"]


def test_a_shuffled_label_candidate_transfers_nothing(result):
    check = next(c for c in result["falsification"]
                 if c["check"] == "label_shuffle")
    assert check["passed"]
    assert check["mean_retention"] <= 0.25


def test_the_alignment_step_is_load_bearing(result):
    check = next(c for c in result["falsification"]
                 if c["check"] == "role_model_shuffle")
    assert check["applicable"] is True
    assert check["passed"]
    assert check["mean_retention"] <= 0.5


def test_every_conjunct_is_load_bearing(result):
    check = next(c for c in result["falsification"]
                 if c["check"] == "literal_ablation")
    literals = result["grammars"]["relational"]["candidate"]["literals"]
    assert set(check["load_bearing"]) == set(literals)


def test_an_injected_confounder_moves_nothing(result):
    check = next(c for c in result["falsification"]
                 if c["check"] == "confounder_injection")
    assert check["prediction_drift"] <= 0.02


def test_the_over_approximation_probe_ran_and_is_scored(result):
    """The case built so the obvious candidate should fail."""
    check = next(c for c in result["falsification"]
                 if c["check"] == "over_approximation_probe")
    assert check["environment"] == "env_f2"
    assert "the_recovered_structure_is_not_a_strict_over_approximation" in {
        c["criterion"] for c in result["verdict"]["criteria"]}


def test_the_clean_sweep_flag_is_reported(result):
    check = next(c for c in result["falsification"]
                 if c["check"] == "suspicious_clean_sweep")
    assert isinstance(check["flag"], bool)


# ── replication ─────────────────────────────────────────────────────────

def test_three_seeds_recover_the_same_structure(result):
    replication = result["replication"]
    assert len(replication["per_seed"]) == 3
    assert replication["distinct_structures"] == 1
    assert replication["structure_stable"] is True
    for row in replication["per_seed"]:
        assert row["grammar"] == "relational"


def test_the_same_structure_does_not_mean_the_same_verdict(result):
    """The finding that a structure-hash-only replication check would hide.

    Every seed recovers a byte-identical candidate with identical retention,
    and the run still does not reach the same verdict on all of them, because
    the invariance criterion turns on a re-alignment cost that straddles its
    ceiling. Replication reports both, separately.
    """
    replication = result["replication"]
    assert replication["invariance_stable"] is False
    assert replication["invariance_passes_on"] < len(replication["per_seed"])
    low, high = replication["realignment_cost_range"]
    assert low < replication["realignment_ceiling"] < high


def test_per_seed_numbers_are_reported_not_only_averaged(result):
    for row in result["replication"]["per_seed"]:
        assert row["minimum_retention"] is not None
        assert row["per_environment"]


# ── provenance and authority ────────────────────────────────────────────

def test_the_candidate_travels_with_its_failure_modes(result):
    modes = result["grammars"]["relational"]["known_failure_modes"]
    assert modes
    environments = {mode.get("environment") for mode in modes}
    assert {"env_05", "env_06", "env_07", "env_08"} <= environments


def test_a_proposal_is_emitted_and_cannot_be_adopted(result):
    proposal = result["proposal"]
    assert proposal["status"] == "REVIEW_REQUIRED"
    assert proposal["production_authority"] == "none"
    assert proposal["evidence"]["replication"]["stable"] is True
    assert proposal["localisation"]["known_failure_modes"]


def test_authority_and_grammar_invariants_hold(result):
    assert result["authority"]["production_authority_reachable"] is False
    assert result["grammar_immutability"]["unchanged"] is True
    assert result["production_fingerprint"]["unchanged"] is True


def test_the_candidate_is_unchanged_by_the_whole_evaluation(result):
    for row in result["grammars"].values():
        assert row["structure_hash_before"] == row["structure_hash_after"]


# ── reproducibility and evidence ────────────────────────────────────────

def test_run_is_reproducible_from_seed():
    first = run(seed=91, persist=False, seeds=(91,))
    again = run(seed=91, persist=False, seeds=(91,))
    assert first["run_id"] == again["run_id"]
    assert first["evidence"]["chain"]["head"] == again["evidence"]["chain"]["head"]


def test_evidence_chain_seals_every_stage(result):
    chain = result["evidence"]["chain"]
    assert chain["verified"] is True
    assert chain["problems"] == []
    stages = [entry["stage"] for entry in result["evidence"]["stages"]]
    for grammar in ("surface", "typed", "relational"):
        assert f"grammar:{grammar}" in stages
    for stage in ("competing_hypotheses", "falsification", "replication",
                  "authority", "verdict"):
        assert stage in stages


def test_persisting_writes_the_required_artifacts():
    from pathlib import Path

    persisted = run(seed=SEED, persist=True)
    directory = Path(persisted["artifact_dir"])
    assert directory.parent.name == "lb3"
    for name in ("run_manifest.json", "dataset_manifest.json",
                 "environment_manifest.json", "role_models.json",
                 "candidates.json", "transfer_matrix.json",
                 "competing_hypotheses.json", "invariance_results.json",
                 "falsification_results.json", "replication.json",
                 "provenance.json", "report.md"):
        assert (directory / name).exists(), name
    manifest = json.loads((directory / "run_manifest.json").read_text())
    assert manifest["verdict"]["decision"] == persisted["verdict"]["decision"]


# ── reporting ───────────────────────────────────────────────────────────

def test_console_report_shows_the_whole_matrix(result):
    text = lb3_console_report(result)
    assert "LB-3 Cross-Environment Structural Transfer" in text
    for grammar in ("surface", "typed", "relational"):
        assert grammar in text
    for env_id in result["environments"]:
        assert env_id in text
    assert "Competing explanations" in text
    assert "the ALIGNMENT broke, not the candidate" in text
    assert "Production authority reachable:    NO" in text


def test_markdown_report_is_complete(result):
    text = lb3_markdown_report(result)
    assert "**RESULT: PARTIALLY_SUPPORTED**" in text
    for heading in ("## Environments", "## Transfer matrix",
                    "## Competing explanations", "## Falsification",
                    "## Replication", "## Authority",
                    "## Acceptance criteria"):
        assert heading in text
    assert "Known failure modes, measured" in text


def test_cli_runs(capsys):
    assert main(["--seed", "5", "--no-persist", "--seeds", "5"]) == 0
    assert "LB-3 Cross-Environment" in capsys.readouterr().out


def test_cli_reports_a_non_supported_verdict_as_a_failure(capsys):
    """`--require-supported` must not be satisfied by PARTIALLY_SUPPORTED."""
    code = main(["--seed", "42", "--no-persist", "--seeds", "42",
                 "--require-supported"])
    capsys.readouterr()
    assert code == 1
