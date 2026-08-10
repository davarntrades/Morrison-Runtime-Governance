"""The full LB-0 experiment, end to end, from one seed.

This is the test that would fail if the experiment stopped working. It runs the
real pipeline — no stubs, no shortcuts — and checks the acceptance criteria the
prototype README lists, plus reproducibility and evidence integrity.

It deliberately asserts on STRUCTURE and INVARIANTS rather than on exact metric
values. Pinning "held-out F1 == 1.0" would turn an experiment into a golden
file: a future improvement to the corpus that made the problem harder would
read as a regression. What must hold is that the gate is met, and that every
number in the report came from the run rather than from a constant.
"""

from __future__ import annotations

import json

import pytest

from living_boundary.evidence.report import console_report, markdown_report
from living_boundary.experiments import hidden_ground_truth as oracle
from living_boundary.run_lb0 import (
    MAX_HELD_OUT_FPR, MAX_SHUFFLE_CONTROL_MCC, MIN_F1_IMPROVEMENT,
    MIN_STABILITY_AGREEMENT, MIN_SUPPORTING_TRACES, main, run,
)

SEED = 42


@pytest.fixture(scope="module")
def result():
    return run(seed=SEED, stability_seeds=1, persist=False)


# ── the acceptance criteria, one test each ──────────────────────────────

def test_the_experiment_reaches_a_verdict(result):
    assert result["verdict"]["decision"] in ("SUPPORTED", "REJECTED",
                                             "INCONCLUSIVE")


def test_lb0_is_supported_by_the_evidence(result):
    """If this fails, read the criteria below: exactly one of them will say why."""
    failed = [c["criterion"] for c in result["verdict"]["criteria"]
              if not c["passed"]]
    assert result["verdict"]["decision"] == "SUPPORTED", (
        f"criteria that failed: {failed}")


def test_the_ontology_gap_is_detected_and_evidenced(result):
    gap = result["ontology_gap"]
    assert gap["detected"]
    assert gap["residual_unsafe"] > 0
    assert gap["signature_collisions"] > 0
    assert gap["supporting_trace_ids"]
    assert gap["status"] == "experimental"


def test_a_candidate_primitive_is_produced_with_provenance(result):
    candidate = result["candidate_primitive"]
    assert candidate is not None
    assert candidate["literals"]
    assert candidate["supporting_traces"] >= MIN_SUPPORTING_TRACES
    assert candidate["source_evidence"]
    assert candidate["hypothesis"] and candidate["falsifiable_prediction"]
    assert candidate["production_authority"] == "none"


def test_the_candidate_does_not_lean_on_session_metadata(result):
    candidate = result["candidate_primitive"]
    assert not candidate["discovery_metrics"]["uses_surface_features"], (
        "the candidate used {}, which is session metadata with no causal "
        "relationship to the outcome".format(
            candidate["discovery_metrics"]["surface_literals"]))


def test_every_condition_survived_targeted_falsification(result):
    falsification = result["falsification"]
    assert falsification["passed"], falsification["failures"]
    assert falsification["cases_generated"] > 50
    assert not falsification["untestable_literals"]
    for name, stats in falsification["per_literal"].items():
        assert stats["cases"] >= falsification["criteria"]["min_cases_per_literal"], name


def test_held_out_beats_both_baselines_by_the_declared_margin(result):
    assert result["held_out"]["f1_delta"] >= MIN_F1_IMPROVEMENT
    assert result["held_out_strengthened"]["f1_delta"] > 0
    assert result["held_out"]["candidate"]["false_positive_rate"] <= MAX_HELD_OUT_FPR
    assert result["held_out"]["discordance"]["b_corrects_a"] > 0


def test_the_blind_spot_is_recovered_without_overblocking(result):
    recovery = result["residual_recovery"]
    assert recovery["recovered_unsafe"] > 0
    assert recovery["recovery_rate"] > 0.9
    assert recovery["false_positive_rate_on_uncovered_safe"] <= MAX_HELD_OUT_FPR


def test_the_memorisation_control_finds_nothing(result):
    control = result["controls"]["label_shuffle"]
    assert control["held_out_mcc"] <= MAX_SHUFFLE_CONTROL_MCC


def test_the_structure_is_stable_across_seeds(result):
    stability = result["stability"]
    assert stability["seeds_compared"] >= 1
    assert stability["mean_prediction_agreement"] >= MIN_STABILITY_AGREEMENT


def test_production_authority_stayed_unreachable(result):
    assert result["authority"]["production_authority_reachable"] is False
    assert result["production_fingerprint"]["unchanged"] is True


# ── reproducibility and evidence ────────────────────────────────────────

def test_run_is_reproducible_from_seed():
    """Same seed, same everything — including the sealed evidence head."""
    first = run(seed=99, stability_seeds=0, persist=False)
    again = run(seed=99, stability_seeds=0, persist=False)

    assert first["dataset"]["dataset_hash"] == again["dataset"]["dataset_hash"]
    assert first["run_id"] == again["run_id"]
    assert first["candidate_primitive"]["structure_hash"] == \
        again["candidate_primitive"]["structure_hash"]
    assert first["held_out"]["candidate"] == again["held_out"]["candidate"]
    assert first["verdict"]["decision"] == again["verdict"]["decision"]
    assert first["evidence"]["chain"]["head"] == again["evidence"]["chain"]["head"], (
        "the evidence chain head must be reproducible from the seed; if it is "
        "not, timestamps have leaked into the sealed records")


def test_a_different_seed_produces_a_different_corpus_and_the_same_structure():
    first = run(seed=101, stability_seeds=0, persist=False)
    other = run(seed=202, stability_seeds=0, persist=False)
    assert first["dataset"]["dataset_hash"] != other["dataset"]["dataset_hash"]
    assert first["verdict"]["decision"] == other["verdict"]["decision"]


def test_evidence_chain_is_sealed_and_verifies(result):
    chain = result["evidence"]["chain"]
    assert chain["verified"] is True
    assert chain["problems"] == []
    assert chain["records"] >= 8
    stages = [entry["stage"] for entry in result["evidence"]["stages"]]
    for required in ("dataset", "baseline", "ontology_gap", "structure_search",
                     "falsification", "held_out", "controls", "authority",
                     "verdict"):
        assert required in stages, required


def test_evidence_records_every_field_the_blueprint_requires(result):
    """Blueprint §17 / prototype README §10."""
    for field in ("run_id", "seed", "dataset", "ontology", "code_provenance",
                  "ontology_gap", "candidate_primitive", "falsification",
                  "held_out", "verdict", "generated_at", "evidence",
                  "split_integrity", "refinement_rounds"):
        assert field in result, field
    assert result["dataset"]["dataset_version"]
    assert result["ontology"]["ontology_version"]
    assert "commit" in result["code_provenance"]


def test_the_harness_disclosure_is_present_but_was_never_an_input(result):
    """The rule appears in the human-readable record, for audit.

    It is written after the verdict, is read by nothing, and the isolation
    tests prove the discovery layer could not have reached it.
    """
    disclosure = result["harness_disclosure"]
    assert disclosure["hidden_rule_id"] == oracle.HIDDEN_RULE_ID
    assert disclosure["oracle_version"] == oracle.ORACLE_VERSION
    search_inputs = json.dumps(result["search"], sort_keys=True)
    assert oracle.HIDDEN_RULE_STATEMENT not in search_inputs


def test_persisting_writes_a_complete_evidence_package(tmp_path):
    persisted = run(seed=SEED, stability_seeds=0, persist=True)
    from pathlib import Path
    directory = Path(persisted["artifact_dir"])
    for name in ("run_manifest.json", "dataset_manifest.json",
                 "baseline_metrics.json", "detected_gaps.json",
                 "candidate_primitives.json", "falsification.json",
                 "held_out_metrics.json", "controls.json", "authority.json",
                 "provenance.json", "evidence_chain.jsonl", "report.md"):
        assert (directory / name).exists(), name
    manifest = json.loads((directory / "run_manifest.json").read_text())
    assert manifest["verdict"]["decision"] == persisted["verdict"]["decision"]


# ── reporting ───────────────────────────────────────────────────────────

def test_console_report_states_the_result_without_narrative(result):
    text = console_report(result)
    assert "LB-0 Living Boundary Experiment" in text
    assert "Ontology gap detected:" in text
    assert "Falsification:" in text
    assert "Production authority reachable:  NO" in text
    assert "Verdict:" in text
    for criterion in result["verdict"]["criteria"]:
        assert criterion["criterion"] in text, (
            "every criterion must appear in the report, passed or failed")


def test_markdown_report_is_complete(result):
    text = markdown_report(result)
    assert "**RESULT:" in text
    assert "## Did the existing ontology miss the failure?" in text
    assert "## Was production authority reachable?" in text
    assert "## Acceptance criteria" in text
    assert oracle.HIDDEN_RULE_STATEMENT in text, (
        "the audit record must disclose the ground truth a reviewer needs")


def test_cli_runs_and_reports(capsys):
    assert main(["--seed", "7", "--no-persist", "--stability-seeds", "0"]) == 0
    assert "LB-0 Living Boundary Experiment" in capsys.readouterr().out


def test_cli_json_mode_emits_machine_readable_output(capsys):
    assert main(["--seed", "7", "--no-persist", "--stability-seeds", "0",
                 "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"]["decision"]


def test_cli_require_supported_flag_gates_the_exit_code(capsys):
    code = main(["--seed", "42", "--no-persist", "--stability-seeds", "1",
                 "--require-supported"])
    capsys.readouterr()
    assert code == 0
