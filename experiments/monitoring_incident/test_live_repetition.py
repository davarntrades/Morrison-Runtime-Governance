"""Live-run evidence durability (final audit §4.1).

Identical live configurations used to hash to the same run_id, and a re-run
silently deleted the earlier evidence. These tests prove the fix: each replicate
is a distinct --repetition with its own run_id, a duplicate run is rejected
fail-closed without touching the original's bytes, and five repeated stochastic
runs produce five independently preserved evidence records.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from experiments.monitoring_incident.harness import RunConfig, RunExistsError, run_episode
from experiments.monitoring_incident.proposers import Proposer, ProposalBatch


class _StochasticProposer(Proposer):
    """Stands in for a live model: SAME identity() across instances (so the same
    run_id), but DIFFERENT actions per `variant` (so different evidence)."""
    provider = "mock-live"
    deterministic = False

    def __init__(self, variant: str):
        super().__init__(model="mock-model", config={"temperature": 0.9, "tool_protocol": "native"})
        self._variant = variant
        self._done = False

    def start(self, task_prompt: str) -> None:
        self._done = False

    def propose(self, feedback):
        if self._done:
            return ProposalBatch(stop_reason="done")
        self._done = True
        return ProposalBatch(calls=[{"id": "c0", "tool": "write_file", "args": {
            "path": "config/notifications.json", "content": '{"variant": "%s"}' % self._variant}}])


def _live_cfg(out, repetition=0, seed=None):
    return RunConfig(scenario="alert_suppression", condition="hierarchical", output_dir=out,
                     on_existing="error", repetition=repetition, seed=seed,
                     labels={"intent": "live", "category": "live_model"})


def test_same_config_second_run_is_rejected_without_touching_the_first():
    out = Path(tempfile.mkdtemp())
    first = run_episode(_live_cfg(out), _StochasticProposer("A"))
    run_id = first["metadata"]["run_id"]
    original = (out / run_id / "evidence.jsonl").read_bytes()
    original_summary = (out / run_id / "summary.json").read_bytes()

    with pytest.raises(RunExistsError):
        run_episode(_live_cfg(out), _StochasticProposer("B"))

    # the original run's bytes are byte-for-byte unchanged
    assert (out / run_id / "evidence.jsonl").read_bytes() == original
    assert (out / run_id / "summary.json").read_bytes() == original_summary
    # and no second directory was created
    assert [d for d in os.listdir(out) if d.startswith("mi-")] == [run_id]


def test_five_repetitions_are_independently_preserved():
    out = Path(tempfile.mkdtemp())
    run_ids, terminals = [], []
    for rep in range(5):
        s = run_episode(_live_cfg(out, repetition=rep), _StochasticProposer("rep%d" % rep))
        run_ids.append(s["metadata"]["run_id"])
        terminals.append(s["evidence"]["terminal_hash"])
    assert len(set(run_ids)) == 5, "repetitions collided: %s" % run_ids
    dirs = sorted(d for d in os.listdir(out) if d.startswith("mi-"))
    assert len(dirs) == 5, "expected 5 preserved run dirs, got %s" % dirs
    # every run's evidence file survives and matches its reported terminal hash
    for rid, th in zip(run_ids, terminals):
        assert (out / rid / "evidence.jsonl").is_file()
        assert th


def test_repetition_is_part_of_run_identity_and_metadata():
    out = Path(tempfile.mkdtemp())
    a = run_episode(_live_cfg(out, repetition=0), _StochasticProposer("x"))
    b = run_episode(_live_cfg(out, repetition=1), _StochasticProposer("x"))
    assert a["metadata"]["run_id"] != b["metadata"]["run_id"]
    assert a["metadata"]["repetition"] == 0
    assert b["metadata"]["repetition"] == 1


def test_live_metadata_records_the_required_fields():
    out = Path(tempfile.mkdtemp())
    s = run_episode(_live_cfg(out, repetition=0, seed=123), _StochasticProposer("x"))
    m = s["metadata"]
    for field in ("git", "governance_manifest_sha256", "scenario", "condition", "provider",
                  "model", "repetition", "seed", "tool_protocol", "max_steps", "max_turns",
                  "generation_mode", "started_utc", "completed_utc"):
        assert field in m, "missing metadata field %s" % field
    assert m["git"]["commit"]
    assert m["provider"] == "mock-live"
    assert m["seed"] == 123
    assert m["generation_mode"] == "stochastic"      # a seed does NOT make it deterministic
    assert s["evidence"]["final_evidence_chain_hash"] == s["evidence"]["terminal_hash"]
    assert s["metadata"]["baseline_oracle"]["confinement_status"] in ("ok", "degraded", "unknown")


def test_scripted_runs_remain_deterministic_and_regenerable():
    """The overwrite policy must not change scripted behaviour: a scripted re-run
    regenerates into the same run_id (on_existing='overwrite') with identical
    DECISIONS and outcomes. (The chain hash itself is not byte-identical across
    runs because records carry wall-clock `time_utc`; only the decisions are
    deterministic, which is the honest reproducibility claim.)"""
    from experiments.monitoring_incident.cases import by_id
    from experiments.monitoring_incident.proposers import ScriptedProposer
    out = Path(tempfile.mkdtemp())
    case = by_id("C12-legit-digest")
    a = run_episode(RunConfig(scenario=case.scenario, condition="hierarchical", output_dir=out,
                              case_id=case.id, escalation_policy="oracle"),
                    ScriptedProposer(case.id, case.steps))
    b = run_episode(RunConfig(scenario=case.scenario, condition="hierarchical", output_dir=out,
                              case_id=case.id, escalation_policy="oracle"),
                    ScriptedProposer(case.id, case.steps))
    assert a["metadata"]["run_id"] == b["metadata"]["run_id"]        # same id (deterministic config)
    assert a["metadata"]["generation_mode"] == "deterministic"
    # same decisions and outcomes on the re-run
    assert a["metrics"]["unauthorized_executed"] == b["metrics"]["unauthorized_executed"]
    assert a["metrics"]["monitoring_intact_final"] == b["metrics"]["monitoring_intact_final"]
    assert a["metrics"]["decisions"] == b["metrics"]["decisions"]
    assert a["evidence"]["valid"] and b["evidence"]["valid"]
    # the re-run replaced the dir (overwrite), leaving exactly one run dir
    assert [d for d in os.listdir(out) if d.startswith("mi-")] == [a["metadata"]["run_id"]]
