"""Evidence-anchor generation and verification (final audit §4).

The anchor pins every run's run_id, evidence path, terminal hash, commit and
manifest hash, validates chains before anchoring, refuses to overwrite an
existing anchor, and verifies every run against it with a nonzero exit on any
integrity failure. These tests cover tampering, wrong terminal hashes, missing
logs, duplicate ids, and repeat-run preservation.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from experiments.monitoring_incident import anchoring as A
from experiments.monitoring_incident.cases import by_id
from experiments.monitoring_incident.cli import main as cli_main
from experiments.monitoring_incident.harness import RunConfig, run_episode
from experiments.monitoring_incident.proposers import ScriptedProposer

RUNS = [("C12-legit-digest", "hierarchical"), ("C05-profile-two-step", "global_only"),
        ("C03-overrides", "local_only")]


@pytest.fixture
def campaign(tmp_path):
    out = tmp_path / "campaign"
    out.mkdir()
    for cid, cond in RUNS:
        case = by_id(cid)
        run_episode(RunConfig(scenario=case.scenario, condition=cond, output_dir=out, case_id=cid),
                    ScriptedProposer(cid, case.steps))
    return out


def test_anchor_generates_and_verifies(campaign):
    built = A.build_anchor(campaign)
    assert built["ok"] and built["anchor"]["runs"] == len(RUNS)
    for row in built["anchor"]["rows"]:
        assert row["chain_valid"] and row["terminal_hash"] and row["commit"]
        assert row["manifest_sha256"].startswith("a054fcdb52fc")
    anchor_path = campaign / A.DEFAULT_ANCHOR_NAME
    A.write_anchor(built["anchor"], anchor_path)
    result = A.verify_against_anchor(campaign, A.load_anchor(anchor_path))
    assert result["ok"] and result["checked"] == len(RUNS)


def test_anchor_refuses_to_overwrite_without_force(campaign):
    built = A.build_anchor(campaign)
    path = campaign / A.DEFAULT_ANCHOR_NAME
    A.write_anchor(built["anchor"], path)
    with pytest.raises(FileExistsError):
        A.write_anchor(built["anchor"], path)
    A.write_anchor(built["anchor"], path, force=True)       # explicit force is allowed


def test_anchor_does_not_rewrite_evidence(campaign):
    before = {p: Path(p).read_bytes() for p in
              map(str, campaign.rglob("evidence.jsonl"))}
    A.build_anchor(campaign)
    A.write_anchor(A.build_anchor(campaign)["anchor"], campaign / A.DEFAULT_ANCHOR_NAME)
    A.verify_against_anchor(campaign, A.load_anchor(campaign / A.DEFAULT_ANCHOR_NAME))
    after = {p: Path(p).read_bytes() for p in before}
    assert after == before, "anchoring/verification modified evidence files"


def test_verify_detects_tampering(campaign):
    path = campaign / A.DEFAULT_ANCHOR_NAME
    A.write_anchor(A.build_anchor(campaign)["anchor"], path)
    ev = next(campaign.rglob("evidence.jsonl"))
    lines = ev.read_text().splitlines()
    rec = json.loads(lines[1]); rec["payload"]["tampered"] = True
    lines[1] = json.dumps(rec); ev.write_text("\n".join(lines) + "\n")
    result = A.verify_against_anchor(campaign, A.load_anchor(path))
    assert not result["ok"]
    assert any(p["kind"] == "verification_failed" for p in result["problems"])


def test_verify_detects_wrong_terminal_hash(campaign):
    anchor = A.build_anchor(campaign)["anchor"]
    anchor["rows"][0]["terminal_hash"] = "deadbeef" * 8
    result = A.verify_against_anchor(campaign, anchor)
    assert not result["ok"]
    kinds = {p["kind"] for p in result["problems"]}
    assert "anchor_body_altered" in kinds or "verification_failed" in kinds


def test_verify_detects_missing_log(campaign):
    path = campaign / A.DEFAULT_ANCHOR_NAME
    A.write_anchor(A.build_anchor(campaign)["anchor"], path)
    ev = next(campaign.rglob("evidence.jsonl"))
    ev.unlink()
    result = A.verify_against_anchor(campaign, A.load_anchor(path))
    assert not result["ok"]
    assert any(p["kind"] == "missing_evidence" for p in result["problems"])


def test_scan_detects_duplicate_run_ids(campaign):
    run_dir = next(d for d in campaign.iterdir() if d.name.startswith("mi-"))
    shutil.copytree(run_dir, campaign / (run_dir.name + "-copy"))
    scan = A.scan_campaign(campaign)
    assert any(p["kind"] == "duplicate_run_id" for p in scan["problems"])
    assert not A.build_anchor(campaign)["ok"]


def test_build_fails_on_terminal_hash_disagreement(campaign):
    # corrupt a summary's recorded terminal hash → build must report it, not write
    summ = next(campaign.rglob("summary.json"))
    j = json.loads(summ.read_text()); j["evidence"]["terminal_hash"] = "0" * 64
    summ.write_text(json.dumps(j))
    built = A.build_anchor(campaign)
    assert not built["ok"]
    assert any(p["kind"] == "terminal_hash_mismatch" for p in built["problems"])


def test_cli_anchor_generate_then_verify_exit_codes(campaign):
    path = campaign / A.DEFAULT_ANCHOR_NAME
    assert cli_main(["anchor", "--output-dir", str(campaign)]) == 0
    assert path.exists()
    assert cli_main(["anchor", "--output-dir", str(campaign), "--verify"]) == 0
    # re-generate without --force is rejected (nonzero), anchor preserved
    assert cli_main(["anchor", "--output-dir", str(campaign)]) == 2
    # tamper → verify exits nonzero
    ev = next(campaign.rglob("evidence.jsonl"))
    ev.write_text(ev.read_text() + '{"junk": true}\n')
    assert cli_main(["anchor", "--output-dir", str(campaign), "--verify"]) == 1


def test_repeat_runs_each_have_a_distinct_anchor_row(tmp_path):
    """Five preserved repetitions each anchor independently."""
    from experiments.monitoring_incident.proposers import Proposer, ProposalBatch

    class Mock(Proposer):
        provider = "mock-live"
        def __init__(self, v):
            super().__init__(model="m", config={"tool_protocol": "native"}); self._v = v; self._d = False
        def start(self, t): self._d = False
        def propose(self, fb):
            if self._d: return ProposalBatch(stop_reason="done")
            self._d = True
            return ProposalBatch(calls=[{"id": "c", "tool": "write_file",
                                         "args": {"path": "config/notifications.json",
                                                  "content": '{"v":"%s"}' % self._v}}])
    out = tmp_path / "live"
    out.mkdir()
    for rep in range(5):
        run_episode(RunConfig(scenario="alert_suppression", condition="hierarchical", output_dir=out,
                              on_existing="error", repetition=rep, labels={"intent": "live"}),
                    Mock("rep%d" % rep))
    built = A.build_anchor(out)
    assert built["ok"] and built["anchor"]["runs"] == 5
    assert len({r["run_id"] for r in built["anchor"]["rows"]}) == 5
