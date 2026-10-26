"""Evidence-anchor generation and verification for a Phase 2 campaign.

An anchor is an independently inspectable manifest that pins, for every run in a
campaign directory, its run id, evidence path, final chain hash, commit SHA and
governance-manifest hash. It is READ-ONLY with respect to the evidence: building
or verifying an anchor never rewrites an evidence file.

TAMPER MODEL (read this). An anchor stored beside its evidence does NOT by itself
guarantee tamper resistance: an actor who can rewrite an `evidence.jsonl` can
also rewrite the anchor next to it, and the per-episode decision HMAC key is held
in memory and cannot be checked offline. The anchor is tamper-EVIDENT only to the
extent its contents are pinned somewhere the evidence writer cannot reach — e.g.
committed to git, or its own sha recorded off-machine (`shasum -a 256`). Within a
campaign directory it detects accidental corruption, truncation, duplication and
missing logs, and lets an independent party re-verify every chain against a fixed
terminal hash; it is not a cryptographic proof of non-tampering.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from pathlib import Path

from experiments.monitoring_incident import evidence as E

ANCHOR_SCHEMA = "monitoring-incident-anchor/v1"
DEFAULT_ANCHOR_NAME = "EVIDENCE_ANCHOR.json"
TAMPER_NOTE = (
    "An anchor stored beside its evidence does not independently guarantee tamper "
    "resistance: whoever can rewrite an evidence file can rewrite this anchor too, "
    "and decision HMAC keys are not verifiable offline. Pin anchor_sha256 off-machine "
    "(or commit this file to git) for an external anchor; within the directory this "
    "detects corruption, truncation, duplication and missing logs only.")


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=repr)


def scan_campaign(campaign_dir) -> dict:
    """Find every run directory (one holding summary.json + evidence.jsonl).

    Returns {"runs": {run_id: {...}}, "problems": [...]}. Problems cover missing
    evidence/summary, malformed summaries, duplicate run ids, and a dir name that
    does not match the run id recorded inside.
    """
    root = Path(campaign_dir)
    runs: dict = {}
    problems: list = []
    if not root.is_dir():
        return {"runs": {}, "problems": [{"kind": "missing_campaign_dir", "path": str(root)}]}
    for summary_path in sorted(root.rglob("summary.json")):
        run_dir = summary_path.parent
        evidence_path = run_dir / "evidence.jsonl"
        try:
            summary = json.loads(summary_path.read_text("utf-8"))
            run_id = summary["metadata"]["run_id"]
        except (ValueError, OSError, KeyError, TypeError) as e:
            problems.append({"kind": "malformed_summary", "path": str(summary_path), "error": str(e)})
            continue
        if not evidence_path.is_file():
            problems.append({"kind": "missing_evidence", "run_id": run_id, "path": str(evidence_path)})
            continue
        if run_dir.name != run_id:
            problems.append({"kind": "run_id_dir_mismatch", "run_id": run_id, "dir": run_dir.name})
        if run_id in runs:
            problems.append({"kind": "duplicate_run_id", "run_id": run_id,
                             "paths": [runs[run_id]["run_dir"], str(run_dir)]})
            continue
        runs[run_id] = {"run_dir": str(run_dir), "summary_path": str(summary_path),
                        "evidence_path": str(evidence_path),
                        "evidence_rel": str(evidence_path.relative_to(root)),
                        "summary": summary}
    return {"runs": runs, "problems": problems}


def _row_for(run_id: str, entry: dict, root: Path) -> dict:
    """Validate one run's chain and return its anchor row (never writes)."""
    problems = []
    try:
        records = E.load(entry["evidence_path"])
    except (OSError, ValueError) as e:
        return {"run_id": run_id, "error": "unreadable_evidence: %s" % e, "chain_valid": False}, \
            [{"kind": "unreadable_evidence", "run_id": run_id, "error": str(e)}]
    check = E.verify_records(records)
    if not check["valid"]:
        problems.append({"kind": "invalid_chain", "run_id": run_id, "detail": check["problems"][:3]})
    summary = entry["summary"]
    meta = summary.get("metadata", {})
    recorded_terminal = (summary.get("evidence", {}) or {}).get("terminal_hash")
    if recorded_terminal != check["terminal_hash"]:
        problems.append({"kind": "terminal_hash_mismatch", "run_id": run_id,
                         "summary": recorded_terminal, "recomputed": check["terminal_hash"]})
    row = {"run_id": run_id, "evidence_path": entry["evidence_rel"],
           "terminal_hash": check["terminal_hash"], "records": check["records"],
           "chain_valid": check["valid"] and not problems,
           "commit": (meta.get("git") or {}).get("commit"),
           "manifest_sha256": meta.get("governance_manifest_sha256"),
           "scenario": meta.get("scenario"), "condition": meta.get("condition"),
           "provider": meta.get("provider"), "model": meta.get("model"),
           "repetition": meta.get("repetition"), "generation_mode": meta.get("generation_mode"),
           "unauthorized_executed": (summary.get("metrics") or {}).get("unauthorized_executed"),
           "monitoring_intact_final": (summary.get("metrics") or {}).get("monitoring_intact_final")}
    return row, problems


def build_anchor(campaign_dir) -> dict:
    """Validate every run and build the anchor. Does not write anything.

    Returns {"anchor": {...}|None, "problems": [...], "ok": bool}. `ok` is False
    if any run is missing, duplicated, malformed, has an invalid chain, or a
    terminal hash that disagrees with its summary.
    """
    root = Path(campaign_dir)
    scan = scan_campaign(root)
    problems = list(scan["problems"])
    rows = []
    for run_id in sorted(scan["runs"]):
        row, row_problems = _row_for(run_id, scan["runs"][run_id], root)
        rows.append(row)
        problems.extend(row_problems)
    if not rows and not problems:
        problems.append({"kind": "no_runs", "path": str(root)})
    anchor = {"schema": ANCHOR_SCHEMA, "campaign_dir": str(root),
              "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
              "runs": len(rows), "note": TAMPER_NOTE, "rows": rows}
    # A self-digest over the rows, so a verifier can confirm the anchor's own body
    # was not edited after the sha was pinned externally.
    anchor["anchor_sha256"] = hashlib.sha256(_canonical(rows).encode()).hexdigest()
    ok = not problems and all(r.get("chain_valid") for r in rows)
    return {"anchor": anchor, "problems": problems, "ok": ok}


def write_anchor(anchor: dict, anchor_path, force: bool = False) -> None:
    """Write the anchor JSON. Refuses to overwrite an existing file without force."""
    path = Path(anchor_path)
    if path.exists() and not force:
        raise FileExistsError(
            "anchor %s already exists; pass --force to overwrite it (the previous "
            "anchor is otherwise preserved)" % path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(anchor, indent=2, sort_keys=True) + "\n", "utf-8")


def verify_against_anchor(campaign_dir, anchor: dict) -> dict:
    """Re-verify every run against the anchor. Never writes.

    Checks: the anchor body matches its own `anchor_sha256`; every anchored run's
    evidence still exists, its chain re-verifies, and its recomputed terminal hash
    equals the anchored one; and no anchored run is missing or extra.
    Returns {"ok": bool, "problems": [...], "checked": n}.
    """
    root = Path(campaign_dir)
    problems = []
    rows = anchor.get("rows", [])
    expect_sha = hashlib.sha256(_canonical(rows).encode()).hexdigest()
    if anchor.get("anchor_sha256") != expect_sha:
        problems.append({"kind": "anchor_body_altered",
                         "recorded": anchor.get("anchor_sha256"), "recomputed": expect_sha})
    anchored_ids = {r["run_id"] for r in rows}
    present = scan_campaign(root)["runs"]
    for extra in sorted(set(present) - anchored_ids):
        problems.append({"kind": "run_not_in_anchor", "run_id": extra})
    for row in rows:
        run_id = row["run_id"]
        evidence = root / row["evidence_path"]
        if not evidence.is_file():
            problems.append({"kind": "missing_evidence", "run_id": run_id, "path": str(evidence)})
            continue
        try:
            records = E.load(evidence)
        except (OSError, ValueError) as e:
            problems.append({"kind": "unreadable_evidence", "run_id": run_id, "error": str(e)})
            continue
        check = E.verify_records(records, terminal_hash=row["terminal_hash"])
        if not check["valid"]:
            problems.append({"kind": "verification_failed", "run_id": run_id,
                             "detail": check["problems"][:3]})
    return {"ok": not problems, "problems": problems, "checked": len(rows)}


def load_anchor(anchor_path) -> dict:
    return json.loads(Path(anchor_path).read_text("utf-8"))
