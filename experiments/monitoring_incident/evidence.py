"""Decision-bound, hash-chained evidence.

One JSONL file per run. Every record carries the previous record's hash, and
`verify_records` checks more than the chain: every executed action must be
preceded by an ALLOW decision for the same action hash in the same step, no
decision may execute twice, and no effect may appear in a step where nothing
was executed.

Tamper-EVIDENT against a retained terminal hash (written to summary.json and
printed by the CLI), not tamper-proof: whoever can rewrite both the log and
the retained hash can rewrite history. The records are not signed.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from pathlib import Path

SCHEMA = "monitoring-incident-evidence/v1"
GENESIS = "0" * 64
RECORD_TYPES = (
    "run_start", "proposal", "oracle_label", "local_evaluation", "global_evaluation",
    "decision", "adversarial_hook", "external_change", "execution", "step_outcome",
    "concurrency_rejected", "report", "oracle_final", "run_end",
)


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=repr)


def record_hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "record_hash"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


class EvidenceLog:
    def __init__(self, path: Path, run_id: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.run_id = run_id
        self.records: list = []

    @property
    def terminal_hash(self) -> str:
        return self.records[-1]["record_hash"] if self.records else GENESIS

    def append(self, rtype: str, payload: dict, step=None) -> dict:
        if rtype not in RECORD_TYPES:
            raise ValueError("unknown evidence record type %r" % rtype)
        record = {"schema": SCHEMA, "run_id": self.run_id, "seq": len(self.records),
                  "type": rtype, "step": step,
                  "time_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                  "payload": json.loads(_canonical(payload)),
                  "prev_hash": self.terminal_hash}
        record["record_hash"] = record_hash(record)
        self.records.append(record)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(_canonical(record) + "\n")
        return record


def load(path) -> list:
    return [json.loads(line) for line in Path(path).read_text("utf-8").splitlines() if line.strip()]


def verify_records(records: list, terminal_hash=None) -> dict:
    problems = []
    prev = GENESIS
    run_ids = {r.get("run_id") for r in records}
    if len(run_ids) > 1:
        problems.append("multiple run ids in one log")
    allow = {}            # (step, decision_id) -> action_hash
    used = set()
    external_steps = set()
    for i, r in enumerate(records):
        if r.get("schema") != SCHEMA:
            problems.append("record %d: wrong schema" % i)
        if r.get("seq") != i:
            problems.append("record %d: seq %r" % (i, r.get("seq")))
        if r.get("prev_hash") != prev:
            problems.append("record %d: chain broken" % i)
        if record_hash(r) != r.get("record_hash"):
            problems.append("record %d: hash mismatch (altered)" % i)
        prev = r.get("record_hash")
        p = r.get("payload") or {}
        if r.get("type") == "decision" and p.get("verdict") == "ALLOW":
            allow[(r.get("step"), p.get("decision_id"))] = p.get("action_hash")
        if r.get("type") == "execution" and p.get("executed"):
            key = (r.get("step"), p.get("decision_id"))
            if key not in allow:
                problems.append("record %d: execution without a prior ALLOW decision in step %s"
                                % (i, r.get("step")))
            elif allow[key] != p.get("action_hash"):
                problems.append("record %d: executed action hash differs from the ALLOW decision" % i)
            if p.get("decision_id") in used:
                problems.append("record %d: decision executed twice" % i)
            used.add(p.get("decision_id"))
        if r.get("type") == "external_change":
            external_steps.add(r.get("step"))
        if r.get("type") == "step_outcome" and not p.get("executed") \
                and p.get("state_before") != p.get("state_after") \
                and not (p.get("external_change") and r.get("step") in external_steps):
            problems.append("record %d: state changed in step %s with no execution"
                            % (i, r.get("step")))
    if records and records[0].get("type") != "run_start":
        problems.append("log does not begin with run_start")
    if records and records[-1].get("type") != "run_end":
        problems.append("log does not end with run_end (truncated?)")
    if terminal_hash is not None and prev != terminal_hash:
        problems.append("terminal hash does not match the retained anchor")
    return {"valid": not problems, "problems": problems, "records": len(records),
            "terminal_hash": prev}
