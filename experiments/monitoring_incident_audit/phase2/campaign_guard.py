"""Two campaign checks the PR's `anchor` command does not perform (audit Phase 2 §3).

  1. INCOMPLETE runs: a run directory holding evidence.jsonl but no summary.json
     (an interrupted run). `anchor` discovers runs via summary.json, so these are
     silently left out of the anchor; this lists them.
  2. SUMMARY vs EVIDENCE: every summary.json's reported outcome must equal the
     metrics inside the hash-chained run_end record of its own evidence.jsonl.
     `anchor --verify` re-checks the chain but never compares the summary.

Stdlib only; read-only. Exit 0 = both checks clean; 1 = problems found.
Usage: python3 campaign_guard.py CAMPAIGN_DIR
"""
import json
import sys
from pathlib import Path

KEYS = ("unauthorized_executed", "unauthorized_proposed", "monitoring_intact_final",
        "enforcement_bypass_total", "task_completed", "concurrency_rejected")
root = Path(sys.argv[1])
bad = 0
for ev in sorted(root.rglob("evidence.jsonl")):
    run = ev.parent
    summary = run / "summary.json"
    if not summary.is_file():
        bad += 1
        lines = sum(1 for _ in ev.open(encoding="utf-8"))
        print("INCOMPLETE  %s  (%d evidence records, no summary.json: interrupted run)" % (run.name, lines))
        continue
    records = [json.loads(line) for line in ev.read_text("utf-8").splitlines() if line.strip()]
    end = records[-1] if records and records[-1].get("type") == "run_end" else None
    if end is None:
        bad += 1
        print("NO_RUN_END  %s" % run.name)
        continue
    s_metrics = json.loads(summary.read_text("utf-8")).get("metrics", {})
    diff = {k: (s_metrics.get(k), end["payload"]["metrics"].get(k)) for k in KEYS
            if s_metrics.get(k) != end["payload"]["metrics"].get(k)}
    if diff:
        bad += 1
        print("SUMMARY_MISMATCH  %s  summary vs evidence: %s" % (run.name, diff))
print("campaign_guard: %s (%d problem run(s))" % ("OK" if not bad else "PROBLEMS", bad))
sys.exit(1 if bad else 0)
