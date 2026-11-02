"""Flatten the load results into one CSV row per (run, concurrency level)."""

from __future__ import annotations

import csv
import json

from benchmarks.performance.common import RESULTS

COLS = ["model", "mode", "session", "workers", "proposals", "wall_s", "throughput_per_s",
        "cpu_utilisation_pct", "rss_mb", "verdict_p50_us", "verdict_p95_us", "verdict_p99_us",
        "verdict_max_us", "outside_stages_p99_us", "commit_p99_us", "prohibited",
        "prohibited_block", "prohibited_escalate", "prohibited_permit", "blocking_rate_pct",
        "prohibited_executed", "legit_total", "legit_executed", "legit_blocked",
        "legit_escalated", "shared_committed", "shared_expected_if_live", "shared_outflow",
        "global_invariant_holds", "duplicate_commits", "effects_without_record",
        "evidence_chain_failures", "replay_executed", "policy_change_executed",
        "error_rate_pct"]


def row(s: dict) -> dict:
    v, p, lg, sh = s["verdict_latency"], s["prohibited"], s["legitimate"], s["shared_limit"]
    return {
        "model": s["model"], "mode": s["mode"], "session": s.get("session"),
        "workers": s["workers"], "proposals": s["proposals"], "wall_s": round(s["wall_s"], 3),
        "throughput_per_s": round(s["throughput_per_s"], 1),
        "cpu_utilisation_pct": round(s["cpu_utilisation_pct"] or 0, 1),
        "rss_mb": round(s["rss_mb"], 1),
        "verdict_p50_us": round(v.get("p50_us", 0), 1), "verdict_p95_us": round(v.get("p95_us", 0), 1),
        "verdict_p99_us": round(v.get("p99_us", 0), 1), "verdict_max_us": round(v.get("max_us", 0), 1),
        "outside_stages_p99_us": round(s["outside_kernel_stages_latency"].get("p99_us", 0), 1),
        "commit_p99_us": round(s["proposal_to_commit_latency"].get("p99_us", 0), 1),
        "prohibited": p["proposal_level_total"], "prohibited_block": p["block"],
        "prohibited_escalate": p["escalate"], "prohibited_permit": p["permit"],
        "blocking_rate_pct": round(p["blocking_rate_pct"], 2),
        "prohibited_executed": p["executed"],
        "legit_total": lg["total"], "legit_executed": lg["executed"],
        "legit_blocked": lg["blocked"], "legit_escalated": lg["escalated"],
        "shared_committed": sh["committed"], "shared_expected_if_live": sh["expected_commits_if_live"],
        "shared_outflow": sh["outflow"], "global_invariant_holds": sh["invariant_holds"],
        "duplicate_commits": s["duplicates"]["double_execute_commit_successes_gt1"]
        + s["duplicates"]["duplicate_decision_ids_in_resource"],
        "effects_without_record": s["consistency"]["effects_without_executed_record"],
        "evidence_chain_failures": s["consistency"]["evidence_chain_failures"],
        "replay_executed": s["special"]["replay_executed"],
        "policy_change_executed": s["special"]["policy_change_executed"],
        "error_rate_pct": round(s["error_rate_pct"], 3),
    }


def main() -> int:
    rows = []
    for f in sorted(RESULTS.glob("load-*.json")):
        if f.name.endswith("-raw.json"):
            continue
        rows += [row(s) for s in json.loads(f.read_text())["summaries"]]
    with open(RESULTS / "summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows -> {RESULTS / 'summary.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
