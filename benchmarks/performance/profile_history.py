"""Diagnostic for the history-dependent latency (independent review, finding E).

MEASUREMENT ONLY: wraps the continuity store and the Ω engine from the
outside to count work per decision, and runs cProfile; no kernel code is
changed. It turns two claims in BENCHMARK_HANDOFF.md section 7 from
code-inspection into observation:

  * the trajectory engine is handed the WHOLE governed prefix on every
    decision (states evaluated per decision grows with history), and
  * the ledger is re-read from the store many times per decision
    (`store.entries` calls per decision).

    python -m benchmarks.performance.profile_history --out DIR [--histories 0,8,32,64,128]
"""

from __future__ import annotations

import argparse
import cProfile
import io
import pstats
import time

from benchmarks.performance.common import Deployment, environment, set_results_dir, write_json


class CountingStore:
    """Delegating wrapper that counts `entries()` calls and rows returned."""

    def __init__(self, inner) -> None:
        self.inner, self.entries_calls, self.rows_read = inner, 0, 0

    def entries(self, key):
        rows = self.inner.entries(key)
        self.entries_calls += 1
        self.rows_read += len(rows)
        return rows

    def __getattr__(self, name):
        return getattr(self.inner, name)


def measure(history: int, samples: int = 20) -> dict:
    dep = Deployment()
    dep.principals = ["a"]
    store = CountingStore(dep.store)
    dep.store = store
    k = dep.kernel("a", mediated=False)
    evaluated = []
    original = k.layer.evaluate_trajectory

    def counting(traj):
        evaluated.append(len(traj.states))
        return original(traj)
    k.layer.evaluate_trajectory = counting
    call = {"tool": "read_doc", "args": {"id": "pub"}}
    for i in range(history):
        d = k.authorize({"tool": "read_doc", "args": {"id": f"pub-{i}"}})
        k.execute(d, lambda req: "ok")
    store.entries_calls = store.rows_read = 0
    evaluated.clear()
    t = []
    for _ in range(samples):
        t0 = time.perf_counter_ns()
        d = k.authorize(call, reserve=False)
        t.append(time.perf_counter_ns() - t0)
    calls, rows, states = store.entries_calls, store.rows_read, list(evaluated)
    prof = cProfile.Profile()
    prof.enable()
    for _ in range(5):
        k.authorize(call, reserve=False)
    prof.disable()
    buf = io.StringIO()
    pstats.Stats(prof, stream=buf).sort_stats("cumulative").print_stats(12)
    t.sort()
    return {"history": history, "samples": samples,
            "authorize_p50_ms": t[len(t) // 2] / 1e6,
            "store_entries_calls_per_decision": calls / samples,
            "ledger_rows_read_per_decision": rows / samples,
            "trajectory_evaluations_per_decision": len(states) / samples,
            "states_per_trajectory_evaluation": (sum(states) / len(states)) if states else 0,
            "verdict": d.verdict,
            "cprofile_top_cumulative": buf.getvalue().splitlines()[:40]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--histories", default="0,8,32,64,128")
    a = ap.parse_args(argv)
    set_results_dir(a.out)
    rows = [measure(int(h)) for h in a.histories.split(",")]
    for r in rows:
        print({k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items()
               if k != "cprofile_top_cumulative"})
    write_json("profile-history.json", {"environment": environment(), "label":
               "diagnostic, preview decisions (reserve=False), not a latency benchmark",
               "rows": rows})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
