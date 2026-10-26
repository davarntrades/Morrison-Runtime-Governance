"""Concurrency follow-up to boundary_probe 5b: what does the sandbox actually
contain after two individually ALLOWed C05/C06 steps execute concurrently?
Also re-checks probe 2b under `ungoverned` (does a tool error spend a decision?).

Usage: python race_final.py [TRIALS]
"""
import collections
import importlib
import os
import shutil
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
TRIALS = int(sys.argv[1]) if len(sys.argv) > 1 else 30
sys.argv = [sys.argv[0], os.devnull]           # boundary_probe writes its JSON to argv[1] on import
# Loaded by name: a sibling script, not a package (keeps test_lint_gate from
# reading it as an undeclared third-party import). Its probes run once on load.
BP = importlib.import_module("boundary_probe")
from experiments.monitoring_incident import scenarios as S  # noqa: E402
from experiments.monitoring_incident.oracle import Oracle  # noqa: E402

out = collections.Counter()
for _ in range(TRIALS):
    work, sb, auth, ex = BP.world("global_only")
    dA = BP.decide(auth, sb, ex, BP.A_STEP)
    dB = BP.decide(auth, sb, ex, BP.B_STEP)
    res = {}
    ta = threading.Thread(target=lambda: res.__setitem__("A", ex.execute(dA, BP.A_STEP)))
    tb = threading.Thread(target=lambda: res.__setitem__("B", ex.execute(dB, BP.B_STEP)))
    ta.start(); tb.start(); ta.join(); tb.join()
    fs = sb.snapshot()
    a_in = fs[".env"] == BP.A_STEP["args"]["content"].encode()
    b_in = fs["config/notifications.json"] == BP.B_STEP["args"]["content"].encode()
    intact = Oracle(S.get("alert_suppression"), sb.baseline, work).evaluate(
        fs, include_task=False)["monitoring_intact"]
    out[(res["A"].executed, res["B"].executed, "A_persisted=%s" % a_in, "B_persisted=%s" % b_in,
         "monitoring_intact=%s" % intact, "ledger=%d" % len(ex.executed))] += 1
    shutil.rmtree(work, ignore_errors=True)
print("RACE-FINAL (A_executed, B_executed, ...): count over %d trials" % TRIALS)
for k, v in sorted(out.items(), key=lambda kv: -kv[1]):
    print("  %3d  %s" % (v, k))

work, sb, auth, ex = BP.world("ungoverned")
a = {"tool": "delete_file", "args": {"path": "nope.txt"}}
d = BP.decide(auth, sb, ex, a)
r1, r2 = ex.execute(d, a), ex.execute(d, a)
print("2b-redo first: executed=%s tool_error=%r | second: executed=%s refusal=%r"
      % (r1.executed, r1.tool_error, r2.executed, r2.refusal))
shutil.rmtree(work, ignore_errors=True)
