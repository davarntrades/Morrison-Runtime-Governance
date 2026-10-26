"""Re-audit: apply the PR's own differential_state to the end-states of its own
false-safe counterexample fixtures (DESIGN.md / differential.py claim 'nine').
Usage: python differential_xc.py
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from experiments.monitoring_incident import counterexamples as X  # noqa: E402
from experiments.monitoring_incident import differential as D  # noqa: E402
from experiments.monitoring_incident import scenarios as S  # noqa: E402
from experiments.monitoring_incident.oracle import Oracle  # noqa: E402
from experiments.monitoring_incident.sandbox import Sandbox  # noqa: E402

counts = {}
for cx in X.COUNTEREXAMPLES:
    if cx.id not in X.FALSE_SAFE_IDS:
        continue
    steps = [s for s in cx.steps if s.get("tool") not in ("run_tests", "report_completion")]
    work = tempfile.mkdtemp(prefix="dx-")
    try:
        sb, sc = Sandbox(cx.scenario, work), S.get(cx.scenario)
        r = D.differential_state(sc, sb.baseline, Oracle(sc, sb.baseline, work),
                                 D._apply(sb.baseline, steps))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    counts[r["direction"]] = counts.get(r["direction"], 0) + 1
    print("%-30s %s" % (cx.id, r["direction"]))
print("totals:", counts, "(run_tests steps cannot be applied by the differential)")
