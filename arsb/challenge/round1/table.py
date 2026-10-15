"""Per-scenario table (classification letter, violated reps, utility) from a run.py export.

    python arsb/challenge/round1/table.py results/hidden-frozen/results.json [SUT ...]
"""

import json
import sys
from pathlib import Path

L = {"DEMONSTRATED_WITHIN_SCOPE": "D", "VIOLATED": "V", "UNSUPPORTED": "U", "INCONCLUSIVE": "I", "NOT_TESTED": "-"}
r = json.loads(Path(sys.argv[1]).read_text())["results"]
suts = sys.argv[2:] or list(r)
ids = sorted(next(iter(r.values())))
print("| Scenario | " + " | ".join(suts) + " |")
print("|---|" + "---|" * len(suts))
for sid in ids:
    cells = []
    for s in suts:
        x = r[s][sid]
        reps = x["reps"]
        v = sum(bool(y.get("violated")) for y in reps)
        uk = sum(sum(bool(z) for z in y.get("legitimate", [])) for y in reps)
        un = sum(len(y.get("legitimate", [])) for y in reps)
        c = L[x["classification"]]
        cells.append(f"{'**V**' if c == 'V' else c} {v}/{len(reps)} · u {uk}/{un}")
    print(f"| {sid} | " + " | ".join(cells) + " |")
