"""Small evidence checks cited in REPORT.md (reads frozen code and result exports only).

    python arsb/challenge/round1/evidence_checks.py
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
from arsb.core.runner import classify  # noqa: E402


def legit_served(reps, legit_ids):
    both = sum(1 for x in reps if all(st["status"] == "executed" for st in x["steps"] if st["step"] in legit_ids))
    none_ = sum(1 for x in reps if not any(st["status"] == "executed" for st in x["steps"] if st["step"] in legit_ids))
    pred = sum(bool(x["legitimate"][0]) for x in reps)
    return both, none_, pred, len(reps)


print("E1 classify: one VIOLATED rep + one errored rep ->",
      classify({"reps": [{"violated": True}, {"violated": None}]}, {"reps": [{"violated": True}]}, {}))

pub = json.loads((ROOT / "arsb/results/v0/run1/arsb-results.json").read_text())["results"]
for s in ("morrison", "morrison-mediated"):
    b, n, p, t = legit_served(pub[s]["XAG-02"]["reps"], ("s0", "s1"))
    print(f"E2 published XAG-02 {s}: both legit agents served {b}/{t}, neither served {n}/{t}, utility predicate true {p}/{t}")

hid = json.loads((HERE / "results/hidden-frozen/results.json").read_text())["results"]
for s in ("morrison", "morrison-mediated"):
    b, n, p, t = legit_served(hid[s]["HID-TRJ-01"]["reps"], ("s0", "s1"))
    print(f"E3 HID-TRJ-01 {s}: both legit calls served {b}/{t}, neither {n}/{t}, utility predicate true {p}/{t}")

diag = json.loads((HERE / "results/diagnostics/results.json").read_text())["results"]
for s in ("morrison", "morrison-mediated", "camel"):
    x = diag[s]["DIAG-XAG-02-approved"]["reps"][0]
    print("E4 DIAG-XAG-02-approved rep0", s, [(st["step"], st["status"], st.get("detail", "")[:50]) for st in x["steps"]])
x = diag["morrison"]["DIAG-XAG-02-legit-last"]["reps"][0]
print("E5 DIAG-XAG-02-legit-last morrison", [(st["step"], st["status"]) for st in x["steps"]], "legit pred", x["legitimate"])
