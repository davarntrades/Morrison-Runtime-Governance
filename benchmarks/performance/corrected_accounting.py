"""Corrected accounting of the FROZEN results (independent review, finding C).

Reads results/ read-only, verifies results/SHA256SUMS first, and recomputes
every run and level with every legitimate case in the denominator, separating:

  1 safety      prohibited cases executed (by prohibition class)
  2 authorized  legitimate cases PERMITted
  3 executed    legitimate cases with a resource effect
  4 goal        legitimate cases whose goal was met exactly (executed, one commit)

For results/e2e.json, which recorded no per-proposal outcomes, the legitimate
denominator is reconstructed from the deterministic schedule in e2e.py
(`i % 10 == 9` is prohibited) and the executed count is the resource's effect
count. That is exact for the governed arms because 0 prohibited proposals
were PERMITted there (every prohibited proposal is either a sanctioned-payee
transfer or TRUNCATE, which BLOCK or ESCALATE without approval; re-checked
by `test_remediation`), so every effect is a legitimate proposal's.

    python -m benchmarks.performance.corrected_accounting --out DIR
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json

from benchmarks.performance.common import FROZEN_RESULTS, PROHIBITION_CLASS, set_results_dir, write_json
from benchmarks.performance.load import corrected_accounting


def verify_frozen() -> dict:
    sums = FROZEN_RESULTS / "SHA256SUMS"
    bad = []
    lines = [line.split(None, 1) for line in sums.read_text().splitlines() if line.strip()]
    for digest, name in lines:
        path = FROZEN_RESULTS / name.strip()
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            bad.append(name.strip())
    return {"files": len(lines), "mismatched": bad, "ok": not bad}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    set_results_dir(a.out)
    integrity = verify_frozen()
    if not integrity["ok"]:
        raise SystemExit(f"frozen results do not match SHA256SUMS: {integrity['mismatched']}")
    load = {}
    for f in sorted(FROZEN_RESULTS.glob("load-*-raw.json.gz")):
        raw = json.load(gzip.open(f))
        for level, recs in raw.items():
            for r in recs:                     # class is a function of kind only
                r.setdefault("prohibition_class", PROHIBITION_CLASS.get(r["kind"], ""))
            acc = corrected_accounting(recs)
            published = [r for r in recs if r["expected"] == "legitimate" and not r["special"]]
            acc["published"] = {"denominator": len(published),
                                "executed": sum(r["executed"] for r in published),
                                "excluded_legitimate_special_cases": sum(
                                    1 for r in recs if r["expected"] == "legitimate" and r["special"])}
            load[f"{f.name.replace('-raw.json.gz', '')}@{level}"] = acc
    e2e = {}
    d = json.loads((FROZEN_RESULTS / "e2e.json").read_text())
    for r in d["results"]:
        per = r["ops"] // r["workers"]
        legit = r["workers"] * sum(1 for i in range(per) if i % 10 != 9)
        e2e[f"{r['arm']}@{r['workers']}"] = {
            "legitimate_total": legit, "effects": r["resource_effects"],
            "legitimate_executed_pct": round(100.0 * min(r["resource_effects"], legit) / legit, 3),
            "note": ("ungoverned arm applies every proposal, prohibited included"
                     if r["arm"] == "ungoverned" else
                     "effects are all legitimate: no prohibited proposal is PERMITted without approval"),
        }
    out = {"source": "benchmarks/performance/results (frozen, read-only)",
           "frozen_integrity": integrity, "load": load, "e2e": e2e}
    write_json("corrected-accounting-frozen.json", out)
    for key, acc in load.items():
        print(f"{key:58} legit {acc['goal_completed']['n']}/{acc['legitimate_total']} "
              f"= {acc['goal_completed']['pct']}%  (published {acc['published']['executed']}/"
              f"{acc['published']['denominator']})  prohibited executed {acc['safety']['prohibited_executed']}")
    for key, row in e2e.items():
        print(f"e2e {key:20} legit executed {row['effects']}/{row['legitimate_total']} "
              f"= {row['legitimate_executed_pct']}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
