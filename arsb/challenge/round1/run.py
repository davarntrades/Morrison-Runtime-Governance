"""Round-1 driver: run scenario files (frozen or hidden) against frozen and/or
corrected adapters with the FROZEN harness (runner.run_scenario, classify,
score.summarise). Nothing frozen is modified.

    python arsb/challenge/round1/run.py --scenarios DIR_OR_FILES... --output DIR
        [--sut NAME ...] [--extra]     # --extra adds the corrected adapters
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from arsb.__main__ import adapters  # noqa: E402
from arsb.core.runner import classify, load_scenarios, run_scenario  # noqa: E402
from arsb.core.score import render, summarise  # noqa: E402


def extra_adapters() -> dict:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from adapters.corrected import (CaMeLConfirm, CaMeLFaithful, CaMeLLabels, MorrisonNoDefaultDomains, MorrisonScoped, MorrisonScopedMediated,
                                    ProgentCallable, ProgentFixedApproval)
    return {c.name: c for c in (CaMeLConfirm, CaMeLLabels, CaMeLFaithful, ProgentFixedApproval,
                                ProgentCallable, MorrisonNoDefaultDomains, MorrisonScoped, MorrisonScopedMediated)}


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--scenarios", nargs="+", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--sut", action="append")
    p.add_argument("--extra", action="store_true")
    a = p.parse_args(argv)
    files = []
    for s in a.scenarios:
        q = Path(s)
        files += sorted(f for f in q.glob("*.json") if f.name != "MANIFEST.json") if q.is_dir() else [q]
    scenarios = load_scenarios(paths=files)
    reg = adapters()
    if a.extra:
        reg.update(extra_adapters())
    suts = a.sut or list(reg)
    if "ungoverned" not in suts:
        suts = ["ungoverned"] + suts
    results = {}
    for sut in suts:
        results[sut] = {}
        for sc in scenarios:
            t0 = time.perf_counter()
            r = run_scenario(sc, reg[sut])
            r["seconds"] = round(time.perf_counter() - t0, 3)
            results[sut][sc["id"]] = r
    for sut in suts:
        for sc in scenarios:
            r = results[sut][sc["id"]]
            r["classification"] = classify(r, results["ungoverned"][sc["id"]], sc)
            reps = r["reps"]
            vi = sum(bool(x.get("violated")) for x in reps)
            lok = sum(sum(bool(y) for y in x.get("legitimate", [])) for x in reps)
            ln = sum(len(x.get("legitimate", [])) for x in reps)
            print(f"{sut:26s} {sc['id']:12s} {r['classification']:26s} viol {vi}/{len(reps)} util {lok}/{ln}"
                  + (f"  ({r['unsupported']})" if r.get("unsupported") else ""))
    table = summarise(results, scenarios)
    hashes = {sc["id"]: hashlib.sha256(Path(f).read_bytes()).hexdigest() for sc, f in zip(scenarios, sorted(files))}
    out = {"driver": "arsb/challenge/round1/run.py", "frozen_commit": "6a80d78",
           "scenario_sha256": hashes, "results": results, "scorecard": table}
    a.output.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(out, indent=1, sort_keys=True, default=str)
    (a.output / "results.json").write_text(blob)
    (a.output / "SCORECARD.md").write_text(render(table, scenarios) + "\n")
    print(render(table, scenarios))
    return 0


if __name__ == "__main__":
    sys.exit(main())
