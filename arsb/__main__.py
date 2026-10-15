"""Run ARSB v0 (scripted threat models only; no model inference).

    python -m arsb --output DIR [--sut NAME ...] [--scenario ID ...] [--reps N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

from arsb.core.runner import SCENARIO_DIR, classify, load_scenarios, run_scenario
from arsb.core.score import render, summarise


def adapters() -> dict:
    from arsb.adapters.baselines import Allowlist, DenyAll, Ungoverned
    from arsb.adapters.reference_provenance import ReferenceProvenance
    out = {"ungoverned": Ungoverned, "deny-all": DenyAll, "allowlist": Allowlist,
           "reference-provenance": ReferenceProvenance}
    try:
        from arsb.adapters.morrison import Morrison, MorrisonMediated
        out.update({"morrison": Morrison, "morrison-mediated": MorrisonMediated})
    except ImportError as exc:                          # pragma: no cover
        print(f"morrison adapters unavailable: {exc}", file=sys.stderr)
    for mod, cls in (("arsb.adapters.progent_adapter", "Progent"), ("arsb.adapters.camel_adapter", "CaMeL")):
        try:
            m = __import__(mod, fromlist=[cls])
            out[getattr(m, cls).name] = getattr(m, cls)
        except Exception as exc:                        # noqa: BLE001 - optional, reported
            print(f"{mod} unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m arsb")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--sut", action="append")
    p.add_argument("--scenario", action="append")
    p.add_argument("--reps", type=int)
    a = p.parse_args(argv)
    scenarios = load_scenarios()
    if a.scenario:
        scenarios = [s for s in scenarios if s["id"] in a.scenario]
    registry = adapters()
    suts = a.sut or list(registry)
    if "ungoverned" not in suts:
        suts = ["ungoverned"] + suts                    # classification needs the baseline
    results, started = {}, time.time()
    for sut in suts:
        results[sut] = {}
        for sc in scenarios:
            t0 = time.perf_counter()
            r = run_scenario(sc, registry[sut], a.reps)
            r["seconds"] = round(time.perf_counter() - t0, 3)
            results[sut][sc["id"]] = r
    for sut in suts:
        for sc in scenarios:
            r = results[sut][sc["id"]]
            r["classification"] = classify(r, results["ungoverned"][sc["id"]], sc)
            print(f"{sut:22s} {sc['id']:8s} {r['classification']:26s} "
                  f"viol {sum(bool(x.get('violated')) for x in r['reps'])}/{len(r['reps'])}"
                  + (f"  ({r['unsupported']})" if r.get("unsupported") else ""))
    table = summarise(results, scenarios)
    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True).stdout.strip())
    manifest = json.loads((SCENARIO_DIR / "MANIFEST.json").read_text())
    out = {"benchmark": "ARSB", "version": "0.1", "threat_models_run": ["TM-S"],
           "provenance": {"git_commit": head, "git_dirty": dirty, "python": platform.python_version(),
                          "started_at": started, "argv": sys.argv[1:]},
           "scenario_hashes": {s["id"]: manifest.get(s["id"]) for s in scenarios},
           "results": results, "scorecard": table}
    a.output.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(out, indent=1, sort_keys=True, default=str)
    (a.output / "arsb-results.json").write_text(blob)
    (a.output / "SCORECARD.md").write_text(render(table, scenarios) + "\n")
    (a.output / "arsb-results.sha256").write_text(hashlib.sha256(blob.encode()).hexdigest() + "\n")
    print(render(table, scenarios))
    return 0


if __name__ == "__main__":
    sys.exit(main())
