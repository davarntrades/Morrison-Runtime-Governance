"""Run the repository's existing supporting experiments and extract a summary.

    python -m audit_demo.supporting --output audit_demo/evidence/supporting

Runs, unchanged, three existing harnesses:
  * runtime_eval.falsification            (offline adversarial falsification)
  * runtime_eval.frontier.cli             (Frontier Lab, deterministic planner)
  * experiments.local_global_admissibility (local-only vs hierarchical)
and writes supporting_summary.json with numbers extracted from their output
files. Report B quotes only this summary.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str], log: Path) -> int:
    with log.open("w") as fh:
        return subprocess.run([sys.executable, *cmd], stdout=fh, stderr=subprocess.STDOUT,
                              check=False).returncode


def summarise_falsification(path: Path) -> dict:
    data = json.loads(path.read_text())
    rows = []
    for e in data["experiments"]:
        arms = e.get("arms", {})
        rows.append({
            "id": e.get("id"), "title": e.get("title", ""),
            "property": e.get("property", ""),
            "suite_violation_flag": bool(e.get("violated")),
            "error": "error" in e,
            "arms_reaching_prohibited_state": sorted(
                k for k, v in arms.items()
                if isinstance(v, dict) and v.get("prohibited_state_reached")),
            "arms_total": len(arms),
        })
    return {"file": path.name, "experiments": len(rows),
            "errors": sum(r["error"] for r in rows),
            "suite_violation_flags": [r["id"] for r in rows if r["suite_violation_flag"]],
            "rows": rows, "proposer": data.get("proposer"),
            "provenance": data.get("provenance", {})}


def summarise_frontier(path: Path) -> dict:
    d = json.loads(path.read_text())
    keys = ("total_trials", "model_compromise_count", "model_resistance_count",
            "morrison_block_count", "morrison_escalate_count",
            "unauthorized_execution_count", "runtime_containment_rate",
            "false_positive_rate_on_safe_controls", "permitted_safe_actions")
    return {"file": path.name, **{k: d.get(k) for k in keys},
            "planner": "deterministic (scripted, no hosted model)"}


def summarise_local_global(path: Path) -> dict:
    data = json.loads(path.read_text())
    out = {}
    for mode, rows in data["arms"].items():
        out[mode] = {"requests": len(rows),
                     "executed": sum(bool(r.get("executed")) for r in rows),
                     "local_verdicts": [(r.get("local_verdict") or {}).get("verdict") for r in rows],
                     "global_verdicts": [(r.get("global_verdict") or {}).get("verdict") for r in rows],
                     "final_total": rows[-1].get("total_after") if rows else None}
    return {"file": path.name, "arms": out}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m audit_demo.supporting")
    p.add_argument("--output", type=Path, default=Path("audit_demo/evidence/supporting"))
    a = p.parse_args(argv)
    out = a.output
    out.mkdir(parents=True, exist_ok=True)
    codes = {
        "falsification": _run(["-m", "runtime_eval.falsification", "--output",
                               str(out / "falsification"), "--phase", "audit-demo"],
                              out / "falsification.log"),
        "frontier": _run(["-m", "runtime_eval.frontier.cli", "--provider", "deterministic",
                          "--scenario", "all", "--output", str(out / "frontier")],
                         out / "frontier.log"),
        "local_global": _run(["-m", "experiments.local_global_admissibility.experiment",
                              "--output", str(out / "local_global")], out / "local_global.log"),
    }
    summary = {
        "exit_codes": codes,
        "falsification": summarise_falsification(out / "falsification" / "falsification-audit-demo.json"),
        "frontier_cli": summarise_frontier(out / "frontier" / "summary.json"),
        "local_global": summarise_local_global(out / "local_global" / "traces.json"),
    }
    (out / "supporting_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str))
    print(json.dumps({k: summary[k] for k in ("exit_codes",)}, indent=1))
    print("falsification flags:", summary["falsification"]["suite_violation_flags"],
          "errors:", summary["falsification"]["errors"])
    print("frontier:", summary["frontier_cli"])
    print("local/global:", summary["local_global"])
    return 0 if not any(codes.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
