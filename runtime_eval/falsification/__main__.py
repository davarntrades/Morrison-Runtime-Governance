"""Run the offline falsification suite.

    python -m runtime_eval.falsification --output DIR --phase pre-repair

Writes DIR/falsification-<phase>.json. An experiment that crashes is
recorded with its traceback, never dropped.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import tempfile
import time
import traceback
from importlib.metadata import version
from pathlib import Path


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True,
                          check=False).stdout.strip()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m runtime_eval.falsification")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--phase", required=True, help="e.g. pre-repair / post-repair")
    p.add_argument("--only", action="append", help="experiment id prefix")
    p.add_argument("--stress", action="store_true", help="run only the repeated race experiments")
    args = p.parse_args(argv)

    from runtime_eval.falsification.experiments import ALL, Ctx, stress
    if args.stress:
        ALL = [stress]                                          # noqa: N806
    args.output.mkdir(parents=True, exist_ok=True)
    results, started = [], time.time()
    with tempfile.TemporaryDirectory() as tmp:
        ctx = Ctx(Path(tmp))
        for fn in ALL:
            t0 = time.perf_counter()
            try:
                res = fn(ctx)
            except Exception:                       # noqa: BLE001 - recorded
                res = {"id": getattr(fn, "__name__", "?"), "error": traceback.format_exc()}
            if args.only and not any(str(res.get("id", "")).startswith(o) for o in args.only):
                continue
            res["duration_s"] = round(time.perf_counter() - t0, 3)
            results.append(res)
            flag = ("ERROR" if "error" in res else
                    "VIOLATION" if res.get("violated") else "")
            print(f"{res.get('id', '?'):14s} {res.get('duration_s')}s {flag}")
    out = {
        "phase": args.phase,
        "provenance": {"git_commit": _git("rev-parse", "HEAD"),
                       "git_dirty": bool(_git("status", "--porcelain")),
                       "python": platform.python_version(),
                       "agentdojo": version("agentdojo"),
                       "platform": platform.platform(),
                       "started_at": started, "argv": sys.argv[1:]},
        "proposer": "scripted (no model calls)",
        "experiments": results,
    }
    path = args.output / f"falsification-{args.phase}.json"
    path.write_text(json.dumps(out, indent=2, sort_keys=True, default=str))
    print(f"wrote {path}")
    return 1 if any("error" in r for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
