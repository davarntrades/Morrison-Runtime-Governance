"""E0 entry point. Runs the frozen protocol e0-1.0.0 exactly once.

Headline comparison is T vs B1, per profile:

    P(U | T, profile) < P(U | B1, same profile)

B0 is diagnostic context and contributes nothing to the classification.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
for _p in (HERE, REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import runner  # noqa: E402
from environment_e0 import SPEC_VERSION, mixed_support_workflow  # noqa: E402
from profiles import PROFILES  # noqa: E402
from runner import enumerate_trials, rates, run_cell  # noqa: E402

HEADLINE_ARMS = ("B1", "T")
DIAGNOSTIC_ARMS = ("B0",)
ALL_ARMS = DIAGNOSTIC_ARMS + HEADLINE_ARMS


def engine_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=os.path.dirname(os.path.dirname(HERE)),
            text=True).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def main() -> int:
    runner.ENGINE_COMMIT = engine_commit()
    env = mixed_support_workflow()
    trials = enumerate_trials()

    out = {
        "spec_version": SPEC_VERSION,
        "model_hash": env.model_hash,
        "engine_commit": runner.ENGINE_COMMIT,
        "trials_enumerated": len(trials),
        "headline_arms": list(HEADLINE_ARMS),
        "cells": {},
    }

    records_all = []
    for arm in ALL_ARMS:
        for profile in PROFILES:
            counters, records = run_cell(arm, profile, trials)
            out["cells"][f"{arm}:{profile}"] = {
                "counts": counters.as_dict(),
                "rates": rates(counters),
                "trials_run": len(records),
            }
            records_all.extend(records)

    data_dir = os.path.join(HERE, "results")
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(data_dir, "e0_results.json"), "w") as fh:
        json.dump(out, fh, indent=2, default=str)
    with open(os.path.join(data_dir, "e0_trials.jsonl"), "w") as fh:
        for rec in records_all:
            fh.write(json.dumps(asdict(rec), default=str) + "\n")

    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
