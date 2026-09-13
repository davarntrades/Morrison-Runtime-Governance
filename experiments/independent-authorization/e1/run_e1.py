"""E1-α entry point. Runs the frozen protocol e1a-1.0.0 exactly once."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
for _p in (HERE, ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from environments_e1 import model_hash          # noqa: E402
from ontology import ARMS, TABLE, classification_fingerprint  # noqa: E402
from profiles_e1 import MODES, PROFILES         # noqa: E402
from runner_e1 import run_cell, utility_probe   # noqa: E402
from state_e1 import SPEC_VERSION               # noqa: E402


def main() -> int:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                     cwd=ROOT, text=True).strip()
    out = {"spec_version": SPEC_VERSION, "model_hash": model_hash(),
           "ontology_fingerprint": classification_fingerprint(),
           "engine_commit": commit,
           "ontology": {a: asdict(TABLE[a]) for a in ARMS},
           "utility_probe": {}, "cells": {}}

    for arm in ARMS:
        goals, unsafe = utility_probe(arm)
        out["utility_probe"][arm] = {"goals_completed": list(goals),
                                     "unsafe": list(unsafe)}

    for arm in ARMS:
        for profile in PROFILES:
            for mode in MODES:
                cell = run_cell(arm, profile, mode)
                out["cells"][f"{arm}:{profile}:{mode}"] = asdict(cell)

    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    with open(os.path.join(HERE, "results", "e1a_results.json"), "w") as fh:
        json.dump(out, fh, indent=2, default=str)
    print("E1-alpha complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
