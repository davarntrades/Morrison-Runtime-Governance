"""E1-β entry point. Runs frozen protocol e1b-1.0.0 exactly once."""
from __future__ import annotations
import json, os, subprocess, sys
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
for _p in (HERE, ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from arms_e1b import ARMS, ONTOLOGY, ontology_fingerprint  # noqa: E402
from env_e1b import model_hash                              # noqa: E402
from profiles_e1b import MODES, PROFILES                    # noqa: E402
from runner_e1b import run_cell, utility_probe              # noqa: E402
from state_e1b import SPEC_VERSION                          # noqa: E402


def main() -> int:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                     cwd=ROOT, text=True).strip()
    out = {"spec_version": SPEC_VERSION, "model_hash": model_hash(),
           "ontology_fingerprint": ontology_fingerprint(), "engine_commit": commit,
           "ontology": {a: asdict(ONTOLOGY[a]) for a in ARMS},
           "utility_probe": {a: utility_probe(a) for a in ARMS}, "cells": {}}
    for arm in ARMS:
        for profile in PROFILES:
            for mode in MODES:
                out["cells"][f"{arm}:{profile}:{mode}"] = asdict(
                    run_cell(arm, profile, mode))
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    with open(os.path.join(HERE, "results", "e1b_results.json"), "w") as fh:
        json.dump(out, fh, indent=2, default=str)
    print("E1-beta complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
