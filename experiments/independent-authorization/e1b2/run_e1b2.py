"""Track A entry point. Runs frozen e1b-1.0.0 with the corrected B7, once."""
from __future__ import annotations
import json, os, subprocess, sys
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
E1B = os.path.join(os.path.dirname(HERE), "e1b")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
for _p in (HERE, E1B, ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import runner_e1b                                            # noqa: E402
from arms_e1b import ARMS, ONTOLOGY, ontology_fingerprint     # noqa: E402
from arms_e1b2 import SPEC_VERSION, build_corrected           # noqa: E402
from env_e1b import model_hash                                # noqa: E402
from profiles_e1b import MODES, PROFILES                      # noqa: E402


def main() -> int:
    # Substitute ONLY the arm builder. The runner, environment, predicates,
    # profiles and denominators are the frozen E1-β objects.
    runner_e1b.build = build_corrected

    commit = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                     cwd=ROOT, text=True).strip()
    out = {"spec_version": SPEC_VERSION,
           "inherits_environment": "e1b-1.0.0",
           "model_hash": model_hash(),
           "ontology_fingerprint": ontology_fingerprint(),
           "engine_commit": commit,
           "correction": "B7 destination checks scoped to the shared "
                         "capability surface; no other change",
           "utility_probe": {a: runner_e1b.utility_probe(a) for a in ARMS},
           "cells": {}}
    for arm in ARMS:
        for profile in PROFILES:
            for mode in MODES:
                out["cells"][f"{arm}:{profile}:{mode}"] = asdict(
                    runner_e1b.run_cell(arm, profile, mode))

    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    with open(os.path.join(HERE, "results", "e1b2_results.json"), "w") as fh:
        json.dump(out, fh, indent=2, default=str)
    print("Track A complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
