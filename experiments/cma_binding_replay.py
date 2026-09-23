"""Replay live CMA proposals against frozen 1f3db3c authority primitives.

No Anthropic API call is made. This tests R2-R5 in the original Python boundary
with R0 proposals obtained in live GitHub Actions run 35932225731.
"""
import hashlib
import json
import sys
import os
from pathlib import Path

sys.path.insert(0, os.environ.get("CMA_PROTOTYPE_ROOT", str(Path(__file__).resolve().parents[2] / "cma" / "governance-agent")))
from governor import Executor, Pipeline, StaleAuthorization, evaluate, initial_policy, initial_state
from governor.state import digest

SOURCE = Path(os.environ.get("CMA_LIVE_RESULTS", str(Path(__file__).resolve().parents[2] / "campaign1" / "experiments" / "evidence" / "results.json")))
OUTPUT = Path(os.environ.get("CMA_REPLAY_OUTPUT", str(Path(__file__).resolve().parent / "binding-replay-results.json")))
records = json.loads(SOURCE.read_text())
out = {"source_workflow_run": 35932225731, "source_commit": "1f3db3c37d7b394185df0e5a5a12efcffe1ac5d6",
       "live_result_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(), "trials": []}

for rec in records:
    for raw in rec.get("raw_proposals", []):
        canonical = rec["canonical_proposals"][rec["raw_proposals"].index(raw)]
        before, policy = initial_state(), initial_policy()
        evaluated = evaluate(policy, before, canonical)
        normal = Pipeline(before, policy).submit(canonical)
        direct = Executor(before)
        error = None
        try:
            direct.commit(evaluated["authorization"], evaluated["proposal"], evaluated["simulated_state"])
        except (StaleAuthorization, TypeError) as exc:
            error = type(exc).__name__ + ": " + str(exc)
        after = direct.snapshot()
        out["trials"].append({"family": rec["family"], "trial": rec["trial"], "session": rec["session"],
            "raw": raw, "canonical": canonical, "raw_digest": digest(raw), "canonical_digest": digest(canonical),
            "verdict": evaluated["verdict"], "violated": evaluated["violated"],
            "authorization": evaluated["authorization"], "normal_pipeline_verdict": normal["verdict"],
            "normal_pipeline_committed": normal["state_before_digest"] != normal["state_after_digest"],
            "direct_executor_error": error, "direct_executor_committed": digest(before) != digest(after),
            "state_before_digest": digest(before), "state_after_digest": digest(after)})

OUTPUT.write_text(json.dumps(out, indent=2) + "\n")
print(OUTPUT)
