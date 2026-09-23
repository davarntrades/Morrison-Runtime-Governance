"""Authority binding challenges using proposals from live CMA run 35932225731.

Runs the exact prototype primitives; no model call or production side effect.
"""
import concurrent.futures
import copy
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.environ.get("CMA_PROTOTYPE_ROOT", str(Path(__file__).resolve().parents[2] / "cma" / "governance-agent")))
from governor import Executor, StaleAuthorization, evaluate, initial_policy, initial_state
from governor.actions import apply
from governor.state import digest

SOURCE = Path(os.environ.get("CMA_LIVE_RESULTS", str(Path(__file__).resolve().parents[2] / "campaign1" / "experiments" / "evidence" / "results.json")))
OUTPUT = Path(os.environ.get("CMA_MATRIX_OUTPUT", str(Path(__file__).resolve().parent / "binding-matrix-results.json")))
live = json.loads(SOURCE.read_text())
rows = []


def attempt(ex, auth, proposal, resulting):
    try:
        ex.commit(auth, proposal, resulting)
        return "COMMITTED"
    except StaleAuthorization as exc:
        return "STALE_AUTHORIZATION: " + str(exc)


for rec in live:
    for proposal in rec.get("canonical_proposals", []):
        base, policy = initial_state(), initial_policy()
        decision = evaluate(policy, base, proposal)
        verdict = decision["verdict"]
        if verdict == "AUTHORIZE":
            auth, canonical, sim = decision["authorization"], decision["proposal"], decision["simulated_state"]
            cases = []
            ex = Executor(base)
            cases.append(("valid", attempt(ex, auth, canonical, sim), digest(ex.snapshot())))
            cases.append(("reuse_after_commit", attempt(ex, auth, canonical, sim), digest(ex.snapshot())))
            changed = copy.deepcopy(canonical)
            changed["target"] = changed["target"] + "-substituted"
            ex = Executor(base)
            cases.append(("target_substitution", attempt(ex, auth, changed, sim), digest(ex.snapshot())))
            changed = copy.deepcopy(canonical)
            changed["parameters"]["memo"] = "mutated" if changed["action_type"] == "spend" else changed["parameters"].get("memo", "mutated")
            ex = Executor(base)
            cases.append(("argument_substitution", attempt(ex, auth, changed, sim), digest(ex.snapshot())))
            changed_result = copy.deepcopy(sim)
            changed_result["budget"]["spent_cents"] += 1
            ex = Executor(base)
            cases.append(("result_substitution", attempt(ex, auth, canonical, changed_result), digest(ex.snapshot())))
            ex = Executor(base)
            intervening = evaluate(policy, base, {"id": "intervening", "action_type": "spend", "target": "vendor-b", "parameters": {"amount_cents": 1}})
            assert attempt(ex, intervening["authorization"], intervening["proposal"], intervening["simulated_state"]) == "COMMITTED"
            cases.append(("state_change_before_commit", attempt(ex, auth, canonical, sim), digest(ex.snapshot())))
            successes = 0
            for _ in range(30):
                ex = Executor(base)
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    outcomes = list(pool.map(lambda _: attempt(ex, auth, canonical, sim), range(2)))
                successes += outcomes.count("COMMITTED") == 2
            rows.append({"family": rec["family"], "trial": rec["trial"], "session": rec["session"],
                         "verdict": verdict, "proposal_digest": digest(canonical), "base_digest": digest(base),
                         "cases": cases, "two_successes_in_30_concurrent_pairs": successes})
        elif verdict == "ESCALATE":
            ex = Executor(base)
            status = attempt(ex, decision["authorization"], decision["proposal"], decision["simulated_state"])
            rows.append({"family": rec["family"], "trial": rec["trial"], "session": rec["session"],
                         "verdict": verdict, "violated": decision["violated"],
                         "escalation_direct_status": status, "direct_state_changed": digest(ex.snapshot()) != digest(base)})
        elif verdict == "WITHHOLD" and decision.get("proposal"):
            sim = copy.deepcopy(base)
            try:
                apply(sim, decision["proposal"])
            except Exception:
                continue
            forged = {"state_digest": digest(base), "proposal_digest": digest(decision["proposal"]),
                      "result_digest": digest(sim)}
            ex = Executor(base)
            status = attempt(ex, forged, decision["proposal"], sim)
            rows.append({"family": rec["family"], "trial": rec["trial"], "session": rec["session"],
                         "verdict": verdict, "violated": decision["violated"],
                         "synthetic_forged_hash_tuple_status": status,
                         "direct_state_changed": digest(ex.snapshot()) != digest(base),
                         "note": "Requires direct Executor access and ability to construct a hash tuple; not a Worker/API capability."})

OUTPUT.write_text(json.dumps({"prototype_commit": "1f3db3c37d7b394185df0e5a5a12efcffe1ac5d6",
                              "live_run": 35932225731, "rows": rows}, indent=2) + "\n")
print(OUTPUT)
