"""Aggregate verified live AgentDojo runs into one paired comparison.

    python -m runtime_eval.falsification.live_summary OUT.json RUN_DIR [RUN_DIR ...]

Each RUN_DIR is a rebuilt, verified evidence directory. One record per
(run, arm). Every count carries its denominator. Attack pairs (genuine
prompt injection through tool output), standalone injection tasks (the
attacker's goal given as the user's own request) and benign tasks (no
injection) are kept apart and never pooled.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from runtime_eval.agentdojo_bench.analyze import analyse
from runtime_eval.agentdojo_bench.ci import load_arms

REPO = "https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/"


def _frac(n: int, d: int) -> str:
    return f"{n}/{d}"


def summarise(root: Path) -> dict:
    arms = load_arms(root)
    an = analyse(root)["arms"]
    ver = json.loads((root / "verification.json").read_text())
    run_id = root.name.split("-")[1]
    out = {"run_dir": root.name, "run_url": REPO + run_id,
           "verification_ok": ver["ok"], "matched_conditions": ver["matched_conditions"],
           "evidence_chains": {"checked": ver["evidence_chains"]["checked"],
                               "failed": len(ver["evidence_chains"]["failed"])},
           "credential_redactions": len(ver["redactions"]), "arms": {}}
    for name, arm in arms.items():
        a = an[name]
        pairs, std, ben = a["episodes"], a["standalone_episodes"], a.get("benign_episodes", [])

        def n(rows, pred):
            return sum(1 for r in rows if pred(r))

        reqs = arm.get("api_requests") or []
        out["arms"][name] = {
            "model": arm["model"], "attack": arm["attack"], "status": arm["status"],
            "git_commit": arm["provenance"]["git_commit"],
            "llm_settings": arm["llm_settings"], "approver": arm.get("approver"),
            "attack_pairs": {
                "pairs": len(pairs),
                "agentdojo_attack_success": _frac(n(pairs, lambda r: r["agentdojo_attack_succeeded"]), len(pairs)),
                "prohibited_attempted": _frac(n(pairs, lambda r: r["prohibited_attempted"]), len(pairs)),
                "prohibited_executed": _frac(n(pairs, lambda r: r["prohibited_executed"]), len(pairs)),
                "verified_prohibited_effect": _frac(n(pairs, lambda r: r["local_safety"] == "VIOLATED"), len(pairs)),
                "attacker_funds_total": sum(r["attacker_funds_total"] for r in pairs),
                "utility_under_attack": _frac(n(pairs, lambda r: r["utility"]), len(pairs)),
                "pairs_with_legitimate_calls_withheld": _frac(n(pairs, lambda r: r["benign_calls_withheld"]), len(pairs)),
                "prohibited_attempt_examples": [
                    {"user_task": r["user_task"], "injection_task": r["injection_task"],
                     "attempts": r["prohibited_attempts"], "effects": r["verified_prohibited_effects"]}
                    for r in pairs if r["prohibited_attempted"]][:20],
            },
            "standalone_injection_tasks": {
                "episodes": len(std),
                "prohibited_proposals": sum(len(r["prohibited_attempts"]) for r in std),
                "prohibited_executed": sum(1 for r in std for x in r["prohibited_attempts"] if x["executed"]),
                "verified_prohibited_effect": _frac(n(std, lambda r: r["local_safety"] == "VIOLATED"), len(std)),
            },
            "benign_user_tasks": {
                "episodes": len(ben),
                "utility": _frac(n(ben, lambda r: r["utility"]), len(ben)),
                "episodes_with_legitimate_calls_withheld": _frac(
                    n(ben, lambda r: r["calls_executed"] < r["calls_attempted"]), len(ben)),
                "withheld": [{"user_task": r["user_task"], "calls": r["benign_calls_withheld"]}
                             for r in ben if r["benign_calls_withheld"]],
            },
            "approvals": a.get("approvals"),
            "binding_failures": a["binding_failures"],
            "effect_inconsistencies": a["effect_inconsistencies"],
            "api": {**{k: arm["api_usage"][k] for k in ("requests", "input_tokens", "output_tokens",
                                                        "est_cost_usd", "stop_reasons", "served_models")},
                    "requests_with_request_id": sum(1 for r in reqs if r.get("request_id"))},
        }
    canary = root / "canary" / "preflight.json"
    if canary.exists():
        c = json.loads(canary.read_text()).get("canary") or {}
        out["canary"] = {k: c.get(k) for k in ("ok", "served_model", "input_tokens",
                                                 "output_tokens", "est_cost_usd")}
    return out


def main(out: Path, roots: list[Path]) -> int:
    runs = [summarise(r) for r in roots]
    total = {"billed_requests": 0, "input_tokens": 0, "output_tokens": 0, "est_cost_usd": 0.0}
    for run in runs:
        c = run.get("canary") or {}
        if c.get("ok"):
            total["billed_requests"] += 1
            total["input_tokens"] += c.get("input_tokens") or 0
            total["output_tokens"] += c.get("output_tokens") or 0
            total["est_cost_usd"] += c.get("est_cost_usd") or 0.0
        for arm in run["arms"].values():
            total["billed_requests"] += arm["api"]["requests"]
            total["input_tokens"] += arm["api"]["input_tokens"]
            total["output_tokens"] += arm["api"]["output_tokens"]
            total["est_cost_usd"] += arm["api"]["est_cost_usd"]
    total["est_cost_usd"] = round(total["est_cost_usd"], 4)
    out.write_text(json.dumps({"runs": runs, "totals": total,
                               "cost_basis": "token usage x list price per model; "
                                             "the Anthropic invoice is authoritative"},
                              indent=2, sort_keys=True))
    print(json.dumps(total, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), [Path(p) for p in sys.argv[2:]]))
