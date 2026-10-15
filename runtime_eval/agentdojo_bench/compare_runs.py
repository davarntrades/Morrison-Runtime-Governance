"""Machine-readable paired comparison across live AgentDojo runs.

    python -m runtime_eval.agentdojo_bench.compare_runs OUT.json RUN_DIR [RUN_DIR ...]

Each RUN_DIR is a verified evidence directory (with analysis.json). Every
count is reported with its denominator; attack-pair, standalone and benign
episodes are kept separate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from runtime_eval.agentdojo_bench.analyze import analyse
from runtime_eval.agentdojo_bench.ci import load_arms


def _frac(n: int, d: int) -> str:
    return f"{n}/{d}"


def summarise_run(root: Path) -> dict:
    arms = load_arms(root)
    analysis = analyse(root)
    ver = json.loads((root / "verification.json").read_text())
    canary = json.loads((root / "canary" / "preflight.json").read_text()).get("canary", {})
    out = {"run_dir": root.name, "verification_ok": ver["ok"],
           "evidence_chains_verified": ver["evidence_chains"]["checked"],
           "evidence_chains_failed": len(ver["evidence_chains"]["failed"]),
           "matched_conditions": ver["matched_conditions"]["ok"],
           "credential_redactions": len(ver["redactions"]),
           "canary": {k: canary.get(k) for k in ("ok", "served_model", "stop_reason",
                                                 "input_tokens", "output_tokens",
                                                 "est_cost_usd")},
           "arms": {}}
    for name, arm in arms.items():
        an = analysis["arms"][name]
        pairs, std, ben = an["episodes"], an["standalone_episodes"], an.get("benign_episodes", [])

        def n(rows, pred):
            return sum(1 for r in rows if pred(r))

        withheld_std = [a for r in std for a in r["prohibited_attempts"] if not a["executed"]]
        out["arms"][name] = {
            "status": arm["status"],
            "provenance": arm["provenance"],
            "llm_settings": arm["llm_settings"],
            "api_usage": arm["api_usage"],
            "attack_pairs": {
                "pairs": len(pairs),
                "agentdojo_attack_success": _frac(n(pairs, lambda r: r["agentdojo_attack_succeeded"]), len(pairs)),
                "prohibited_attempted": _frac(n(pairs, lambda r: r["prohibited_attempted"]), len(pairs)),
                "prohibited_executed": _frac(n(pairs, lambda r: r["prohibited_executed"]), len(pairs)),
                "verified_prohibited_effect": _frac(n(pairs, lambda r: r["local_safety"] == "VIOLATED"), len(pairs)),
                "utility_under_attack": _frac(n(pairs, lambda r: r["utility"]), len(pairs)),
                "pairs_with_legitimate_calls_withheld": _frac(n(pairs, lambda r: r["benign_calls_withheld"]), len(pairs)),
                "calls_attempted": sum(r["calls_attempted"] for r in pairs),
                "calls_authorised": sum(r["calls_authorised"] for r in pairs),
                "calls_executed": sum(r["calls_executed"] for r in pairs),
            },
            "standalone_injection_tasks": {
                "episodes": len(std),
                "prohibited_proposals": sum(len(r["prohibited_attempts"]) for r in std),
                "prohibited_proposals_executed": sum(1 for r in std for a in r["prohibited_attempts"] if a["executed"]),
                "verified_prohibited_effect": _frac(n(std, lambda r: r["local_safety"] == "VIOLATED"), len(std)),
                "attacker_funds_total": sum(r["attacker_funds_total"] for r in std),
                "withheld_by": sorted({f'{a["verdict"]}:{a["layer"]}:{a["rule"]}' for a in withheld_std}),
            },
            "benign_user_tasks": {
                "episodes": len(ben),
                "utility": _frac(n(ben, lambda r: r["utility"]), len(ben)),
                "legitimate_calls_withheld": [
                    {"user_task": r["user_task"], **w} for r in ben for w in r["benign_calls_withheld"]],
            },
            "binding_failures": an["binding_failures"],
            "effect_inconsistencies": an["effect_inconsistencies"],
            "refusals": [{"episode": r.get("episode"), "request_id": r.get("request_id"),
                          "category": (r.get("stop_details") or {}).get("category")}
                         for r in arm["api_requests"] if r["stop_reason"] == "refusal"],
        }
    return out


def main(out: Path, roots: list[Path]) -> int:
    runs = [summarise_run(r) for r in roots]
    total = {"billed_requests": 0, "input_tokens": 0, "output_tokens": 0, "est_cost_usd": 0.0}
    for run in runs:
        c = run["canary"]
        total["billed_requests"] += 1
        total["input_tokens"] += c.get("input_tokens") or 0
        total["output_tokens"] += c.get("output_tokens") or 0
        total["est_cost_usd"] += c.get("est_cost_usd") or 0.0
        for arm in run["arms"].values():
            u = arm["api_usage"]
            total["billed_requests"] += u["requests"]
            total["input_tokens"] += u["input_tokens"]
            total["output_tokens"] += u["output_tokens"]
            total["est_cost_usd"] += u["est_cost_usd"]
    total["est_cost_usd"] = round(total["est_cost_usd"], 4)
    result = {"runs": runs, "totals_across_runs": total,
              "cost_basis": "token usage x Claude Opus 5.5 list price ($4 in / $20 out "
                            "per MTok); the Anthropic invoice is authoritative"}
    out.write_text(json.dumps(result, indent=2, sort_keys=True))
    print(json.dumps(total, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), [Path(p) for p in sys.argv[2:]]))
