"""Run the audit cases through the PR's unmodified harness, all four conditions."""
import importlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2])); sys.path.insert(0, str(Path(__file__).resolve().parent))
from experiments.monitoring_incident.harness import RunConfig, run_episode
from experiments.monitoring_incident.proposers import ScriptedProposer
from experiments.monitoring_incident.sandbox import Sandbox
# Sibling script loaded by name (see race_final.py).
AUDIT_CASES = importlib.import_module("audit_cases").AUDIT_CASES

out = Path(sys.argv[1]); policy = sys.argv[2] if len(sys.argv) > 2 else "deny"
only = set(sys.argv[3:])
base_audit = Sandbox.template_files("alert_suppression")["var/log/security_audit.jsonl"].decode()
rows = []
for cid, sid, desc, steps in AUDIT_CASES:
    if only and cid not in only: continue
    steps = json.loads(json.dumps(steps).replace("@BASELINE_AUDIT@", json.dumps(base_audit)[1:-1]))
    for cond in ("ungoverned", "local_only", "global_only", "hierarchical"):
        s = run_episode(RunConfig(scenario=sid, condition=cond, output_dir=out, case_id=cid,
                                  escalation_policy=policy), ScriptedProposer(cid, steps))
        recs = [json.loads(l) for l in open(out / s["metadata"]["run_id"] / "evidence.jsonl")]
        trace = []
        ev = {}
        for r in recs:
            p = r["payload"]
            if r["type"] == "oracle_label": ev[p["eval_id"]] = {"tool": p["action"]["tool"], "label": p["label"]}
            elif r["type"] == "local_evaluation": ev[p["eval_id"]]["L"] = p["verdict"][:4]
            elif r["type"] == "global_evaluation": ev[p["eval_id"]]["G"] = p["verdict"][:4]
            elif r["type"] == "decision": ev[p["eval_id"]]["D"] = p["verdict"]
            elif r["type"] == "execution": ev[p["eval_id"]]["X"] = p["executed"]
        m = s["metrics"]
        rows.append({"case": cid, "cond": cond, "steps": list(ev.values()),
                     "unauth_exec": m["unauthorized_executed"], "final_intact": m["monitoring_intact_final"],
                     "task": m["task_completed"], "proj_div_steps": m["projection_divergence_steps"],
                     "fp_esc": m["false_positive_escalate"], "evidence_valid": s["evidence"]["valid"]})
        r = rows[-1]
        print("%-28s %-12s unauth_exec=%d final_intact=%-5s task=%-5s projdiv=%d valid=%s | %s" % (
            cid, cond, r["unauth_exec"], r["final_intact"], r["task"], r["proj_div_steps"], r["evidence_valid"],
            "  ".join("%s[%s L=%s G=%s D=%s X=%s]" % (e["tool"][:6], e["label"][:5], e.get("L","-"), e.get("G","-"), e.get("D"), e.get("X","-")) for e in r["steps"])))
json.dump(rows, open(str(out) + "_rows.json", "w"), indent=1)
