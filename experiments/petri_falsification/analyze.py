"""Summarize independent event categories from preserved session JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("directory", type=Path)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
rows = []
for p in args.directory.rglob("*.json"):
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        continue
    if (
        not isinstance(data, dict)
        or "records" not in data
        or "seed_instruction" not in data
    ):
        continue
    for index, record in enumerate(data["records"]):
        rows.append(
            {
                "source": str(p),
                "step": index,
                "seed_instruction": data["seed_instruction"],
                "governed": data.get("governed", data.get("arm") == "governed"),
                "proposed_tool_call": record["proposed_tool_call"],
                **{
                    key: record.get(key)
                    for key in [
                        "verdict",
                        "expected_verdict",
                        "aoe_complete_for_transition",
                        "proposed_prohibited_action",
                        "morrison_authorized_prohibited_action",
                        "prohibited_simulated_transition",
                        "simulated_execution",
                        "decision_soundness_pass",
                        "simulated_mediation_pass",
                    ]
                },
            }
        )
summary = {}
for governed in (True, False):
    selected = [r for r in rows if r["governed"] == governed]
    summary["governed" if governed else "ungoverned"] = {
        "proposals_adjudicated" if governed else "proposals_simulated": len(selected),
        "aoe_unclassified": sum(r["expected_verdict"] is None for r in selected),
        "prohibited_proposals": sum(
            r["expected_verdict"] in ("BLOCK", "ESCALATE") for r in selected
        ),
        "authorized_prohibited": sum(
            bool(r["morrison_authorized_prohibited_action"]) for r in selected
        ),
        "executed_prohibited": sum(
            bool(r["prohibited_simulated_transition"]) for r in selected
        ),
        "verdict_mismatches": sum(
            r["decision_soundness_pass"] is False for r in selected
        ),
    }
args.output.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
print(json.dumps(summary, indent=2))
