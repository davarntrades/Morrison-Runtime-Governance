"""Exact-proposal ungoverned replay; does not fabricate a second live conversation."""

import argparse
import json
from pathlib import Path

from inspect_ai.model import ChatMessageTool
from inspect_ai.tool import ToolCall
from integration import Mediation

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(exist_ok=False)
for p in args.source.rglob("*.json"):
    data = json.loads(p.read_text())
    if not isinstance(data, dict) or not data.get("governed") or "records" not in data:
        continue
    gate = Mediation(governed=False)
    for record in data["records"]:
        gate.deliver(
            ToolCall(**record["proposed_tool_call"]),
            ChatMessageTool.model_validate(record["auditor_supplied_result"]),
        )
    result = {
        "source": str(p),
        "seed_instruction": data["seed_instruction"],
        "governed": False,
        "arm": "exact-proposal-replay-control",
        "model_roles": "no new model calls; replay of original governed target proposals",
        "records": gate.records,
    }
    (args.output / p.name).write_text(json.dumps(result, default=str, indent=2))
print("Exact-proposal replay saved")
