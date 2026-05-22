"""Deterministic JSONL replay for multi-agent runs.

Each record carries the fields the spec requires (agent_id,
local_history, shared_env_state, proposed_tool_call,
governance_decision, omega_domain, joint_trajectory_hash, reason).
Wall-clock latency is NOT written → byte-identical replay holds."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


class TraceWriter:
    def __init__(self, path):
        self.path = Path(path)

    def write(self, run_result, extra_header: Optional[dict] = None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        header = {"scenario": run_result.scenario, "mode": run_result.mode}
        if extra_header:
            header.update(extra_header)
        lines.append(json.dumps({"__header__": header}, sort_keys=True,
                                 ensure_ascii=False))
        for rec in run_result.records():
            lines.append(json.dumps(rec, sort_keys=True, ensure_ascii=False))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TraceReader:
    def __init__(self, path):
        self.path = Path(path)

    def read(self):
        header, rows = None, []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict) and "__header__" in obj:
                header = obj["__header__"]
            else:
                rows.append(obj)
        return header, rows
