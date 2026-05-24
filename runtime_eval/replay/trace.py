"""JSONL replay trace I/O. Deterministic: same inputs → byte-identical
output files (no timestamps, no nondeterministic field order).

Wall-clock fields (`latency_ms` on the DecisionRecord and
`eval_time_ms` / `eval_number` injected by GovernanceLayer._run) are
stripped by default so byte-identical replay holds. Pass
`deterministic=False` to keep them for ops-style audit logs."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Optional

from runtime_eval.governance.decision_trace import DecisionRecord, DecisionTrace


_WALL_CLOCK_FIELDS = ("latency_ms",)
_WALL_CLOCK_METADATA = ("eval_time_ms", "eval_number")


def _record_to_deterministic_json(rec: DecisionRecord) -> str:
    d = asdict(rec)
    for f in _WALL_CLOCK_FIELDS:
        d.pop(f, None)
    md = d.get("metadata") or {}
    if isinstance(md, dict):
        for f in _WALL_CLOCK_METADATA:
            md.pop(f, None)
    return json.dumps(d, sort_keys=True, ensure_ascii=False)


class TraceWriter:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def write(self, trace: DecisionTrace,
              extra_header: Optional[dict] = None,
              deterministic: bool = True) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines: list[str] = []
        if extra_header:
            lines.append(json.dumps({"__header__": extra_header},
                                     sort_keys=True, ensure_ascii=False))
        if deterministic:
            lines.extend(_record_to_deterministic_json(r)
                         for r in trace.records)
        else:
            lines.extend(r.to_json() for r in trace.records)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TraceReader:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def read(self) -> tuple[Optional[dict], list[dict]]:
        header: Optional[dict] = None
        rows: list[dict] = []
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
