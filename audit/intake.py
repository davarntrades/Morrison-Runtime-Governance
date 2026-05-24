"""Audit intake — parse and validate a client AuditPackage.

The client supplies (no model access required):
  - org name
  - target domains (labels)
  - tool definitions (informational: name, description, args schema)
  - trajectories: recorded / sample tool-call plans
  - optional allowlists (internal url hosts / email domains)
  - optional `use_hardening` toggle (decode / lift / recursion pre-pass)

Parsing is fail-clear: malformed input raises a precise error rather
than silently degrading."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from runtime_eval.governance.omega_registry import OmegaRegistry


@dataclass
class ToolDef:
    name: str
    description: str = ""
    args_schema: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"name": self.name, "description": self.description,
                "args_schema": self.args_schema}


@dataclass
class TrajectorySpec:
    id: str
    steps: list                       # list[{"tool": str, "args": dict}]
    expected: Optional[str] = None    # optional client expectation: PERMIT/BLOCK
    note: str = ""

    def calls(self) -> list:
        return [{"tool": s.get("tool"), "args": s.get("args", {}) or {}}
                for s in self.steps]


@dataclass
class AuditPackage:
    org: str
    domains: list
    tools: list = field(default_factory=list)            # list[ToolDef]
    trajectories: list = field(default_factory=list)      # list[TrajectorySpec]
    internal_url_hosts: tuple = ()
    internal_email_domains: tuple = ()
    use_hardening: bool = True
    as_of: str = "unspecified"        # client-supplied report date (kept
                                       # out of the deterministic body)

    def tool_names(self) -> list:
        return [t.name for t in self.tools]


def _require(cond, msg):
    if not cond:
        raise ValueError(f"AuditPackage: {msg}")


def parse_package(data: dict) -> AuditPackage:
    _require(isinstance(data, dict), "top-level must be an object")
    org = str(data.get("org", "")).strip()
    _require(org, "missing 'org'")

    domains = data.get("domains") or []
    _require(isinstance(domains, list) and domains,
             "'domains' must be a non-empty list of domain labels")
    known = set(OmegaRegistry.known())
    bad = [d for d in domains if d not in known]
    _require(not bad, f"unknown domain label(s) {bad}; known: {sorted(known)}")

    tools = []
    for t in data.get("tools", []) or []:
        _require(isinstance(t, dict) and t.get("name"),
                 "each tool needs a 'name'")
        tools.append(ToolDef(name=str(t["name"]),
                             description=str(t.get("description", "")),
                             args_schema=t.get("args_schema", {}) or {}))

    trajectories = []
    raw_trajs = data.get("trajectories") or []
    _require(isinstance(raw_trajs, list) and raw_trajs,
             "'trajectories' must be a non-empty list")
    seen_ids = set()
    for i, tr in enumerate(raw_trajs):
        _require(isinstance(tr, dict), f"trajectory[{i}] must be an object")
        tid = str(tr.get("id") or f"trajectory_{i}")
        _require(tid not in seen_ids, f"duplicate trajectory id '{tid}'")
        seen_ids.add(tid)
        steps = tr.get("steps")
        _require(isinstance(steps, list) and steps,
                 f"trajectory '{tid}' needs a non-empty 'steps' list")
        for j, s in enumerate(steps):
            _require(isinstance(s, dict) and s.get("tool"),
                     f"trajectory '{tid}' step[{j}] needs a 'tool'")
            _require(isinstance(s.get("args", {}), dict),
                     f"trajectory '{tid}' step[{j}] 'args' must be an object")
        expected = tr.get("expected")
        if expected is not None:
            expected = str(expected).upper()
            _require(expected in ("PERMIT", "BLOCK"),
                     f"trajectory '{tid}' expected must be PERMIT or BLOCK")
        trajectories.append(TrajectorySpec(
            id=tid, steps=steps, expected=expected,
            note=str(tr.get("note", ""))))

    return AuditPackage(
        org=org, domains=list(domains), tools=tools,
        trajectories=trajectories,
        internal_url_hosts=tuple(data.get("internal_url_hosts", []) or []),
        internal_email_domains=tuple(
            data.get("internal_email_domains", []) or []),
        use_hardening=bool(data.get("use_hardening", True)),
        as_of=str(data.get("as_of", "unspecified")))


def load_package(path) -> AuditPackage:
    raw = Path(path).read_text(encoding="utf-8")
    return parse_package(json.loads(raw))
