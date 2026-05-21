"""Semantic lifting — structural, ontology-based, deterministic.

Given a call, returns an augmented copy carrying canonical-tool and
capability fields. This is NOT semantic moderation: it's a deterministic
ontology lookup followed by capability inference. The lifted call is
what the reachability rules see — paraphrases of forbidden operations
("backup_externally", "facilitate_transfer") then route through the
canonical Ω rules ("http_request", "transfer") structurally.

Output preserves the original tool name so audit/replay shows what the
planner actually emitted; the canonical fields are added under
`_lifted_*` keys plus the canonical tool name is exposed as a peer
`tool_canonical` field that downstream layers can prefer.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Optional

from runtime_eval.governance.action_ontology import lookup, OntologyEntry


# Reuse the structural capability inference from the existing core.
from morrison_governance.forecasting import infer_capabilities


@dataclass
class LiftReport:
    matched_ontology: bool = False
    canonical_tool: Optional[str] = None
    capabilities: list = field(default_factory=list)
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "matched_ontology": self.matched_ontology,
            "canonical_tool": self.canonical_tool,
            "capabilities": list(self.capabilities),
            "notes": self.notes,
        }


def lift(call: dict) -> tuple[dict, LiftReport]:
    """Return (lifted_call, report). The lifted call carries:
      - the original `tool` and `args` (unchanged)
      - `tool_canonical`         — the ontology's canonical tool name
      - `_lifted_capabilities`   — sorted list of capability tags
      - `_lifted_notes`          — short audit string
    """
    out = copy.deepcopy(call)
    report = LiftReport()

    name = str(out.get("tool", "")).strip().lower()
    entry: Optional[OntologyEntry] = lookup(name)

    capabilities = sorted(infer_capabilities(out))
    if entry is not None:
        report.matched_ontology = True
        report.canonical_tool = entry.canonical_tool
        report.notes = entry.notes
        # the canonical capability augments — never replaces — the
        # structurally-inferred set.
        capabilities = sorted(set(capabilities) | {entry.capability})
        out["tool_canonical"] = entry.canonical_tool
        # operational tool field is rewritten to the canonical so the
        # reachability rules see the canonical action; the audit log
        # preserves the original via DecisionRecord.proposed.
        if entry.canonical_tool != name:
            out["tool_original"] = call.get("tool")
            out["tool"] = entry.canonical_tool

    report.capabilities = capabilities
    out["_lifted_capabilities"] = capabilities
    if report.notes:
        out["_lifted_notes"] = report.notes
    return out, report
