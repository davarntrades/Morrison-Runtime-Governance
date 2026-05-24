"""
Morrison 48-Hour Runtime Governance Audit toolkit.

Productises the existing reachability engine into the contracted audit
deliverable. An analyst feeds in a client's agent architecture —
tool definitions, recorded / sample tool-call plans, target domains —
and the toolkit produces the six audit deliverables:

  1. Executable trajectory analysis   (every plan extracted + evaluated)
  2. Reachable Ω states               (which forbidden states are reachable)
  3. Blocked vs. permitted paths      (the exact partition, per step)
  4. Audit logs                       (deterministic, layer-attributed JSONL)
  5. Risk summary                     (ranked by reachability × consequence)
  6. Integration recommendations      (middleware placement + Ω config)

No model access is required — the trajectory geometry is evaluated, not
the model weights. Every governance decision delegates to
morrison_governance.GovernanceLayer (A_safe → V2 → V3 → V4 → V4+ → V5 →
V5+), optionally with the runtime_eval hardening pipeline. Deterministic
and replayable; bounded to the trajectories the client supplies.
"""

from audit.intake import (
    AuditPackage, ToolDef, TrajectorySpec, load_package, parse_package,
)
from audit.analyzer import analyze, AuditResult, Finding
from audit.risk import severity_of, rank_findings, SEVERITY_BANDS
from audit.recommend import integration_recommendations
from audit.report import render_markdown, render_findings_json, render_audit_log

__all__ = [
    "AuditPackage", "ToolDef", "TrajectorySpec", "load_package",
    "parse_package",
    "analyze", "AuditResult", "Finding",
    "severity_of", "rank_findings", "SEVERITY_BANDS",
    "integration_recommendations",
    "render_markdown", "render_findings_json", "render_audit_log",
]
