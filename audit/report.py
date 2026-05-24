"""Render the six audit deliverables.

  render_markdown      — the human-readable report (deliverables 1–6)
  render_findings_json — machine-readable findings + summary
  render_audit_log     — deterministic JSONL, one record per governance
                          decision (deliverable 4)

All artifacts are deterministic: no wall-clock, no RNG. The only
date in the report is the client-supplied `as_of` field, kept in a
metadata header so the analytic body remains byte-stable."""

from __future__ import annotations

import json

from audit.risk import rank_findings
from audit.recommend import integration_recommendations


def render_findings_json(result, package) -> str:
    payload = {
        "meta": {"org": result.org, "as_of": package.as_of,
                 "domains": result.domains, "hardening": result.use_hardening,
                 "interface": "morrison-audit/1.0"},
        "summary": result.summary(),
        "findings": [f.as_dict() for f in rank_findings(result.findings)],
        "recommendations": integration_recommendations(result, package),
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)


def render_audit_log(result) -> str:
    """Deliverable 4 — deterministic JSONL, one line per governance
    decision (per step of every trajectory), layer-attributed."""
    lines = []
    for f in result.findings:
        for step in f.per_step:
            lines.append(json.dumps({
                "trajectory_id": f.trajectory_id,
                "step": step["step"], "tool": step["tool"],
                "verdict": step["verdict"], "layer": step["layer"],
                "rule": step["rule"], "executed": step["executed"],
                "trajectory_hash": f.trajectory_hash,
            }, sort_keys=True, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


def _band_emoji(band: str) -> str:
    return {"critical": "■ CRITICAL", "high": "▲ HIGH",
            "medium": "● MEDIUM", "low": "· low", "none": "  none"}.get(
                band, band)


def render_markdown(result, package) -> str:
    s = result.summary()
    ranked = rank_findings(result.findings)
    recs = integration_recommendations(result, package)
    out: list = []

    out.append(f"# Runtime Governance Audit — {result.org}")
    out.append("")
    out.append(f"*As of: {package.as_of} · domains: "
               f"{', '.join(result.domains)} · hardening: "
               f"{'on' if result.use_hardening else 'off'}*")
    out.append("")
    out.append("> Bounded, reproducible analysis of the trajectories "
               "supplied. No model access was required — the trajectory "
               "geometry is evaluated, not the model. This is not a proof "
               "of safety; it reports which forbidden states (Ω) are "
               "reachable from the supplied executable plans.")
    out.append("")

    # Executive summary
    out.append("## Executive summary")
    out.append("")
    out.append(f"- Trajectories analysed: **{s['trajectories']}**")
    out.append(f"- Reach Ω (blocked pre-execution): **{s['blocked']}**")
    out.append(f"- Clear (permitted): **{s['permitted']}**")
    b = s["severity_bands"]
    out.append(f"- Severity: critical **{b['critical']}** · high "
               f"**{b['high']}** · medium **{b['medium']}** · low "
               f"**{b['low']}** · none **{b['none']}**")
    out.append("")

    # 1. Executable trajectory analysis
    out.append("## 1. Executable trajectory analysis")
    out.append("")
    out.append("| Trajectory | Steps | Verdict | Layer | Rule | Severity |")
    out.append("|:--|--:|:--|:--|:--|:--|")
    for f in ranked:
        out.append(f"| `{f.trajectory_id}` | {f.n_steps} | "
                   f"{'BLOCK' if f.blocked else 'PERMIT'} | "
                   f"{f.layer or '—'} | {f.rule or '—'} | "
                   f"{_band_emoji(f.severity_band)} ({f.severity:.2f}) |")
    out.append("")

    # 2. Reachable Ω states
    out.append("## 2. Reachable Ω states")
    out.append("")
    if s["reachable_omega_states"]:
        out.append("Forbidden states reachable from the supplied "
                   "trajectories (each was blocked pre-execution):")
        out.append("")
        out.append("| Ω domain | Rule |")
        out.append("|:--|:--|")
        for r in s["reachable_omega_states"]:
            out.append(f"| {r['omega_domain'] or '—'} | "
                       f"`{r['rule']}` |")
    else:
        out.append("No Ω state was reachable from the supplied "
                   "trajectories under the configured domains.")
    out.append("")

    # 3. Blocked vs permitted paths
    out.append("## 3. Blocked vs. permitted paths")
    out.append("")
    for f in ranked:
        verdict = "BLOCK" if f.blocked else "PERMIT"
        out.append(f"### `{f.trajectory_id}` → **{verdict}**"
                   + (f" at {f.layer} (`{f.rule}`)" if f.blocked else ""))
        out.append("")
        out.append("| Step | Tool | Verdict | Layer | Executed |")
        out.append("|--:|:--|:--|:--|:--:|")
        for st in f.per_step:
            out.append(f"| {st['step']} | `{st['tool']}` | {st['verdict']} | "
                       f"{st['layer']} | {'yes' if st['executed'] else 'no'} |")
        if f.layers_that_would_object:
            out.append("")
            out.append(f"*Layers that would object (no short-circuit): "
                       f"{', '.join(f.layers_that_would_object)}.*")
        if f.expectation_met is False:
            out.append("")
            out.append(f"> ⚠ Client expected **{f.expected}**; governance "
                       f"verdict was **{verdict}** — flagged for review.")
        out.append("")

    # 4. Audit log (pointer)
    out.append("## 4. Audit log")
    out.append("")
    out.append("A deterministic, layer-attributed JSONL log of every "
               "governance decision is provided alongside this report "
               "(`audit_log.jsonl`) and replays byte-identically.")
    out.append("")

    # 5. Risk summary
    out.append("## 5. Risk summary (ranked by reachability × consequence)")
    out.append("")
    ranked_blocked = [f for f in ranked if f.blocked]
    if ranked_blocked:
        out.append("| # | Trajectory | Ω domain | Rule | Severity |")
        out.append("|--:|:--|:--|:--|:--|")
        for i, f in enumerate(ranked_blocked, 1):
            out.append(f"| {i} | `{f.trajectory_id}` | "
                       f"{f.omega_domain or '—'} | `{f.rule or '—'}` | "
                       f"{_band_emoji(f.severity_band)} ({f.severity:.2f}) |")
    else:
        out.append("No reachable Ω states to rank.")
    out.append("")
    out.append("*Severity = consequence (Ω blast radius) × reachability "
               "(how immediately the trajectory reaches it). A "
               "deterministic prioritisation aid, not a probability.*")
    out.append("")

    # 6. Integration recommendations
    out.append("## 6. Integration recommendations")
    out.append("")
    for r in recs:
        out.append(f"- **[{r['priority']}]** {r['recommendation']}  \n"
                   f"  _evidence: {r['evidence']}_")
    out.append("")

    out.append("-----")
    out.append("")
    out.append("*Bounded to the supplied trajectories and configured Ω "
               "domains. Generated by the Morrison Runtime Governance "
               "audit toolkit; governance decisions delegate to the "
               "reachability core (A_safe → V2 → V3 → V4 → V4+ → V5 → "
               "V5+). ℛ(t) ∩ Ω = ∅.*")
    return "\n".join(out)
