"""Markdown tables generated from the run indexes (numbers are never hand-copied)."""

from __future__ import annotations

import json
from pathlib import Path

from experiments.dynamic_omega import governance as G

COUNTS = ["proposed", "unsafe_proposed", "permitted", "unsafe_permitted", "executed",
          "unsafe_executed", "prevented", "detected_after_only", "false_refusals",
          "legit_proposed", "legit_executed", "decided_on_unevaluated_state",
          "executed_on_changed_state", "stale_authority_harm", "representation_mismatch",
          "unmodelled_treated_as_no_effect", "not_established", "escalated"]
SHORT = {"ENFORCEMENT_FAILURE": "FAIL", "PREVENTED": "prevented", "DETECTED_ONLY": "detected-only",
         "SAFE_COMPLETED": "ok", "FALSE_REFUSAL": "false-refusal",
         "ENV_VIOLATION_UNMEDIATED": "env-violation", "NOT_EXERCISED": "NOT EXERCISED"}


def _label(c):
    cond = G.CONDITIONS[c]
    return "%s %s%s" % (cond.number, c, " (exp.)" if cond.experimental else "")


def outcome_matrix(rows: list, conds=None) -> str:
    conds = conds or [c for c in G.ORDER if any(r["condition"] == c for r in rows)]
    cases = []
    for r in rows:
        if r.get("case") not in cases:
            cases.append(r["case"])
    by = {(r["case"], r["condition"]): r for r in rows}
    out = ["| case | " + " | ".join(G.CONDITIONS[c].number for c in conds) + " |",
           "|---|" + "---|" * len(conds)]
    for case in cases:
        cells = []
        for c in conds:
            r = by.get((case, c))
            if r is None:
                cells.append("")
                continue
            cell = SHORT.get(r["outcome"], r["outcome"])
            if r.get("expect") and r["expect"] != r["outcome"]:
                cell += " (pred. %s)" % SHORT.get(r["expect"], r["expect"])
            cells.append(cell)
        out.append("| %s | %s |" % (case, " | ".join(cells)))
    return "\n".join(out)


def condition_totals(rows: list, conds=None) -> str:
    conds = conds or [c for c in G.ORDER if any(r["condition"] == c for r in rows)]
    tot = {c: {k: 0 for k in COUNTS} for c in conds}
    viol = {c: [0, 0, 0] for c in conds}       # runs with final violation, agent-attr., env-only
    outc = {c: {} for c in conds}
    for r in rows:
        c = r["condition"]
        if c not in tot:
            continue
        for k in COUNTS:
            tot[c][k] += int(r.get(k) or 0)
        viol[c][0] += int(bool(r.get("final_violations")))
        viol[c][1] += int(bool(r.get("violations_agent_attributable")))
        viol[c][2] += int(bool(r.get("violations_env_only")))
        outc[c][r["outcome"]] = outc[c].get(r["outcome"], 0) + 1
    hdr = "| metric | " + " | ".join(_label(c) for c in conds) + " |"
    out = [hdr, "|---|" + "---|" * len(conds)]
    for k in COUNTS:
        out.append("| %s | %s |" % (k, " | ".join(str(tot[c][k]) for c in conds)))
    out.append("| runs with a property violated at end | %s |"
               % " | ".join(str(viol[c][0]) for c in conds))
    out.append("| … attributable to the governed agent | %s |"
               % " | ".join(str(viol[c][1]) for c in conds))
    out.append("| … caused only by unmediated environment | %s |"
               % " | ".join(str(viol[c][2]) for c in conds))
    for o in SHORT:
        out.append("| outcome: %s | %s |" % (SHORT[o], " | ".join(str(outc[c].get(o, 0))
                                                                  for c in conds)))
    return "\n".join(out)


def _enrich(rows: list, run_root: Path) -> list:
    """Fill every metric from the run's own summary.json (live indexes are partial)."""
    out = []
    for r in rows:
        summ = json.loads((run_root / r["run_id"] / "summary.json").read_text("utf-8"))
        m = summ["metrics"]
        out.append(dict(r, case=r.get("case") if "task" not in r else r["task"],
                        **{k: m[k] for k in COUNTS + ["final_violations",
                                                      "violations_agent_attributable",
                                                      "violations_env_only", "outcome"]}))
    return out


def outcome_summary(sets: list) -> str:
    """One table: per (set, outcome class) the number of runs, per condition."""
    conds = [c for c in G.ORDER if any(r["condition"] == c for _, rows in sets for r in rows)]
    out = ["| set | outcome | " + " | ".join(G.CONDITIONS[c].number for c in conds) + " |",
           "|---|---|" + "---|" * len(conds)]
    for name, rows in sets:
        for o in SHORT:
            counts = [sum(1 for r in rows if r["condition"] == c and r["outcome"] == o)
                      for c in conds]
            present = [c for c in conds if any(r["condition"] == c for r in rows)]
            if not any(counts) and o != "NOT_EXERCISED":
                continue
            out.append("| %s | %s | %s |" % (name, SHORT[o], " | ".join(
                str(n) if c in present else "n/a" for n, c in zip(counts, conds))))
    return "\n".join(out)


def render(results_dir) -> str:
    root = Path(results_dir)
    parts, sets = [], []
    for name, title in (("controlled-af", "Controlled A-F"),
                        ("controlled-heldout", "Held-out G (targeted at condition 5)")):
        idx = root / name / "controlled_index.json"
        if idx.exists():
            rows = _enrich(json.loads(idx.read_text("utf-8")), root / name)
            sets.append((title.split(" (")[0], rows))
            parts += ["### %s: outcome per case" % title, "", outcome_matrix(rows), "",
                      "### %s: totals per condition (%d runs)" % (title, len(rows)), "",
                      condition_totals(rows), ""]
    live = root / "live-qwen"
    if live.exists():
        rows = []
        for idx in sorted(live.glob("live_index_rep*.json")):
            rows += _enrich(json.loads(idx.read_text("utf-8")), live)
        per_rep = []
        for idx in sorted(live.glob("live_index_rep*.json")):
            per_rep.append("#### %s\n\n%s\n" % (idx.stem, outcome_matrix(
                _enrich(json.loads(idx.read_text("utf-8")), live))))
        sets.append(("Live qwen3:1.7b (5 reps)", rows))
        parts += ["### Live qwen3:1.7b: outcome per task, per repetition", ""] + per_rep + [
            "### Live qwen3:1.7b: totals per condition (%d runs, all repetitions)" % len(rows), "",
            condition_totals(rows), ""]
    head = ["### Outcome classes per condition (runs)", "", outcome_summary(sets), ""]
    return "\n".join(head + parts)


def add_parser(sub) -> None:
    p = sub.add_parser("report", help="print markdown tables from a results directory")
    p.add_argument("--results", required=True)
    p.set_defaults(fn=lambda a: print(render(a.results)) or 0)


def scenario_details(results_dir) -> str:
    """Per case: the scenario definition, then per condition the decision for
    each step, whether it executed, the oracle label and the final state."""
    from experiments.dynamic_omega import scenarios as S
    root = Path(results_dir)
    rows = []
    for name in ("controlled-af", "controlled-heldout"):
        idx = root / name / "controlled_index.json"
        if idx.exists():
            rows += [(name, r) for r in json.loads(idx.read_text("utf-8"))]
    out = []
    for case in S.ALL_CASES:
        mine = [(n, r) for n, r in rows if r["case"] == case.id]
        if not mine:
            continue
        out += ["#### %s: %s" % (case.id, case.title), "",
                "- **actual:** %s" % case.actual, "- **represented:** %s" % case.represented,
                "- **Ω change:** %s" % case.omega_change, "- **invariant:** %s" % case.invariant,
                "- **proposed transition:** %s" % case.transition,
                "- **failure mode:** %s" % (case.failure_class or "n/a"), "",
                "| condition | per step: decision → executed? (oracle label) | refusal mechanism | "
                "violated at end | outcome |", "|---|---|---|---|---|"]
        for c in G.ORDER:
            hit = [(n, r) for n, r in mine if r["condition"] == c]
            if not hit:
                continue
            n, r = hit[0]
            m = json.loads((root / n / r["run_id"] / "summary.json").read_text("utf-8"))["metrics"]
            steps = "; ".join("%s: %s → %s (%s)" % (s["tool"], s["verdict"],
                                                   "executed" if s["executed"] else "not executed",
                                                   s["label_execution"] or s["label_decision"])
                              for s in m["per_step"])
            kinds = ", ".join(sorted({s["refusal_kind"] for s in m["per_step"] if s["refusal_kind"]}))
            if any(s.get("post_verify_divergence") for s in m["per_step"]):
                kinds = (kinds + ", " if kinds else "") + "post-exec divergence detected"
            if m.get("resource_guard_events") and not kinds:
                kinds = "resource guard (deferred/other writer)"
            out.append("| %s | %s | %s | %s | %s |" % (
                _label(c), steps, kinds or "–", ", ".join(m["final_violations"]) or "none",
                SHORT.get(m["outcome"], m["outcome"])))
        out.append("")
    return "\n".join(out)
