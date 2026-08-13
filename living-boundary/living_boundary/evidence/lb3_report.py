"""Rendering for an LB-3 run.

Same discipline as the three phases before it. Two things specific to LB-3 are
made hard to skip past, because both are ways a transfer result gets overstated
in the telling:

  · THE FULL MATRIX IS PRINTED. Every grammar against every environment,
    including the ones that collapsed and the ones that abstained. A transfer
    claim quoted from the environments where it worked is not a transfer claim.

  · THE RIVALS ARE PRINTED BESIDE THE CANDIDATE. If a cheaper explanation
    retains almost as much, that has to be visible in the same table rather
    than buried in an appendix, because it is the fact that decides whether the
    result means anything.
"""

from __future__ import annotations

_RULE = "─" * 78


def _pct(value) -> str:
    if value is None:
        return "  n/a"
    return f"{value:+.3f}"


def _outcome_mark(outcome: str) -> str:
    return {"TRANSFERRED": "OK  ", "DEGRADED": "PART", "COLLAPSED": "GONE",
            "ABSTAINED": "ABST"}.get(outcome, "??  ")


def _matrix_rows(result):
    """(grammar, env_id, outcome, retention, f1, alignment cost) per cell."""
    rows = []
    for grammar in sorted(result["grammars"]):
        transfer = result["grammars"][grammar].get("transfer", {})
        for env_id in sorted(transfer):
            cell = transfer[env_id]
            rows.append((
                grammar, env_id, cell["outcome"],
                cell.get("retention", {}).get("retention"),
                cell.get("performance", {}).get("f1"),
                cell.get("alignment_cost"),
            ))
    return rows


def lb3_console_report(result: dict) -> str:
    out = []
    out.append("LB-3 Cross-Environment Structural Transfer")
    out.append(_RULE)
    out.append(f"Run ID:            {result['run_id']}")
    out.append(f"Seed:              {result['seed']}")
    out.append(f"Primary grammar:   {result['primary_grammar']}")
    out.append(f"Commit:            {result['code_provenance']['commit'][:12]}")
    out.append("")
    out.append(f"Question: {result['question']}")
    out.append("")

    environments = result["environments"]
    out.append("Environments")
    out.append(_RULE)
    for env_id in sorted(environments):
        row = environments[env_id]
        out.append(f"  {env_id}  {row.get('condition', ''):<30} "
                   f"rule={row.get('rule', '')}")
    out.append("")

    out.append("Transfer matrix  (retention of the discovery-side advantage)")
    out.append(_RULE)
    out.append(f"  {'grammar':<12} {'env':<8} {'outcome':<12} "
               f"{'retention':>10} {'F1':>8} {'align':>8}")
    for grammar, env_id, outcome, keep, f1, cost in _matrix_rows(result):
        out.append(f"  {grammar:<12} {env_id:<8} "
                   f"[{_outcome_mark(outcome)}]{outcome[:1]:<5} "
                   f"{_pct(keep):>10} {_pct(f1):>8} {_pct(cost):>8}")
    out.append("")

    grammar = result["primary_grammar"]
    if grammar:
        primary = result["grammars"][grammar]
        candidate = primary["candidate"]
        out.append(f"Candidate ({grammar}, {candidate['literal_count']} literals, "
                   f"structure {candidate['structure_hash']})")
        out.append(_RULE)
        for literal in candidate["literals"]:
            out.append(f"    {literal}")
        held = candidate["discovery_metrics"]["held_out"]
        out.append(f"  discovery held-out F1 {held['f1']:.4f} "
                   f"(baseline {held['baseline_f1']:.4f}, "
                   f"lift {held['lift']:+.4f})")
        summary = primary["expected_transfer_summary"]
        out.append(f"  retention across unseen environments: "
                   f"min {summary.get('minimum')} / mean {summary.get('mean')} "
                   f"(worst: {summary.get('worst_environment')})")
        out.append("")

        battery = primary["invariance"]
        out.append("Invariance")
        out.append(_RULE)
        for name, row in sorted(battery.get("preserving", {}).items()):
            flag = ("   <- the ALIGNMENT broke, not the candidate: this cost "
                    "would have triggered abstention in an environment"
                    if row.get("realignment_would_have_abstained") else "")
            out.append(f"  preserving   {name:<28} agreement "
                       f"{row['agreement']:.4f}  realign "
                       f"{row.get('realignment_cost', 0.0):.3f}{flag}")
        for name, row in sorted(battery.get("destructive", {}).items()):
            out.append(f"  destructive  {name:<28} extinction "
                       f"{row['extinction']:.4f}")
        for name, row in sorted(
                battery.get("partially_destructive_ungated", {}).items()):
            out.append(f"  ungated      {name:<28} extinction "
                       f"{row['extinction']:.4f}  (measured, not gated — see "
                       f"transfer/invariance.py)")
        out.append("")

    rivals = result["competing_hypotheses"]
    if rivals:
        out.append("Competing explanations  (mean retention where transfer is "
                   "expected)")
        out.append(_RULE)
        ranked = sorted(rivals.items(),
                        key=lambda kv: -kv[1]["expected_transfer_summary"]
                        .get("mean", 0.0))
        for name, row in ranked:
            summary = row["expected_transfer_summary"]
            out.append(f"  {name:<22} mean {summary.get('mean', 0.0):+.3f}  "
                       f"discovery lift {row['discovery']['lift']:+.3f}  "
                       f"{row['description']}")
        out.append("")

    out.append("Falsification")
    out.append(_RULE)
    for check in result["falsification"]:
        mark = "PASS" if check.get("passed") else "FAIL"
        out.append(f"  [{mark}] {check['check']}")
        out.append(f"         {check.get('detail', '')}")
    out.append("")

    replication = result["replication"]
    out.append("Replication")
    out.append(_RULE)
    out.append(f"  {replication['detail']}")
    for row in replication["per_seed"]:
        out.append(f"    seed {row['seed']}: grammar={row['grammar']} "
                   f"structure={row['structure_hash']} "
                   f"min={row['minimum_retention']} mean={row['mean_retention']} "
                   f"invariance={'PASS' if row.get('invariance_would_pass') else 'FAIL'} "
                   f"realign_max={row.get('max_realignment_cost')}")
    out.append("")

    reachable = result["authority"]["production_authority_reachable"]
    mutated = not result["grammar_immutability"]["unchanged"]
    out.append(f"Production authority reachable:    {'YES' if reachable else 'NO'}")
    out.append(f"Feature grammar mutated by LB-3:   {'YES' if mutated else 'NO'}")
    out.append("Production ruleset hash unchanged: "
               f"{result['production_fingerprint']['unchanged']}")
    out.append("")

    verdict = result["verdict"]
    out.append("Acceptance criteria:")
    for criterion in verdict.get("criteria", []):
        out.append(f"  [{'PASS' if criterion['passed'] else 'FAIL'}] "
                   f"{criterion['criterion']}")
        out.append(f"       {criterion['detail']}")
    out.append("")
    out.append(f"Verdict:  {verdict['decision']}")
    out.append(_RULE)
    out.append(f"Evidence: {result.get('artifact_dir', '(not persisted)')}")
    chain = result["evidence"]["chain"]
    out.append(f"Evidence chain head: {chain['head'][:16]} "
               f"({chain['records']} records, verified={chain['verified']})")
    return "\n".join(out)


def lb3_markdown_report(result: dict) -> str:
    lines = []
    lines.append(f"# LB-3 Cross-Environment Structural Transfer — {result['run_id']}")
    lines.append("")
    lines.append(f"**RESULT: {result['verdict']['decision']}**")
    lines.append("")
    lines.append(f"> {result['question']}")
    lines.append("")
    lines.append("| field | value |")
    lines.append("|---|---|")
    lines.append(f"| seed | {result['seed']} |")
    lines.append(f"| primary grammar | `{result['primary_grammar']}` |")
    lines.append(f"| world version | `{result['world_version']}` |")
    lines.append(f"| generated at | {result['generated_at']} |")
    lines.append(f"| commit | `{result['code_provenance']['commit']}` |")
    lines.append("| evidence chain head | "
                 f"`{result['evidence']['chain']['head']}` |")
    lines.append("")

    lines.append("## Environments")
    lines.append("")
    lines.append("| id | condition | description | structure |")
    lines.append("|---|---|---|---|")
    for env_id in sorted(result["environments"]):
        row = result["environments"][env_id]
        lines.append(f"| `{env_id}` | {row.get('condition', '')} | "
                     f"{row.get('description', '')} | "
                     f"{row.get('structure', '')} |")
    lines.append("")

    lines.append("## Transfer matrix")
    lines.append("")
    lines.append("| grammar | environment | outcome | retention | F1 | "
                 "alignment cost |")
    lines.append("|---|---|---|---|---|---|")
    for grammar, env_id, outcome, keep, f1, cost in _matrix_rows(result):
        lines.append(f"| `{grammar}` | `{env_id}` | **{outcome}** | "
                     f"{_pct(keep)} | {_pct(f1)} | {_pct(cost)} |")
    lines.append("")

    grammar = result["primary_grammar"]
    if grammar:
        primary = result["grammars"][grammar]
        candidate = primary["candidate"]
        lines.append(f"## Candidate — `{grammar}`")
        lines.append("")
        lines.append(f"Structure `{candidate['structure_hash']}`, "
                     f"{candidate['literal_count']} literals, status "
                     f"`{candidate['production_authority']}` production "
                     f"authority.")
        lines.append("")
        for literal in candidate["literals"]:
            lines.append(f"- `{literal}`")
        lines.append("")
        summary = primary["expected_transfer_summary"]
        lines.append(f"Retention across unseen environments where transfer was "
                     f"expected: **min {summary.get('minimum')}**, mean "
                     f"{summary.get('mean')} (worst "
                     f"`{summary.get('worst_environment')}`).")
        lines.append("")
        lines.append("### Known failure modes, measured")
        lines.append("")
        for mode in primary["known_failure_modes"]:
            label = mode.get("environment") or mode.get("transform")
            lines.append(f"- `{label}` — {mode.get('reason', '')}")
        lines.append("")
        lines.append("### Invariance")
        lines.append("")
        lines.append("| transform | kind | value |")
        lines.append("|---|---|---|")
        for name, row in sorted(primary["invariance"].get("preserving", {}).items()):
            note = (" — realignment cost "
                    f"{row.get('realignment_cost', 0.0):.3f}"
                    + (", above the abstention ceiling"
                       if row.get("realignment_would_have_abstained") else ""))
            lines.append(f"| `{name}` | preserving (agreement) | "
                         f"{row['agreement']:.4f}{note} |")
        for name, row in sorted(primary["invariance"].get("destructive", {}).items()):
            lines.append(f"| `{name}` | destructive (extinction) | "
                         f"{row['extinction']:.4f} |")
        for name, row in sorted(primary["invariance"]
                                .get("partially_destructive_ungated", {}).items()):
            lines.append(f"| `{name}` | ungated, measured only | "
                         f"{row['extinction']:.4f} |")
        lines.append("")

    lines.append("## Competing explanations")
    lines.append("")
    lines.append("| hypothesis | mean retention | discovery lift | what it says |")
    lines.append("|---|---|---|---|")
    ranked = sorted(result["competing_hypotheses"].items(),
                    key=lambda kv: -kv[1]["expected_transfer_summary"]
                    .get("mean", 0.0))
    for name, row in ranked:
        summary = row["expected_transfer_summary"]
        lines.append(f"| `{name}` | {summary.get('mean', 0.0):+.3f} | "
                     f"{row['discovery']['lift']:+.3f} | {row['description']} |")
    lines.append("")

    lines.append("## Falsification")
    lines.append("")
    for check in result["falsification"]:
        mark = "PASS" if check.get("passed") else "FAIL"
        lines.append(f"- **{mark}** `{check['check']}` — "
                     f"{check.get('detail', '')}")
    lines.append("")

    lines.append("## Replication")
    lines.append("")
    lines.append(result["replication"]["detail"])
    lines.append("")
    lines.append("| seed | grammar | structure | min retention | mean retention "
                 "| invariance | max re-alignment cost |")
    lines.append("|---|---|---|---|---|---|---|")
    for row in result["replication"]["per_seed"]:
        lines.append(f"| {row['seed']} | `{row['grammar']}` | "
                     f"`{row['structure_hash']}` | {row['minimum_retention']} | "
                     f"{row['mean_retention']} | "
                     f"{'PASS' if row.get('invariance_would_pass') else 'FAIL'} | "
                     f"{row.get('max_realignment_cost')} |")
    lines.append("")

    lines.append("## Authority")
    lines.append("")
    lines.append("- production authority reachable: "
                 f"**{result['authority']['production_authority_reachable']}**")
    lines.append("- feature grammar unchanged: "
                 f"**{result['grammar_immutability']['unchanged']}**")
    lines.append("- production ruleset hash unchanged: "
                 f"**{result['production_fingerprint']['unchanged']}**")
    proposal = result.get("proposal")
    lines.append("- proposal status: "
                 f"**{proposal['status'] if proposal else 'none emitted'}**")
    lines.append("")

    lines.append("## Acceptance criteria")
    lines.append("")
    lines.append("| criterion | result | detail |")
    lines.append("|---|---|---|")
    for criterion in result["verdict"].get("criteria", []):
        lines.append(f"| `{criterion['criterion']}` | "
                     f"{'PASS' if criterion['passed'] else 'FAIL'} | "
                     f"{criterion['detail']} |")
    lines.append("")
    lines.append(f"Thresholds: `{result['verdict'].get('thresholds', {})}`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Reproduce: `cd living-boundary && "
                 "python -m living_boundary.run_lb3 --seed "
                 f"{result['seed']}`")
    return "\n".join(lines)
