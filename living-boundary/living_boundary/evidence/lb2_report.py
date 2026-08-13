"""Rendering for an LB-2 run.

Same discipline as LB-0 and LB-1: numbers and eliminations, every acceptance
criterion shown whether it passed or failed, no failure summarised as anything
else. Two additions specific to this phase.

The verdict ladder has three abstaining outcomes, so the report shows the
ABSTENTION RATE as a headline rather than hiding it inside an accuracy figure —
a pipeline that abstains on nothing has not been tested on the cases that matter.

And it prints, in the per-scenario table, the two numbers that carry the whole
observational argument: the share of disagreement the telemetry explains, and
the share it does not. Those replace LB-1's probe columns, and a reader should
be able to see them doing the work.
"""

from __future__ import annotations

_RULE = "─" * 76


def _fmt(value, places: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{places}f}"
    return str(value)


def _interval(payload) -> str:
    if not payload:
        return "n/a"
    return (f"{payload['point']:.3f} "
            f"[{payload['lower']:.3f}, {payload['upper']:.3f}]")


def lb2_console_report(result: dict) -> str:
    out = []
    out.append("LB-2 Observational Representation Adequacy")
    out.append(_RULE)
    out.append(f"Run ID:                  {result['run_id']}")
    out.append(f"Seed:                    {result['seed']}")
    out.append(f"Representation on trial: {result['representation_under_test']}")
    out.append(f"Replay used:             {result['replay_used']}")
    out.append(f"Commit:                  {result['code_provenance']['commit'][:12]}")
    out.append("")
    out.append(f"Question: {result['question']}")
    out.append("")

    for name, record in sorted(result["scenarios"].items()):
        expected = record["expectations"].get("expected_verdict")
        assessment = record["assessment"]
        strata = record["strata"]
        mark = "OK " if assessment["verdict"] == expected else "MISS"
        out.append(_RULE)
        out.append(f"[{mark}] {name}")
        out.append(f"       verdict {assessment['verdict']}  "
                   f"(constructed as {expected})")
        out.append(f"       archive: {strata['trajectories']} sealed "
                   f"trajectories, integrity seals_broken="
                   f"{record['integrity']['seals_broken']}, incompleteness="
                   f"{record['integrity']['field_incompleteness_rate']}")
        out.append(f"       collision rate      {_interval(strata['collision_rate'])}")
        out.append(f"       resolvable by record {_interval(strata['resolvable_fraction'])}")
        out.append(f"       error floors: current grammar "
                   f"{strata['irreducible_error_rate_current_grammar']:.3f}, "
                   f"any representation from this telemetry "
                   f"{strata['telemetry_floor']:.3f}")
        for elimination in assessment["eliminations"]:
            out.append(f"       - {elimination}")
        localisation = assessment.get("localisation") or {}
        if localisation.get("localised"):
            association = localisation["association"]
            out.append(f"       localised to {localisation['observable']!r} "
                       f"via {localisation['exposure']!r} "
                       f"({localisation['matching']} matching): risk difference "
                       f"{association['pooled_risk_difference']:+.3f} "
                       f"[{association['ci_lower']:+.3f}, "
                       f"{association['ci_upper']:+.3f}] over "
                       f"{association['strata_informative']} strata / "
                       f"{association['matched_trajectories']} trajectories")
        elif localisation.get("reason"):
            out.append(f"       localisation declined: {localisation['reason']}")
        recovery = record.get("simulated_recovery")
        if recovery:
            out.append(f"       simulated recovery: held-out F1 "
                       f"{_fmt(recovery['base_held_out']['f1'])} -> "
                       f"{_fmt(recovery['extended_held_out']['f1'])} "
                       f"({recovery['f1_gain']:+.4f}), executed_anything="
                       f"{recovery['executed_anything']}")
        out.append(f"       claims: insufficient="
                   f"{assessment['claims']['representation_is_insufficient']}, "
                   f"observable named="
                   f"{assessment['claims']['specific_observable_is_missing']}, "
                   f"causation={assessment['claims']['causation_established']}")
    out.append(_RULE)
    out.append("")

    verdict = result["verdict"]
    out.append(f"Classification accuracy: {verdict['classification_accuracy']}")
    out.append(f"Abstention rate:         {verdict['abstention_rate']}")
    out.append("")
    out.append("Production authority reachable:    {}".format(
        "YES" if result["authority"]["production_authority_reachable"] else "NO"))
    out.append("Feature grammar mutated by LB-2:   {}".format(
        "YES" if not result["grammar_immutability"]["unchanged"] else "NO"))
    out.append("Production ruleset hash unchanged: {}".format(
        result["production_fingerprint"]["unchanged"]))
    out.append("")

    out.append("Acceptance criteria:")
    for criterion in verdict["criteria"]:
        out.append(f"  [{'PASS' if criterion['passed'] else 'FAIL'}] "
                   f"{criterion['criterion']}")
        out.append(f"       {criterion['detail']}")
    out.append("")
    out.append(f"Verdict:  {verdict['decision']}")
    out.append(_RULE)
    out.append(f"Evidence: {result.get('artifact_dir', '(not persisted)')}")
    out.append("Evidence chain head: {} ({} records, verified={})".format(
        result["evidence"]["chain"]["head"][:16],
        result["evidence"]["chain"]["records"],
        result["evidence"]["chain"]["verified"]))
    return "\n".join(out)


def lb2_markdown_report(result: dict) -> str:
    lines = []
    lines.append(f"# LB-2 Observational Representation Adequacy — {result['run_id']}")
    lines.append("")
    lines.append(f"**RESULT: {result['verdict']['decision']}**")
    lines.append("")
    lines.append(f"> {result['question']}")
    lines.append("")
    lines.append(f"**Replay used: {result['replay_used']}.** No trajectory was "
                 f"re-executed, no provider was contacted, and the scenario "
                 f"objects that decided these outcomes were destroyed before "
                 f"analysis began.")
    lines.append("")
    lines.append("| field | value |")
    lines.append("|---|---|")
    lines.append(f"| seed | {result['seed']} |")
    lines.append(f"| representation on trial | `{result['representation_under_test']}` |")
    lines.append(f"| generated at | {result['generated_at']} |")
    lines.append(f"| commit | `{result['code_provenance']['commit']}` |")
    lines.append(f"| classification accuracy | {result['verdict']['classification_accuracy']} |")
    lines.append(f"| abstention rate | {result['verdict']['abstention_rate']} |")
    lines.append(f"| evidence chain head | `{result['evidence']['chain']['head']}` |")
    lines.append("")

    lines.append("## Verdict per scenario")
    lines.append("")
    lines.append("| scenario | constructed as | verdict | collision rate | "
                 "resolvable by record | localised |")
    lines.append("|---|---|---|---|---|---|")
    for name, record in sorted(result["scenarios"].items()):
        expected = record["expectations"].get("expected_verdict")
        strata = record["strata"]
        localisation = record["assessment"].get("localisation") or {}
        lines.append(
            f"| `{name}` | {expected} | **{record['assessment']['verdict']}** | "
            f"{_interval(strata['collision_rate'])} | "
            f"{_interval(strata['resolvable_fraction'])} | "
            f"{localisation.get('observable') or '—'} |")
    lines.append("")
    lines.append("The two middle columns replace LB-1's replay probe. Collision "
                 "rate says the grammar cannot separate these trajectories; "
                 "*resolvable by record* says whether the telemetry could.")
    lines.append("")

    for name, record in sorted(result["scenarios"].items()):
        assessment = record["assessment"]
        lines.append(f"### {name}")
        lines.append("")
        lines.append(record["scenario"]["description"])
        lines.append("")
        lines.append(f"**{assessment['verdict']}** — {assessment['reason']}")
        lines.append("")
        lines.append("Eliminations, in the order applied:")
        lines.append("")
        for elimination in assessment["eliminations"]:
            lines.append(f"1. {elimination}")
        lines.append("")
        lines.append(f"Claims: `{assessment['claims']}`")
        lines.append("")
        if record.get("simulated_recovery"):
            recovery = record["simulated_recovery"]
            lines.append(
                f"Simulated recovery: reading `{recovery['observable']}` moves "
                f"held-out F1 from {recovery['base_held_out']['f1']} to "
                f"{recovery['extended_held_out']['f1']} "
                f"(**{recovery['f1_gain']:+.4f}**). {recovery['note']}")
            lines.append("")

    lines.append("## Authority")
    lines.append("")
    lines.append(f"- production authority reachable: "
                 f"**{result['authority']['production_authority_reachable']}**")
    lines.append(f"- feature grammar unchanged: "
                 f"**{result['grammar_immutability']['unchanged']}**")
    lines.append(f"- production ruleset hash unchanged: "
                 f"**{result['production_fingerprint']['unchanged']}**")
    lines.append("")

    lines.append("## Acceptance criteria")
    lines.append("")
    lines.append("| criterion | result | detail |")
    lines.append("|---|---|---|")
    for criterion in result["verdict"]["criteria"]:
        lines.append(f"| `{criterion['criterion']}` | "
                     f"{'PASS' if criterion['passed'] else 'FAIL'} | "
                     f"{criterion['detail'].replace('|', '/')} |")
    lines.append("")
    lines.append(f"Thresholds: `{result['verdict']['thresholds']}`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"Reproduce: `cd living-boundary && python -m "
                 f"living_boundary.run_lb2 --seed {result['seed']}`")
    lines.append("")
    return "\n".join(lines)
