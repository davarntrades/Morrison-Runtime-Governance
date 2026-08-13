"""Rendering for an LB-1 run.

Same discipline as the LB-0 report: print the numbers and the eliminations, print
every acceptance criterion whether it passed or failed, and never summarise a
failure as anything else. The eliminations matter especially here — an LB-1
verdict is reached BY ELIMINATION, so a reader who cannot see what was ruled out,
and on what evidence, has been given a conclusion rather than an argument.
"""

from __future__ import annotations

_RULE = "─" * 74


def _fmt(value, places: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{places}f}"
    return str(value)


def lb1_console_report(result: dict) -> str:
    out = []
    out.append("LB-1 Representation Adequacy Experiment")
    out.append(_RULE)
    out.append(f"Run ID:                  {result['run_id']}")
    out.append(f"Seed:                    {result['seed']}")
    out.append(f"Representation on trial: {result['representation_under_test']}")
    out.append(f"Corpus:                  {result['dataset']['dataset_version']} "
               f"(hash {result['dataset']['corpus_hash'][:12]})")
    out.append(f"Commit:                  {result['code_provenance']['commit'][:12]}")
    out.append("")
    out.append(f"Question: {result['question']}")
    out.append("")

    partitions = result["dataset"]["partitions"]
    for name, info in sorted(partitions.items()):
        out.append(f"  {name:<12} {info['trajectories']:>4} trajectories, "
                   f"burst {info['burst_fraction']:.2f}, "
                   f"delegated {info['delegated_fraction']:.2f}")
    out.append("")
    out.append("The SAME corpus is labelled by every environment below, so any")
    out.append("difference in verdict is caused by the environment alone.")
    out.append("")

    for name, record in sorted(result["environments"].items()):
        expected = record["environment_expectations"].get("expected_verdict")
        assessment = record["assessment"]
        collision = record["collision"]
        probe = record["probe"]
        mark = "OK " if assessment["verdict"] == expected else "MISS"
        out.append(_RULE)
        out.append(f"[{mark}] {name}")
        out.append(f"       verdict {assessment['verdict']}  "
                   f"(constructed as {expected})")
        out.append(f"       collisions: {collision['colliding_groups']} of "
                   f"{collision['distinct_feature_signatures']} signatures, "
                   f"{collision['collision_rate']:.2%} of corpus, "
                   f"mean minority fraction "
                   f"{collision['mean_minority_fraction']:.2f}")
        out.append(f"       irreducible error floor for this representation: "
                   f"{collision['irreducible_error_rate']:.2%}")
        out.append(f"       probe: re-run vs record "
                   f"{probe['record_disagreement_rate']:.3f}, "
                   f"re-run vs itself {probe['self_disagreement_rate']:.3f} "
                   f"({probe['sampled']} trajectories)")
        for elimination in assessment["eliminations"]:
            out.append(f"       - {elimination}")
        base = record.get("base_refit", {}).get("held_out", {})
        out.append(f"       current grammar, held-out F1: {_fmt(base.get('f1'))}")

        localisation = record.get("localisation")
        if localisation:
            best = localisation.get("best") or {}
            out.append(f"       localisation: "
                       f"{'nominated ' + str(best.get('observable')) if localisation['localised'] else 'UNLOCALISED'}"
                       f" via family {best.get('family')!r}, resolving "
                       f"{_fmt(best.get('resolution'), 3)} of the disagreement")
            ranked = localisation.get("ranked", [])[:4]
            for entry in ranked:
                out.append(f"         {entry['family']:<24} resolves "
                           f"{entry['resolution']:.3f}")
        recovery = record.get("recovery")
        if recovery:
            out.append(f"       recovery: held-out F1 "
                       f"{_fmt(recovery['base_held_out']['f1'])} -> "
                       f"{_fmt(recovery['extended_held_out']['f1'])} "
                       f"({recovery['f1_gain']:+.4f}) after reading "
                       f"{recovery['observable']!r}")
        proposal = record.get("proposal")
        if proposal:
            out.append(f"       proposal {proposal['proposal_id']} "
                       f"[{proposal['status']}] — missing observable "
                       f"{proposal['missing_observable']!r}")
    out.append(_RULE)
    out.append("")

    authority_state = result["authority"]
    out.append("Production authority reachable:   {}".format(
        "YES" if authority_state["production_authority_reachable"] else "NO"))
    out.append("Feature grammar mutated by LB-1:  {}".format(
        "YES" if not result["grammar_immutability"]["unchanged"] else "NO"))
    out.append("Production ruleset hash unchanged: {}".format(
        result["production_fingerprint"]["unchanged"]))
    out.append("")

    out.append("Acceptance criteria:")
    for criterion in result["verdict"]["criteria"]:
        out.append(f"  [{'PASS' if criterion['passed'] else 'FAIL'}] "
                   f"{criterion['criterion']}")
        out.append(f"       {criterion['detail']}")
    out.append("")
    out.append(f"Verdict:  {result['verdict']['decision']}")
    out.append(_RULE)
    out.append(f"Evidence: {result.get('artifact_dir', '(not persisted)')}")
    out.append("Evidence chain head: {} ({} records, verified={})".format(
        result["evidence"]["chain"]["head"][:16],
        result["evidence"]["chain"]["records"],
        result["evidence"]["chain"]["verified"]))
    return "\n".join(out)


def lb1_markdown_report(result: dict) -> str:
    lines = []
    lines.append(f"# LB-1 Representation Adequacy — {result['run_id']}")
    lines.append("")
    lines.append(f"**RESULT: {result['verdict']['decision']}**")
    lines.append("")
    lines.append(f"> {result['question']}")
    lines.append("")
    lines.append("| field | value |")
    lines.append("|---|---|")
    lines.append(f"| seed | {result['seed']} |")
    lines.append(f"| representation on trial | `{result['representation_under_test']}` |")
    lines.append(f"| corpus hash | `{result['dataset']['corpus_hash'][:16]}` |")
    lines.append(f"| generated at | {result['generated_at']} |")
    lines.append(f"| commit | `{result['code_provenance']['commit']}` |")
    lines.append(f"| evidence chain head | `{result['evidence']['chain']['head']}` |")
    lines.append("")

    lines.append("## Verdict per environment")
    lines.append("")
    lines.append("| environment | constructed as | verdict | collision rate | "
                 "mean minority | re-run vs record | re-run vs self |")
    lines.append("|---|---|---|---|---|---|---|")
    for name, record in sorted(result["environments"].items()):
        expected = record["environment_expectations"].get("expected_verdict")
        assessment = record["assessment"]
        collision = record["collision"]
        probe = record["probe"]
        lines.append(
            f"| {name} | {expected} | **{assessment['verdict']}** | "
            f"{collision['collision_rate']:.3f} | "
            f"{collision['mean_minority_fraction']:.3f} | "
            f"{probe['record_disagreement_rate']:.3f} | "
            f"{probe['self_disagreement_rate']:.3f} |")
    lines.append("")
    lines.append("Note the two columns on the right. Collision rate alone does "
                 "not separate these environments — four of the five collide. "
                 "The probe columns are what does.")
    lines.append("")

    for name, record in sorted(result["environments"].items()):
        lines.append(f"### {name}")
        lines.append("")
        lines.append(f"{record['environment']['description']}")
        lines.append("")
        lines.append(f"**{record['assessment']['verdict']}** — "
                     f"{record['assessment']['reason']}")
        lines.append("")
        lines.append("Eliminations, in the order they were applied:")
        lines.append("")
        for elimination in record["assessment"]["eliminations"]:
            lines.append(f"1. {elimination}")
        lines.append("")
        residual = record["assessment"].get("residual_beyond_noise") or {}
        if residual:
            lines.append(f"Residual beyond estimated noise: `{residual}`")
            lines.append("")
        if record.get("localisation"):
            lines.append("Localisation, ranked:")
            lines.append("")
            lines.append("| family | observable | resolves |")
            lines.append("|---|---|---|")
            for entry in record["localisation"]["ranked"]:
                lines.append(f"| `{entry['family']}` | {entry['observable']} | "
                             f"{entry['resolution']:.3f} |")
            lines.append("")
        if record.get("recovery"):
            recovery = record["recovery"]
            lines.append(
                f"Reading `{recovery['observable']}` raises held-out F1 from "
                f"{recovery['base_held_out']['f1']} to "
                f"{recovery['extended_held_out']['f1']} "
                f"(**{recovery['f1_gain']:+.4f}**).")
            lines.append("")
        if record.get("proposal"):
            lines.append(f"Proposal `{record['proposal']['proposal_id']}` "
                         f"status `{record['proposal']['status']}`, "
                         f"production authority "
                         f"`{record['proposal']['production_authority']}`, "
                         f"grammar-mutation authority "
                         f"`{record['proposal']['grammar_mutation_authority']}`.")
            lines.append("")

    lines.append("## Authority")
    lines.append("")
    lines.append(f"- production authority reachable: "
                 f"**{result['authority']['production_authority_reachable']}**")
    lines.append(f"- feature grammar unchanged across the run: "
                 f"**{result['grammar_immutability']['unchanged']}**")
    lines.append(f"- production ruleset hash unchanged: "
                 f"**{result['production_fingerprint']['unchanged']}**")
    lines.append("")
    lines.append(result["grammar_immutability"]["note"])
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
                 f"living_boundary.run_lb1 --seed {result['seed']}`")
    lines.append("")
    return "\n".join(lines)
