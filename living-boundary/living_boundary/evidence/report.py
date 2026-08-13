"""Human-readable rendering of an LB-0 run.

The report's job is stated in the prototype README: make it possible for
another engineer to determine whether the claimed discovery actually occurred
WITHOUT relying on the model's narrative explanation. So it prints numbers and
predicates, prints every acceptance criterion whether it passed or failed, and
never summarises a failure as anything other than a failure.
"""

from __future__ import annotations

_RULE = "─" * 72


def _fmt(value, places: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return "{:.{}f}".format(value, places)
    return str(value)


def _metrics_block(matrix: dict, indent: str = "  ") -> str:
    lines = [
        f"{indent}Precision:            {_fmt(matrix.get('precision'))}",
        f"{indent}Recall:               {_fmt(matrix.get('recall'))}",
        f"{indent}F1:                   {_fmt(matrix.get('f1'))}",
        f"{indent}False-positive rate:  {_fmt(matrix.get('false_positive_rate'))}",
        f"{indent}False-negative rate:  {_fmt(matrix.get('false_negative_rate'))}",
        "{}tp/fp/tn/fn:          {}/{}/{}/{}".format(
            indent, matrix.get("tp"), matrix.get("fp"), matrix.get("tn"),
            matrix.get("fn")),
    ]
    return "\n".join(lines)


def console_report(result: dict) -> str:
    """The concise report printed by `python -m living_boundary.run_lb0`."""
    candidate = result.get("candidate_primitive")
    gap = result["ontology_gap"]
    falsification = result["falsification"]
    held_out = result["held_out"]
    strengthened = result["held_out_strengthened"]
    verdict = result["verdict"]
    dataset = result["dataset"]

    out = []
    out.append("LB-0 Living Boundary Experiment")
    out.append(_RULE)
    out.append(f"Run ID:               {result['run_id']}")
    out.append(f"Seed:                 {result['seed']}")
    out.append("Dataset:              {} (hash {})".format(
        dataset["dataset_version"], dataset["dataset_hash"][:12]))
    out.append(f"Baseline ontology:    {result['ontology']['ontology_version']}")
    out.append(f"Commit:               {result['code_provenance']['commit'][:12]}")
    out.append("")

    out.append("Trajectories:")
    for name, info in sorted(dataset["splits"].items()):
        out.append("  {:<12} {:>5} trajectories, {:>4} unsafe ({:.1%})".format(
            name, info["trajectories"], info["unsafe"], info["unsafe_rate"]))
    out.append("")

    out.append("Baseline ontology (held-out):")
    out.append(_metrics_block(result["baseline_metrics"]["held_out"]))
    out.append("")
    out.append("Strengthened baseline (held-out, + egress-after-read heuristic):")
    out.append(_metrics_block(result["strengthened_metrics"]["held_out"]))
    out.append("")

    out.append(f"Ontology gap detected: {'YES' if gap['detected'] else 'NO'}")
    out.append(f"  {gap['reason']}")
    out.append("  Unexplained unsafe trajectories: {} of {}".format(
        gap["residual_unsafe"], gap["total_unsafe"]))
    out.append(f"  Affected domains: {', '.join(gap['affected_domains']) or '(none)'}")
    out.append("")

    if not candidate:
        out.append("Candidate primitive:   NONE PRODUCED")
    else:
        out.append("Candidate primitive:   {} [{}]".format(
            candidate["candidate_id"], candidate["status"]))
        out.append(f"  Name:                {candidate['name']}")
        out.append(f"  Structure hash:      {candidate['structure_hash'][:16]}")
        out.append(f"  Supporting traces:   {candidate['supporting_traces']}")
        out.append("  Observed variables:  {}".format(
            ", ".join(candidate["observed_variables"])))
        out.append(f"  Conditions ({len(candidate['literals'])}):")
        for index, literal in enumerate(candidate["literals"], start=1):
            out.append(f"    {index}. {literal['description']}")
            out.append(f"       [{literal['name']}]")
        out.append("")
        out.append("Hypothesis:")
        out.append(f"  {candidate['hypothesis']}")
        out.append("")

    out.append("Falsification:         {}".format(
        "PASS" if falsification["passed"] else "FAIL"))
    out.append(f"  Cases generated:     {falsification['cases_generated']}")
    for name, stats in sorted(falsification.get("per_literal", {}).items()):
        out.append("  ablate {:<48} {:>3} cases  agreement {}".format(
            name[:48], stats["cases"], _fmt(stats["agreement"], 3)))
    for name, stats in sorted(falsification.get("per_control", {}).items()):
        out.append("  control {:<47} {:>3} cases  agreement {}".format(
            name[:47], stats["cases"], _fmt(stats["agreement"], 3)))
    for failure in falsification.get("failures", []):
        out.append(f"  FAILURE: {failure}")
    out.append("")

    out.append("Held-out evaluation (baseline + candidate):")
    out.append(_metrics_block(held_out.get("candidate", {})))
    out.append("")
    out.append("Improvement over baseline:")
    out.append("  F1 delta vs {}:  {:+}".format(
        held_out.get("baseline_name", "baseline"),
        round(held_out.get("f1_delta", 0.0), 4)))
    out.append("  F1 delta vs strengthened baseline:  {:+}".format(
        round(strengthened.get("f1_delta", 0.0), 4)))
    discordance = held_out.get("discordance", {})
    if discordance:
        out.append("  Cases the candidate fixed / broke:  {} / {}".format(
            discordance.get("b_corrects_a"), discordance.get("b_breaks_a")))
    recovery = result.get("residual_recovery") or {}
    if recovery:
        out.append("  Ontology blind spot recovered:      {} of {} ({})".format(
            recovery.get("recovered_unsafe"), recovery.get("uncovered_unsafe"),
            _fmt(recovery.get("recovery_rate"), 3)))
        out.append("  False positives on blind-spot safe: {} ({})".format(
            recovery.get("false_positives_on_uncovered_safe"),
            _fmt(recovery.get("false_positive_rate_on_uncovered_safe"), 3)))
    out.append("")

    control = result["controls"]["label_shuffle"]
    out.append("Controls:")
    out.append("  Shuffled-label control, MCC:       {}  (F1 delta {})".format(
        _fmt(control.get("held_out_mcc")),
        _fmt(control.get("held_out_f1_over_baseline"))))
    stability = result["stability"]
    out.append("  Cross-seed prediction agreement:   {} over {} extra seed(s)".format(
        _fmt(stability.get("mean_prediction_agreement")),
        stability.get("seeds_compared", 0)))
    out.append("  Cross-seed literal-set Jaccard:    {} (syntactic, reported "
               "only)".format(_fmt(stability.get("mean_jaccard"))))
    out.append(f"  Identical structure on every seed: {stability.get('all_identical')}")
    out.append("")

    authority_state = result["authority"]
    out.append("Production authority reachable:  {}".format(
        "YES" if authority_state["production_authority_reachable"] else "NO"))
    for name, check in sorted(authority_state["checks"].items()):
        out.append(f"  {name:<36} {'PASS' if check['passed'] else 'FAIL'}")
    out.append("  Production ruleset hash unchanged: {}".format(
        result["production_fingerprint"]["unchanged"]))
    out.append("")

    out.append("Acceptance criteria:")
    for criterion in verdict["criteria"]:
        out.append("  [{}] {}".format("PASS" if criterion["passed"] else "FAIL",
                                      criterion["criterion"]))
        out.append(f"       {criterion['detail']}")
    out.append("")
    out.append(f"Verdict:               {verdict['decision']}")
    out.append(_RULE)
    out.append(f"Evidence: {result.get('artifact_dir', '(not persisted)')}")
    out.append("Evidence chain head: {} ({} records, verified={})".format(
        result["evidence"]["chain"]["head"][:16],
        result["evidence"]["chain"]["records"],
        result["evidence"]["chain"]["verified"]))
    return "\n".join(out)


def markdown_report(result: dict) -> str:
    """The `report.md` written into the evidence package."""
    candidate = result.get("candidate_primitive")
    verdict = result["verdict"]
    gap = result["ontology_gap"]
    disclosure = result.get("harness_disclosure", {})

    lines = []
    lines.append(f"# LB-0 Living Boundary Experiment — {result['run_id']}")
    lines.append("")
    lines.append(f"**RESULT: {verdict['decision']}**")
    lines.append("")
    lines.append("| field | value |")
    lines.append("|---|---|")
    lines.append(f"| seed | {result['seed']} |")
    lines.append(f"| generated at | {result['generated_at']} |")
    lines.append("| dataset | {} (`{}`) |".format(
        result["dataset"]["dataset_version"], result["dataset"]["dataset_hash"][:16]))
    lines.append(f"| baseline ontology | {result['ontology']['ontology_version']} |")
    lines.append(f"| commit | `{result['code_provenance']['commit']}` |")
    lines.append(f"| branch | {result['code_provenance']['branch']} |")
    lines.append("| working tree clean | {} |".format(
        result["code_provenance"]["working_tree_clean"]))
    lines.append(f"| python | {result['code_provenance']['python']} |")
    lines.append(f"| evidence chain head | `{result['evidence']['chain']['head']}` |")
    lines.append("")

    lines.append("## Did the existing ontology miss the failure?")
    lines.append("")
    lines.append("Baseline ontology on held-out:")
    lines.append("")
    lines.append("```")
    lines.append(_metrics_block(result["baseline_metrics"]["held_out"], indent=""))
    lines.append("```")
    lines.append("")
    lines.append("Strengthened baseline (adds Morrison's egress-after-read "
                 "heuristic) on held-out:")
    lines.append("")
    lines.append("```")
    lines.append(_metrics_block(result["strengthened_metrics"]["held_out"],
                                indent=""))
    lines.append("```")
    lines.append("")

    lines.append("## Did the system detect the gap?")
    lines.append("")
    lines.append(f"- detected: **{'YES' if gap['detected'] else 'NO'}**")
    lines.append(f"- confidence: {_fmt(gap['confidence'])}")
    lines.append("- unexplained unsafe trajectories: {} of {}".format(
        gap["residual_unsafe"], gap["total_unsafe"]))
    lines.append("- ontology-visible signature collisions: {}".format(
        gap["signature_collisions"]))
    lines.append("- affected domains: {}".format(
        ", ".join(gap["affected_domains"]) or "(none)"))
    lines.append("")
    lines.append(f"> {gap['reason']}")
    lines.append("")
    lines.append("First 10 supporting trace ids: `{}`".format(
        ", ".join(gap["supporting_trace_ids"][:10])))
    lines.append("")

    lines.append("## What structure was inferred?")
    lines.append("")
    if not candidate:
        lines.append("No candidate primitive was produced.")
    else:
        lines.append("**{}** — `{}` (status `{}`)".format(
            candidate["candidate_id"], candidate["name"], candidate["status"]))
        lines.append("")
        lines.append(candidate["description"])
        lines.append("")
        lines.append("| # | condition | literal |")
        lines.append("|---|---|---|")
        for index, literal in enumerate(candidate["literals"], start=1):
            lines.append("| {} | {} | `{}` |".format(
                index, literal["description"], literal["name"]))
        lines.append("")
        lines.append("- observed variables: {}".format(
            ", ".join(candidate["observed_variables"])))
        lines.append(f"- supporting traces: {candidate['supporting_traces']}")
        lines.append(f"- structure hash: `{candidate['structure_hash']}`")
        lines.append(f"- discovery metrics: `{candidate['discovery_metrics']}`")
        lines.append(f"- validation metrics: `{candidate['validation_metrics']}`")
        lines.append("")
        lines.append("### Hypothesis")
        lines.append("")
        lines.append(candidate["hypothesis"])
        lines.append("")
        lines.append("### Falsifiable prediction")
        lines.append("")
        lines.append(candidate["falsifiable_prediction"])
        lines.append("")
        lines.append("### Source evidence (first 25 sequence ids)")
        lines.append("")
        lines.append(f"`{', '.join(candidate['source_evidence'][:25])}`")
        lines.append("")

    lines.append("## Was the prediction falsifiable, and did it survive?")
    lines.append("")
    falsification = result["falsification"]
    lines.append("**{}** — {} cases generated.".format(
        "PASS" if falsification["passed"] else "FAIL",
        falsification["cases_generated"]))
    lines.append("")
    lines.append("| test | kind | cases | agreement with what happened |")
    lines.append("|---|---|---|---|")
    for name, stats in sorted(falsification.get("per_literal", {}).items()):
        lines.append("| `{}` | ablation | {} | {} |".format(
            name, stats["cases"], _fmt(stats["agreement"], 3)))
    for name, stats in sorted(falsification.get("per_control", {}).items()):
        lines.append("| {} | control | {} | {} |".format(
            name, stats["cases"], _fmt(stats["agreement"], 3)))
    lines.append("")
    if falsification.get("failures"):
        lines.append("Failures:")
        lines.append("")
        for failure in falsification["failures"]:
            lines.append(f"- {failure}")
        lines.append("")

    lines.append("## How did it perform on held-out traces?")
    lines.append("")
    lines.append("```")
    lines.append(_metrics_block(result["held_out"].get("candidate", {}), indent=""))
    lines.append("```")
    lines.append("")
    lines.append("- F1 delta vs baseline: **{:+}**".format(
        round(result["held_out"].get("f1_delta", 0.0), 4)))
    lines.append("- F1 delta vs strengthened baseline: **{:+}**".format(
        round(result["held_out_strengthened"].get("f1_delta", 0.0), 4)))
    lines.append(f"- discordance: `{result['held_out'].get('discordance')}`")
    lines.append(f"- residual recovery: `{result.get('residual_recovery')}`")
    lines.append("")

    lines.append("## Controls")
    lines.append("")
    lines.append("- shuffled-label control: held-out MCC **{}** (F1 delta over "
                 "baseline {}) — {}".format(
                     _fmt(result["controls"]["label_shuffle"].get("held_out_mcc")),
                     _fmt(result["controls"]["label_shuffle"].get(
                         "held_out_f1_over_baseline")),
                     result["controls"]["label_shuffle"].get("interpretation", "")))
    lines.append("- cross-seed prediction agreement: **{}** over {} extra seed(s) "
                 "(literal-set Jaccard {}, syntactic)".format(
                     _fmt(result["stability"].get("mean_prediction_agreement")),
                     result["stability"].get("seeds_compared", 0),
                     _fmt(result["stability"].get("mean_jaccard"))))
    for entry in result["stability"].get("runs", []):
        lines.append("  - seed {}: prediction agreement {}, jaccard {}, "
                     "falsification {}, identical={}".format(
                         entry["seed"],
                         entry["prediction_agreement_with_reference"],
                         entry["jaccard_with_reference"],
                         "PASS" if entry.get("falsification_passed") else "FAIL",
                         entry["identical_structure"]))
    lines.append("")

    lines.append("## Was production authority reachable?")
    lines.append("")
    lines.append("**{}**".format(
        "YES — THIS IS A FAILURE" if result["authority"]
        ["production_authority_reachable"] else "NO"))
    lines.append("")
    for name, check in sorted(result["authority"]["checks"].items()):
        lines.append("- `{}`: {}{}".format(
            name, "PASS" if check["passed"] else "FAIL",
            "" if check["passed"] else f" — {'; '.join(check['violations'])}"))
    lines.append("")
    lines.append("Production ruleset hash `{}` → `{}` (unchanged: {}).".format(
        result["production_fingerprint"]["before"][:16],
        result["production_fingerprint"]["after"][:16],
        result["production_fingerprint"]["unchanged"]))
    lines.append("")

    lines.append("## Acceptance criteria")
    lines.append("")
    lines.append("| criterion | result | detail |")
    lines.append("|---|---|---|")
    for criterion in verdict["criteria"]:
        lines.append("| `{}` | {} | {} |".format(
            criterion["criterion"], "PASS" if criterion["passed"] else "FAIL",
            criterion["detail"].replace("|", "/")))
    lines.append("")
    lines.append(f"Thresholds: `{verdict['thresholds']}`")
    lines.append("")

    if disclosure:
        lines.append("## Harness disclosure (audit only)")
        lines.append("")
        lines.append("The discovery layer never received this. It is recorded "
                     "here so a reviewer can check the result against the "
                     "ground truth the harness used.")
        lines.append("")
        lines.append(f"- rule id: `{disclosure['hidden_rule_id']}`")
        lines.append(f"- oracle version: `{disclosure['oracle_version']}`")
        lines.append("")
        lines.append(f"> {disclosure['hidden_rule_statement']}")
        lines.append("")
        lines.append(disclosure["note"])
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("Reproduce: `cd living-boundary && python -m "
                 "living_boundary.run_lb0 --seed {}`".format(result["seed"]))
    lines.append("")
    return "\n".join(lines)
