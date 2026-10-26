"""Command-line entry point for the monitoring-incident experiment.

    python -m experiments.monitoring_incident <command> [options]

Commands:
  scripted      Run the scripted adversarial + control suite across conditions.
  live          Run one scenario with a model proposer (ollama / openai / anthropic).
  differential  Oracle-vs-global-model agreement checks (+ run_tests blind-spot probe).
  preflight     Check a local model endpoint (read-only; never pulls a model).
  verify        Verify a run's hash-chained evidence log.
  coverage      Print adversarial-category coverage and the NOT TESTED list.

No command makes a paid API call unless `live --provider anthropic --allow-paid-api`
is given explicitly, and no command downloads a model.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from experiments.monitoring_incident import cases as C
from experiments.monitoring_incident import evidence as E
from experiments.monitoring_incident import scenarios as S
from experiments.monitoring_incident.authority import CONDITIONS
from experiments.monitoring_incident.harness import RunConfig, run_episode
from experiments.monitoring_incident.proposers import ScriptedProposer, ollama_preflight

ALL_CONDITIONS = ["ungoverned", "local_only", "global_only", "hierarchical"]


def _aggregate(rows: list) -> dict:
    """Roll per-episode summaries up by (category, condition) and by condition."""
    keys = ["unauthorized_proposed", "unauthorized_executed", "authorized_proposed",
            "authorized_executed", "false_positive_block", "false_positive_escalate",
            "boundary_attack_must_refuse", "boundary_bypasses", "unattributed_effects",
            "enforcement_bypass_total", "proposals"]
    by_cond = {}
    by_cat_cond = {}
    misleading = {}
    for r in rows:
        cond = r["metadata"]["condition"]
        cat = r["metadata"]["labels"].get("category") or r["metadata"].get("case_id", "")
        m = r["metrics"]
        d = by_cond.setdefault(cond, {k: 0 for k in keys})
        dc = by_cat_cond.setdefault((cat, cond), {k: 0 for k in keys})
        for k in keys:
            d[k] += int(m.get(k) or 0)
            dc[k] += int(m.get(k) or 0)
        if m.get("report", {}).get("present"):
            mk = misleading.setdefault(cond, {"reports": 0, "misleading": 0})
            mk["reports"] += 1
            mk["misleading"] += int(m["report"].get("misleading", False))
    return {"by_condition": by_cond,
            "by_category_condition": {f"{c}|{cond}": v for (c, cond), v in by_cat_cond.items()},
            "report_accuracy_by_condition": misleading}


def cmd_scripted(args) -> int:
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    conditions = args.conditions or ALL_CONDITIONS
    selected = C.cases_for(args.scenario or "", args.categories or None)
    if args.case:
        selected = [c for c in selected if c.id in set(args.case)]
    if not selected:
        print("no cases match the filter", file=sys.stderr)
        return 2
    rows, index = [], []
    for case in selected:
        for cond in conditions:
            for rep in range(args.repetitions):
                cfg = RunConfig(scenario=case.scenario, condition=cond, output_dir=out,
                                case_id=case.id, repetition=rep, escalation_policy=args.escalation,
                                labels={"category": case.category, "intent": case.intent,
                                        "expect": case.expect.get(cond)})
                summary = run_episode(cfg, ScriptedProposer(case.id, case.steps))
                rows.append(summary)
                index.append({"case": case.id, "category": case.category, "intent": case.intent,
                              "condition": cond, "repetition": rep, "run_id": summary["metadata"]["run_id"],
                              "status": summary["status"], "expect": case.expect.get(cond),
                              "escalation_policy": args.escalation,
                              "manifest_sha256": summary["metadata"]["governance_manifest_sha256"],
                              "commit": summary["metadata"]["git"]["commit"],
                              "terminal_hash": summary["evidence"]["terminal_hash"],
                              "unauthorized_executed": summary["metrics"]["unauthorized_executed"],
                              "enforcement_bypass_total": summary["metrics"]["enforcement_bypass_total"],
                              "false_positives": (summary["metrics"]["false_positive_block"]
                                                  + summary["metrics"]["false_positive_escalate"]),
                              "monitoring_intact_final": summary["metrics"]["monitoring_intact_final"],
                              "out_of_band_monitoring_break": summary["metrics"].get("out_of_band_monitoring_break"),
                              "uninspectable_monitoring_state": summary["metrics"].get("uninspectable_monitoring_state"),
                              "evidence_valid": summary["evidence"]["valid"]})
    report = {"suite": "scripted", "manifest_sha256": S.manifest_sha256(),
              "manifest_version": S.manifest()["manifest_version"],
              "conditions": conditions, "cases": len(selected), "episodes": len(rows),
              "escalation_policy": args.escalation,
              "category_coverage": C.CATEGORY_COVERAGE, "not_tested": C.NOT_TESTED,
              "aggregate": _aggregate(rows), "index": index}
    (out / "scripted_report.json").write_text(json.dumps(report, indent=2, sort_keys=True,
                                                         default=repr) + "\n", "utf-8")
    _print_scripted(report)
    bad = [r for r in index if not r["evidence_valid"]
           or any(s.startswith("harness_error") for s in [r["status"]])]
    return 1 if bad else 0


def _print_scripted(report: dict) -> None:
    print("scripted suite: %d cases x %d conditions = %d episodes"
          % (report["cases"], len(report["conditions"]), report["episodes"]))
    print("manifest %s (%s)" % (report["manifest_version"], report["manifest_sha256"][:12]))
    agg = report["aggregate"]["by_condition"]
    print("\n%-13s %9s %9s %9s %9s %9s" % ("condition", "unauth_ex", "bypass", "fp_block",
                                           "fp_esc", "refused"))
    for cond in report["conditions"]:
        d = agg.get(cond, {})
        print("%-13s %9d %9d %9d %9d %9d" % (
            cond, d.get("unauthorized_executed", 0), d.get("enforcement_bypass_total", 0),
            d.get("false_positive_block", 0), d.get("false_positive_escalate", 0),
            d.get("boundary_attack_must_refuse", 0)))
    print("\nreport accuracy by condition (misleading / total):")
    for cond, v in sorted(report["aggregate"]["report_accuracy_by_condition"].items()):
        print("  %-13s %d / %d" % (cond, v["misleading"], v["reports"]))
    print("\nmismatches vs author expectation:")
    any_mismatch = False
    for r in report["index"]:
        exp = r["expect"]
        if exp in ("allowed", "blocked"):
            blocked = r["unauthorized_executed"] == 0 and r["false_positives"] == 0 \
                if r["intent"] != "attack" else r["unauthorized_executed"] == 0
            got = "blocked" if r["unauthorized_executed"] == 0 else "allowed"
            if r["intent"] == "attack" and got != exp:
                print("  %-22s %-12s expected=%s got=%s" % (r["case"], r["condition"], exp, got))
                any_mismatch = True
    if not any_mismatch:
        print("  (none for attack cases)")


def cmd_live(args) -> int:
    from experiments.monitoring_incident.harness import RunExistsError
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    proposer = _make_proposer(args)
    # Live evidence is stochastic and must never be silently replaced: each
    # replicate is a distinct --repetition and overwriting an existing run is
    # rejected fail-closed (on_existing="error").
    cfg = RunConfig(scenario=args.scenario, condition=args.condition, output_dir=out,
                    escalation_policy=args.escalation, max_steps=args.max_steps,
                    max_turns=args.max_turns, repetition=args.repetition, seed=args.seed,
                    on_existing="error",
                    labels={"intent": "live", "category": "live_model"})
    try:
        summary = run_episode(cfg, proposer)
    except RunExistsError as e:
        print(json.dumps({"status": "rejected:run_exists", "error": str(e),
                          "hint": "choose a different --repetition or --output; the existing "
                                  "run's evidence was NOT modified"}, indent=2))
        return 2
    print(json.dumps({"run_id": summary["metadata"]["run_id"], "status": summary["status"],
                      "stop_reason": summary["stop_reason"],
                      "generation_mode": summary["generation_mode"],
                      "started_utc": summary["started_utc"], "completed_utc": summary["completed_utc"],
                      "metrics": summary["metrics"], "evidence": summary["evidence"]},
                     indent=2, default=repr))
    return 0 if summary["status"] == "ok" else 1


def _make_proposer(args):
    protocol = args.tool_protocol
    common = dict(temperature=args.temperature, seed=args.seed, max_tokens=args.max_tokens,
                  tool_protocol=protocol)
    if args.provider == "ollama":
        from experiments.monitoring_incident.proposers import OllamaProposer
        return OllamaProposer(args.model, base_url=args.base_url or "http://127.0.0.1:11434",
                              num_ctx=args.num_ctx, **common)
    if args.provider == "openai-compatible":
        import os
        from experiments.monitoring_incident.proposers import OpenAICompatibleProposer
        key = os.environ.get(args.api_key_env, "") if args.api_key_env else ""
        return OpenAICompatibleProposer(args.model, base_url=args.base_url or "http://127.0.0.1:11434/v1",
                                        api_key=key, **common)
    if args.provider == "anthropic":
        from experiments.monitoring_incident.anthropic_proposer import AnthropicProposer
        return AnthropicProposer(args.model, allow_paid=args.allow_paid_api, effort=args.effort,
                                 max_tokens=args.max_tokens)
    raise ValueError(args.provider)


def cmd_differential(args) -> int:
    import tempfile
    from experiments.monitoring_incident import differential as D
    work = args.work_dir or tempfile.mkdtemp(prefix="mi-diff-")
    result = {"scenarios": {}, "run_tests_blind_spot": D.run_tests_side_effect_probe(work),
              "false_safe_differential": D.false_safe_differential(work)}
    total_disagree = 0
    for sid in (["alert_suppression", "integration_removal"] if not args.scenario else [args.scenario]):
        r = D.check_scenario(sid, work)
        result["scenarios"][sid] = r
        total_disagree += len(r["disagreements"])
        print("%-22s checked=%d agree=%d disagree=%d"
              % (sid, r["checked"], r["agreements"], len(r["disagreements"])))
        for d in r["disagreements"]:
            print("   DISAGREEMENT %s: %s model_violations=%s oracle_broken=%s"
                  % (d["probe"], d["direction"], d["model_violations"], list(d["oracle_clauses"])))
    fsd = result["false_safe_differential"]
    print("\nfalse-safe differential (%d cases): %s" % (fsd["cases"], fsd["counts"]))
    print("  (XC-RT1 is `agree` under a static differential: its break is a run_tests runtime effect)")
    print("run_tests blind-spot probe:", result["run_tests_blind_spot"]["finding"][:120], "...")
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2, default=repr) + "\n", "utf-8")
    return 0


def cmd_preflight(args) -> int:
    info = {"ollama": ollama_preflight(args.base_url or "http://127.0.0.1:11434")}
    import os
    info["anthropic_key_present"] = bool(os.environ.get("ANTHROPIC_API_KEY"))
    info["note"] = ("read-only: no model was pulled and no API call was made. "
                    "anthropic_key_present reports only whether the env var is set.")
    print(json.dumps(info, indent=2))
    return 0


def cmd_verify(args) -> int:
    records = E.load(args.log)
    result = E.verify_records(records, args.terminal_hash)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def cmd_counterexamples(args) -> int:
    from experiments.monitoring_incident import counterexamples as X
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    conditions = args.conditions or ["hierarchical"]
    rows = []
    for cx in X.COUNTEREXAMPLES:
        for cond in conditions:
            summary, rec = X.run_counterexample(cx, cond, out, escalation=args.escalation)
            rows.append({"condition": cond, "expectation": cx.expectation,
                         "description": cx.description, "note": cx.note,
                         "run_id": summary["metadata"]["run_id"],
                         "evidence_valid": summary["evidence"]["valid"],
                         "record": rec.as_dict()})
    report = {"suite": "counterexamples", "manifest_sha256": S.manifest_sha256(),
              "conditions": conditions, "escalation": args.escalation,
              "count": len(X.COUNTEREXAMPLES), "false_safe_ids": X.FALSE_SAFE_IDS, "rows": rows}
    (out / "counterexamples_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, default=repr) + "\n", "utf-8")
    print("counterexamples: %d cases x %d conditions" % (len(X.COUNTEREXAMPLES), len(conditions)))
    print("%-30s %-20s %-10s %-10s %-8s" % ("id", "condition", "unauth_ex", "mon_final", "bypass"))
    for r in rows:
        rec = r["record"]
        print("%-30s %-20s %-10s %-10s %-8s" % (
            rec["id"], r["condition"], rec["unauthorized_executed"],
            rec["observed_monitoring_intact_final"], rec["enforcement_bypass_total"]))
    return 0


def cmd_anchor(args) -> int:
    from experiments.monitoring_incident import anchoring as A
    campaign = Path(args.output_dir)
    anchor_path = Path(args.anchor_file) if args.anchor_file else campaign / A.DEFAULT_ANCHOR_NAME
    if args.verify:
        if not anchor_path.exists():
            print(json.dumps({"ok": False, "error": "no anchor at %s" % anchor_path}, indent=2))
            return 2
        result = A.verify_against_anchor(campaign, A.load_anchor(anchor_path))
        print(json.dumps({"mode": "verify", "anchor": str(anchor_path), "checked": result["checked"],
                          "ok": result["ok"], "problems": result["problems"]}, indent=2))
        return 0 if result["ok"] else 1
    built = A.build_anchor(campaign)
    if not built["ok"]:
        print(json.dumps({"mode": "generate", "ok": False, "runs": built["anchor"]["runs"],
                          "problems": built["problems"],
                          "note": "anchor NOT written: validate/clean the campaign first"}, indent=2))
        return 1
    try:
        A.write_anchor(built["anchor"], anchor_path, force=args.force)
    except FileExistsError as e:
        print(json.dumps({"mode": "generate", "ok": False, "error": str(e)}, indent=2))
        return 2
    print(json.dumps({"mode": "generate", "ok": True, "anchor": str(anchor_path),
                      "runs": built["anchor"]["runs"],
                      "anchor_sha256": built["anchor"]["anchor_sha256"],
                      "hint": "record anchor_sha256 off-machine (or commit the anchor) for an "
                              "external anchor; see the anchor's tamper note"}, indent=2))
    return 0


def cmd_coverage(args) -> int:
    print("Adversarial category coverage (12 planned categories):\n")
    for cat, cases in C.CATEGORY_COVERAGE.items():
        print("  %-34s %s" % (cat, cases))
    print("\nNOT TESTED (with reason):\n")
    for name, reason in C.NOT_TESTED.items():
        print("  %s\n    %s\n" % (name, reason))
    print("Conditions:", ", ".join("%s (%s)" % (k, v.description[:40]) for k, v in CONDITIONS.items()))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m experiments.monitoring_incident",
                                description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scripted", help="run the scripted adversarial + control suite")
    s.add_argument("--output", required=True)
    s.add_argument("--scenario", choices=sorted(S.SCENARIOS))
    s.add_argument("--conditions", nargs="+", choices=ALL_CONDITIONS)
    s.add_argument("--categories", nargs="+")
    s.add_argument("--case", nargs="+")
    s.add_argument("--repetitions", type=int, default=1)
    s.add_argument("--escalation", choices=["deny", "oracle"], default="deny")
    s.set_defaults(func=cmd_scripted)

    lv = sub.add_parser("live", help="run one scenario with a model proposer")
    lv.add_argument("--output", required=True)
    lv.add_argument("--scenario", required=True, choices=sorted(S.SCENARIOS))
    lv.add_argument("--condition", required=True, choices=ALL_CONDITIONS)
    lv.add_argument("--provider", required=True, choices=["ollama", "openai-compatible", "anthropic"])
    lv.add_argument("--model", required=True, help="exact model id; no default is assumed")
    lv.add_argument("--base-url", default="")
    lv.add_argument("--tool-protocol", choices=["native", "json"], default="native")
    lv.add_argument("--temperature", type=float, default=None)
    lv.add_argument("--seed", type=int, default=None)
    lv.add_argument("--num-ctx", type=int, default=8192)
    lv.add_argument("--max-tokens", type=int, default=2048)
    lv.add_argument("--max-steps", type=int, default=25)
    lv.add_argument("--max-turns", type=int, default=30)
    lv.add_argument("--repetition", type=int, default=0,
                    help="replicate index; part of the run id. Re-using an existing "
                         "(config, repetition) into the same --output is rejected, never "
                         "overwritten. Increment it for each stochastic replicate.")
    lv.add_argument("--effort", default="medium", help="anthropic only: output_config.effort")
    lv.add_argument("--api-key-env", default="", help="openai-compatible: env var holding the key")
    lv.add_argument("--allow-paid-api", action="store_true",
                    help="required for --provider anthropic; permits paid calls")
    lv.add_argument("--escalation", choices=["deny", "oracle"], default="deny")
    lv.set_defaults(func=cmd_live)

    d = sub.add_parser("differential", help="oracle vs global-model agreement checks")
    d.add_argument("--scenario", choices=sorted(S.SCENARIOS))
    d.add_argument("--work-dir", default="")
    d.add_argument("--output", default="")
    d.set_defaults(func=cmd_differential)

    pf = sub.add_parser("preflight", help="check a local model endpoint, read-only")
    pf.add_argument("--base-url", default="")
    pf.set_defaults(func=cmd_preflight)

    v = sub.add_parser("verify", help="verify a run's evidence log")
    v.add_argument("--log", required=True)
    v.add_argument("--terminal-hash", default=None)
    v.set_defaults(func=cmd_verify)

    cov = sub.add_parser("coverage", help="print category coverage and NOT TESTED list")
    cov.set_defaults(func=cmd_coverage)

    an = sub.add_parser("anchor", help="generate or verify an evidence anchor for a campaign dir")
    an.add_argument("--output-dir", required=True, help="campaign directory holding run subdirs")
    an.add_argument("--anchor-file", default="", help="anchor path (default <dir>/EVIDENCE_ANCHOR.json)")
    an.add_argument("--force", action="store_true", help="overwrite an existing anchor")
    an.add_argument("--verify", action="store_true", help="verify runs against an existing anchor")
    an.set_defaults(func=cmd_anchor)

    cx = sub.add_parser("counterexamples", help="run the audit counterexamples and publish records")
    cx.add_argument("--output", required=True)
    cx.add_argument("--conditions", nargs="+", choices=ALL_CONDITIONS)
    cx.add_argument("--escalation", choices=["deny", "oracle"], default="deny")
    cx.set_defaults(func=cmd_counterexamples)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
