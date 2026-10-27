"""python -m experiments.dynamic_omega {controlled,live,anchor,report} ..."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments.dynamic_omega import governance as G
from experiments.dynamic_omega import harness as H
from experiments.dynamic_omega import scenarios as S


def _write_index(out: Path, rows: list, name: str) -> None:
    (out / name).write_text(json.dumps(rows, indent=2, sort_keys=True, default=repr) + "\n", "utf-8")


def controlled(args) -> int:
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    cases = ([S.by_id(c) for c in args.cases] if args.cases
             else {"af": S.CASES, "heldout": S.HELDOUT_CASES, "all": S.ALL_CASES}[args.set])
    conds = args.conditions or G.ORDER
    rows, bad = [], 0
    for case in cases:
        for cond in conds:
            summ = H.Episode(case, cond, H.ScriptedProposer(case.steps), out).run()
            m = summ["metrics"]
            row = {"case": case.id, "family": case.family, "condition": cond,
                   "run_id": summ["metadata"]["run_id"], "expect": case.expect.get(cond),
                   "outcome": m["outcome"], "evidence_valid": summ["evidence"]["valid"],
                   **{k: m[k] for k in ("proposed", "unsafe_proposed", "permitted",
                                        "unsafe_permitted", "executed", "unsafe_executed",
                                        "prevented", "detected_after_only", "false_refusals",
                                        "legit_proposed", "legit_executed",
                                        "decided_on_unevaluated_state",
                                        "executed_on_changed_state", "stale_authority_harm",
                                        "representation_mismatch",
                                        "unmodelled_treated_as_no_effect", "not_established",
                                        "escalated", "refusals_by_kind", "final_violations",
                                        "violations_agent_attributable", "violations_env_only")}}
            rows.append(row)
            bad += int(not summ["evidence"]["valid"])
            flag = "" if row["outcome"] == row["expect"] else "   <-- differs from prediction"
            print("%-34s %-27s %-25s%s" % (case.id, cond, row["outcome"], flag))
    _write_index(out, rows, "controlled_index.json")
    return 1 if bad else 0


def anchor(args) -> int:
    out = Path(args.output_dir)
    path = out / "EVIDENCE_ANCHOR.json"
    if args.verify:
        res = H.verify_anchor(out, json.loads(path.read_text("utf-8")))
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    if path.exists():
        print("anchor exists; refusing to overwrite: %s" % path)
        return 1
    body = H.build_anchor(out)
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", "utf-8")
    print("anchored %d runs, anchor_sha256=%s" % (len(body["runs"]), body["anchor_sha256"]))
    return 0 if all(r["valid"] and r["summary_terminal_matches"] for r in body["runs"]) else 1


def build_parser():
    p = argparse.ArgumentParser(prog="python -m experiments.dynamic_omega")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("controlled", help="deterministic scripted scenarios A-F")
    c.add_argument("--output", required=True)
    c.add_argument("--cases", nargs="+")
    c.add_argument("--set", choices=["af", "heldout", "all"], default="af")
    c.add_argument("--conditions", nargs="+", choices=G.ORDER)
    c.set_defaults(fn=controlled)
    a = sub.add_parser("anchor", help="anchor (or --verify) a campaign directory")
    a.add_argument("--output-dir", required=True)
    a.add_argument("--verify", action="store_true")
    a.set_defaults(fn=anchor)
    try:
        from experiments.dynamic_omega import live
        live.add_parser(sub)
    except ImportError:
        pass
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)
