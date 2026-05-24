"""48-Hour Runtime Governance Audit CLI.

    python -m audit run --input client_package.json --out report/
    python -m audit run --input client_package.json --print

Produces (in --out): audit_report.md, audit_findings.json, audit_log.jsonl.
Deterministic: same input → byte-identical artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from audit.intake import load_package
from audit.analyzer import analyze
from audit.report import render_markdown, render_findings_json, render_audit_log


def _cmd_run(args) -> int:
    package = load_package(args.input)
    result = analyze(package)

    md = render_markdown(result, package)
    findings_json = render_findings_json(result, package)
    audit_log = render_audit_log(result)

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "audit_report.md").write_text(md, encoding="utf-8")
        (out / "audit_findings.json").write_text(findings_json,
                                                 encoding="utf-8")
        (out / "audit_log.jsonl").write_text(audit_log, encoding="utf-8")
        print(json.dumps({"wrote": [str(out / "audit_report.md"),
                                    str(out / "audit_findings.json"),
                                    str(out / "audit_log.jsonl")],
                          "summary": result.summary()}, indent=2))
    if args.print or not args.out:
        print(md)
    # exit non-zero if any client expectation was not met (CI signal)
    unmet = any(f.expectation_met is False for f in result.findings)
    return 1 if unmet else 0


def _cmd_validate(args) -> int:
    package = load_package(args.input)
    print(json.dumps({"ok": True, "org": package.org,
                      "domains": package.domains,
                      "trajectories": len(package.trajectories),
                      "tools": len(package.tools)}, indent=2))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="audit",
                                 description="Morrison 48-Hour Runtime "
                                             "Governance Audit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run the audit on a client package")
    run.add_argument("--input", required=True, help="client AuditPackage JSON")
    run.add_argument("--out", default="", help="output directory")
    run.add_argument("--print", action="store_true",
                     help="print the markdown report to stdout")
    run.set_defaults(func=_cmd_run)

    val = sub.add_parser("validate", help="validate a client package")
    val.add_argument("--input", required=True)
    val.set_defaults(func=_cmd_validate)

    ns = ap.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    sys.exit(main())
