"""Release gate: actually run the finite verifier, then check what it produced.

A green `pytest` proves the verifier's own tests pass. It does not prove the
verifier was ever pointed at the declared models, nor that what came out is
internally consistent. This module does that, and fails closed:

- every declared model is enumerated, under every declared escalation policy;
- the verdict must equal the one the repository declares it must be, in BOTH
  directions -- a SAFE model turning UNSAFE is a regression, and an UNSAFE
  model turning SAFE means the verifier stopped finding a counterexample it
  exists to find;
- INCONCLUSIVE never satisfies an expectation;
- every artifact must pass independent validation;
- model and ruleset identity must be establishable, and the verifier's own
  commit must be known and clean -- a verification whose provenance cannot be
  pinned is not evidence.

Run:  python -m morrison_governance.global_verification.ci_gate --out DIR
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .comparison import compare_control_and_governed
from .evidence import build_verification_artifact
from .governance import MorrisonKernelAdapter
from .provenance import VerificationEvidenceLedger, validate_verification_artifact
from .scenarios import get_scenario, perturbation_matrix
from .verifier import (
    ESCALATION_APPROVE,
    ESCALATION_DENY,
    INCONCLUSIVE,
    VerificationLimits,
)

EXPECTATIONS = Path(__file__).with_name("ci_expectations.json")

_POLICIES = {
    "deny": None,
    "deny-and-approve": lambda proposal, decision: (ESCALATION_DENY, ESCALATION_APPROVE),
}


def _environment(name: str):
    for environment in perturbation_matrix():
        if environment.name == name:
            return environment
    return get_scenario(name)


def _slug(model: str, escalations: str) -> str:
    return f"{model}__{escalations}".replace("/", "_")


def run_case(case: dict[str, Any], limits: VerificationLimits, out_dir: Path) -> dict[str, Any]:
    """Enumerate one declared model and judge the artifact it produced."""
    model, escalations = case["model"], case["escalations"]
    expected = case["verdict"]
    environment = _environment(model)
    ledger = VerificationEvidenceLedger()
    governance = MorrisonKernelAdapter(ledger=ledger)
    comparison = compare_control_and_governed(
        environment, governance, limits=limits,
        escalation_policy=_POLICIES[escalations],
    )
    artifact = build_verification_artifact(
        environment, governance, comparison,
        algorithm="bfs", limits=limits, ledger=ledger,
    )
    validation = validate_verification_artifact(artifact)
    path = out_dir / f"{_slug(model, escalations)}.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    actual = artifact["finite_verification"]["verdict"]
    failures: list[str] = []
    if actual != expected:
        failures.append(
            f"verdict {actual} but the repository declares {expected}"
            + (" -- an INCONCLUSIVE never satisfies an expectation"
               if actual == INCONCLUSIVE else "")
        )
    if not validation.valid:
        failures.append(
            "artifact failed validation: "
            + ", ".join(f["check"] for f in validation.failures())
        )
    if not artifact["environment"]["model_hash"]:
        failures.append("model identity could not be established")
    if not artifact["governance"]["ruleset_hash"]:
        failures.append("ruleset identity could not be established")

    return {
        "model": model,
        "escalations": escalations,
        "expected_verdict": expected,
        "verdict": actual,
        "complete_enumeration": artifact["finite_verification"]["complete_enumeration"],
        "verification_id": artifact["verification_id"],
        "model_hash": artifact["environment"]["model_hash"],
        "transition_relation_id": artifact["environment"]["transition_relation_id"],
        "ruleset_hash": artifact["governance"]["ruleset_hash"],
        "engine_version": artifact["governance"]["engine_version"],
        "escalation_outcomes_admitted": artifact["traversal"]["escalation_outcomes_admitted"],
        "artifact_hash": artifact["artifact_integrity"]["artifact_hash"],
        "artifact_valid": validation.valid,
        "artifact_checks": len(validation.checks),
        "evidence_records": artifact["evidence_ledger"]["record_count"],
        "artifact_path": path.name,
        "passed": not failures,
        "failures": failures,
    }


def provenance_gate(verifier: dict[str, Any], *, allow_dirty: bool) -> list[str]:
    """A verification whose own provenance is unknown is not evidence."""
    failures = []
    if not verifier.get("repository_commit"):
        failures.append(
            "repository commit is unknown; the verification cannot be pinned to code"
        )
    if verifier.get("repository_dirty") and not allow_dirty:
        failures.append(
            "the working tree is dirty; the recorded commit does not describe the "
            "code that ran (pass --allow-dirty only for local runs)"
        )
    if not verifier.get("verifier_version"):
        failures.append("verifier version is unknown")
    return failures


def _summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "## Finite-model verification gate",
        "",
        f"**{summary['status']}** — {summary['passed']}/{summary['total']} cases passed.",
        "",
        "Scope: these results hold **within each declared finite model and its "
        "stated assumptions**. They are not a claim about the production "
        "environment and not a claim of universal safety.",
        "",
        f"- commit `{summary['verifier']['repository_commit']}` "
        f"(dirty: {summary['verifier']['repository_dirty']})",
        f"- verifier `{summary['verifier']['verifier_version']}`, "
        f"python {summary['verifier']['python']}",
        "",
        "| model | escalations | verdict | expected | complete | verification id | artifact |",
        "|---|---|---|---|---|---|---|",
    ]
    for case in summary["cases"]:
        mark = "" if case["passed"] else " ❌"
        lines.append(
            f"| `{case['model']}` | {case['escalations']} | {case['verdict']}{mark} | "
            f"{case['expected_verdict']} | {case['complete_enumeration']} | "
            f"`{case['verification_id']}` | {'valid' if case['artifact_valid'] else 'INVALID'} |"
        )
    failed = [c for c in summary["cases"] if not c["passed"]]
    if failed:
        lines += ["", "### Failures", ""]
        for case in failed:
            for reason in case["failures"]:
                lines.append(f"- `{case['model']}` / {case['escalations']}: {reason}")
    if summary["provenance_failures"]:
        lines += ["", "### Provenance", ""] + [
            f"- {reason}" for reason in summary["provenance_failures"]
        ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("verification-artifacts"))
    parser.add_argument("--expectations", type=Path, default=EXPECTATIONS)
    parser.add_argument("--allow-dirty", action="store_true",
                        help="local use only; CI must not pass this")
    parser.add_argument("--max-states", type=int, default=10_000)
    parser.add_argument("--max-edges", type=int, default=100_000)
    parser.add_argument("--max-depth", type=int, default=64)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args(argv)

    limits = VerificationLimits(args.max_states, args.max_edges,
                                args.max_depth, args.timeout_seconds)
    declared = json.loads(args.expectations.read_text(encoding="utf-8"))
    cases = declared["expectations"] + declared["perturbation_expectations"]
    args.out.mkdir(parents=True, exist_ok=True)

    results = [run_case(case, limits, args.out) for case in cases]
    from .provenance import verifier_identity

    verifier = verifier_identity()
    provenance_failures = provenance_gate(verifier, allow_dirty=args.allow_dirty)
    passed = sum(1 for r in results if r["passed"])
    ok = passed == len(results) and not provenance_failures

    summary = {
        "schema": "mrg.global-verification.ci-summary/1",
        "status": "PASS" if ok else "FAIL",
        "scope": (
            "Each result holds within its declared finite model and stated "
            "assumptions only. Not a production-environment claim."
        ),
        "verifier": verifier,
        "expectations_schema": declared["schema"],
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "provenance_failures": provenance_failures,
        "cases": results,
    }
    (args.out / "verification-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (args.out / "verification-summary.md").write_text(
        _summary_markdown(summary), encoding="utf-8")

    for case in results:
        flag = "ok  " if case["passed"] else "FAIL"
        print(f"{flag} {case['model']:38s} {case['escalations']:16s} "
              f"{case['verdict']:28s} {case['verification_id']}")
        for reason in case["failures"]:
            print(f"      {reason}")
    for reason in provenance_failures:
        print(f"FAIL provenance: {reason}")
    print(f"\n{summary['status']}: {passed}/{len(results)} cases, "
          f"artifacts in {args.out}/")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(_summary_markdown(summary))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
