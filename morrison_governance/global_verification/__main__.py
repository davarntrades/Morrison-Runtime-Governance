"""Command-line entry point for finite-model global verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .comparison import compare_control_and_governed, run_composition_experiment
from .evidence import build_verification_artifact
from .governance import MorrisonKernelAdapter
from .provenance import (
    VerificationEvidenceLedger,
    validate_verification_artifact,
)
from .scenarios import SCENARIOS, get_scenario, perturbation_matrix
from .verifier import (
    ESCALATION_APPROVE,
    ESCALATION_DENY,
    VerificationLimits,
)


def _escalation_policy(mode: str):
    """Which resolutions of an ESCALATE the run is allowed to enumerate.

    `deny` is the standing assumption and the default. `deny-and-approve` also
    enumerates the authorised resolution, which is the only way to see what a
    model permits once someone approves.
    """
    if mode == "deny":
        return None
    outcomes = {
        "approve": (ESCALATION_APPROVE,),
        "deny-and-approve": (ESCALATION_DENY, ESCALATION_APPROVE),
    }[mode]
    return lambda proposal, decision: outcomes


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Exhaustively enumerate a finite modeled environment through "
            "control and Morrison-governed execution."
        )
    )
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="secret_exfiltration")
    parser.add_argument("--compare-control", action="store_true", help="retained for explicitness; comparison is always performed")
    parser.add_argument("--perturbations", action="store_true", help="run the finite perturbation matrix")
    parser.add_argument("--composition-experiment", action="store_true")
    parser.add_argument("--algorithm", choices=("bfs", "dfs"), default="bfs")
    parser.add_argument(
        "--escalations",
        choices=("deny", "deny-and-approve", "approve"),
        default="deny",
        help=(
            "how to resolve an ESCALATE. 'deny' (default) leaves escalations "
            "unresolved and non-executable; the others also enumerate the "
            "approved resolution, authorised by a verified approval artifact"
        ),
    )
    parser.add_argument("--max-states", type=int, default=10_000)
    parser.add_argument("--max-edges", type=int, default=100_000)
    parser.add_argument("--max-depth", type=int, default=64)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--export-json", type=Path)
    parser.add_argument("--export-dot", type=Path, help="export the governed graph as DOT")
    return parser


def _print_result(name: str, result: object) -> None:
    comparison = result
    print(f"SCENARIO {name}")
    print("CONTROL")
    print(f"reachable states: {comparison.control.reachable_state_count}")
    print(f"unsafe reachable: {comparison.control.unsafe_reachable_state_count}")
    print(f"shortest unsafe path: {comparison.control.shortest_unsafe_path}")
    print("GOVERNED")
    print(f"reachable states: {comparison.governed.reachable_state_count}")
    print(f"unsafe reachable: {comparison.governed.unsafe_reachable_state_count}")
    print(f"blocked transitions: {comparison.governed.blocked_edge_count}")
    print(f"escalations denied: {comparison.governed.denied_escalation_edge_count}")
    print(f"escalations approved and executed: "
          f"{comparison.governed.approved_escalation_edge_count}")
    print("VERDICT")
    print(comparison.verdict)
    print(comparison.to_dict(include_graph=False)["claim"])


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    limits = VerificationLimits(
        max_states=args.max_states,
        max_edges=args.max_edges,
        max_depth=args.max_depth,
        timeout_seconds=args.timeout_seconds,
    )
    # One ledger per run: the branch kernels are thrown away, their evidence
    # records are not.
    ledger = VerificationEvidenceLedger()
    governance = MorrisonKernelAdapter(ledger=ledger)
    escalation_policy = _escalation_policy(args.escalations)

    if args.composition_experiment:
        experiment = run_composition_experiment(
            governance, limits=limits, escalation_policy=escalation_policy
        )
        payload = experiment.to_dict(include_graph=True)
        print("COMPOSITION EXPERIMENT")
        print(f"Safe(A) and Safe(B): {experiment.local_safety_composed}")
        print(f"new unsafe path in A+B: {experiment.new_unsafe_path_in_composition}")
        print(f"composition verdict: {experiment.composition.verdict}")
        if args.export_json:
            args.export_json.write_text(
                json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
        return 0 if experiment.composition.verdict != "INCONCLUSIVE" else 2

    environments = perturbation_matrix() if args.perturbations else (get_scenario(args.scenario),)
    artifacts = []
    exit_code = 0
    for environment in environments:
        comparison = compare_control_and_governed(
            environment, governance, limits=limits, algorithm=args.algorithm,
            escalation_policy=escalation_policy,
        )
        _print_result(environment.name, comparison)
        artifacts.append(
            build_verification_artifact(
                environment,
                governance,
                comparison,
                algorithm=args.algorithm,
                limits=limits,
                ledger=ledger,
            )
        )
        validation = validate_verification_artifact(artifacts[-1])
        print(f"artifact {artifacts[-1]['verification_id']} "
              f"integrity={'VALID' if validation.valid else 'INVALID'} "
              f"({len(validation.checks)} checks, {len(validation.failures())} failed)")
        if not validation.valid:
            exit_code = 2
        if comparison.verdict == "INCONCLUSIVE":
            exit_code = 2
        if args.export_dot and len(environments) == 1:
            args.export_dot.write_text(comparison.governed.graph.to_dot(), encoding="utf-8")

    if args.export_json:
        payload = artifacts[0] if len(artifacts) == 1 else {"verification_matrix": artifacts}
        args.export_json.write_text(
            json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

