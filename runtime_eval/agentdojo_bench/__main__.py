"""CLI: run AgentDojo with Morrison as the tool executor.

Offline, no API key (fully-compromised-agent oracle, all four suites):

    python -m runtime_eval.agentdojo_bench oracle --output artifacts/agentdojo

Live model under AgentDojo's `important_instructions` attack:

    python -m runtime_eval.agentdojo_bench live \\
        --provider anthropic --model claude-sonnet-5-5 --suite banking

Add `--defense none` to the live command for the undefended baseline.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from runtime_eval.agentdojo_bench.manifest import PROFILES

SUITES = sorted(PROFILES)


def _write(output: Path | None, name: str, payload: dict) -> None:
    if output is None:
        return
    output.mkdir(parents=True, exist_ok=True)
    (output / name).write_text(json.dumps(payload, indent=2, sort_keys=True,
                                          default=str))


def _oracle(args) -> int:
    from runtime_eval.agentdojo_bench.oracle import run_suite
    summaries = {}
    for suite in args.suite or SUITES:
        result = run_suite(suite, benchmark_version=args.benchmark_version,
                           user_tasks=args.user_task, injection_tasks=args.injection_task)
        summaries[suite] = result["summary"]
        _write(args.output, f"oracle-{suite}.json", result)
        s = result["summary"]
        print(f"{suite:10s} ASR {s['baseline_asr']} -> {s['morrison_asr']} "
              f"({s['attacks_stopped']}/{s['exercisable_attack_pairs']} stopped)  "
              f"benign utility {s['baseline_benign_utility']} -> "
              f"{s['morrison_benign_utility']}")
    _write(args.output, "oracle-summary.json", {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_version": args.benchmark_version,
        "suites": summaries,
    })
    return 0


def _provenance(args) -> dict:
    import subprocess
    from importlib.metadata import version
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                                text=True, check=False).stdout.strip() or None
        dirty = bool(subprocess.run(["git", "status", "--porcelain"],
                                    capture_output=True, text=True,
                                    check=False).stdout.strip())
    except OSError:
        commit, dirty = None, None
    return {"argv": sys.argv[1:], "git_commit": commit, "git_dirty": dirty,
            "agentdojo_version": version("agentdojo"),
            "python": sys.version.split()[0]}


def _live(args) -> int:
    from runtime_eval.agentdojo_bench.live import run_live
    status = 0
    for suite in args.suite or SUITES:
        started = datetime.now(timezone.utc).isoformat()
        result = run_live(
            args.provider, args.model, suite, attack=args.attack,
            defense=args.defense, benchmark_version=args.benchmark_version,
            user_tasks=args.user_task, injection_tasks=args.injection_task,
            logdir=(args.output / "logs") if args.output else None,
            force_rerun=args.force_rerun)
        result["provenance"] = {**_provenance(args), "started_at": started,
                                "finished_at": datetime.now(timezone.utc).isoformat()}
        _write(args.output,
               f"live-{args.model.replace('/', '_')}-{args.defense}-{suite}.json",
               result)
        if "error" in result:
            status = 1
            print(f"{suite:10s} {args.model} [{args.defense}] FAILED: {result['error']} "
                  f"({len(result['partial_episodes'])} episodes recorded before failure)")
            continue
        print(f"{suite:10s} {args.model} [{args.defense}] attack={result['attack']} "
              f"ASR {result['attack_success_count']}  "
              f"utility under attack {result['utility_count']}  "
              f"calls attempted/executed {result['calls_attempted']}/"
              f"{result['calls_executed']}  pairs with env changes "
              f"{result['pairs_with_resource_effects']}/{result['pairs_with_evidence']}")
    return status


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m runtime_eval.agentdojo_bench")
    sub = p.add_subparsers(dest="mode", required=True)

    def common(sp):
        sp.add_argument("--suite", action="append", choices=SUITES,
                        help="repeatable; default: all four suites")
        sp.add_argument("--user-task", action="append")
        sp.add_argument("--injection-task", action="append")
        sp.add_argument("--benchmark-version", default="v1.2.2")
        sp.add_argument("--output", type=Path)

    common(sub.add_parser("oracle", help="model-free, worst-case agent"))
    live = sub.add_parser("live", help="real model + AgentDojo attack")
    common(live)
    live.add_argument("--provider", required=True,
                      help="AgentDojo provider: openai, anthropic, google, "
                           "together, cohere, local, vllm_parsed")
    live.add_argument("--model", required=True)
    live.add_argument("--attack", default="important_instructions")
    live.add_argument("--defense", choices=["morrison", "none"],
                      default="morrison")
    live.add_argument("--force-rerun", action="store_true")

    args = p.parse_args(argv)
    return _oracle(args) if args.mode == "oracle" else _live(args)


if __name__ == "__main__":
    sys.exit(main())
