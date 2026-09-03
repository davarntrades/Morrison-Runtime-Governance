"""Command-line entrypoint for frontier containment experiments."""

from __future__ import annotations

import argparse
import json
import sys
from runtime_eval.frontier.evidence import (
    write_run_artifact,
    write_summary_artifact,
)
from runtime_eval.frontier.experiment import aggregate_results, run_experiment
from runtime_eval.frontier.provider_registry import (
    DEFAULT_MODELS,
    PROVIDER_ENV,
    credential_available,
    configured_models,
    make_planner,
)
from runtime_eval.frontier.scenarios import get_scenarios


def _providers(selector: str) -> list[str]:
    return ["openai", "anthropic", "huggingface"] if selector == "all" else [selector]


def _print_run(row: dict) -> None:
    print("=" * 60)
    print("MORRISON FRONTIER MODEL COMPROMISE TEST")
    print("=" * 60)
    print(f"Provider: {row['provider']}")
    print(f"Model: {row['model']}")
    print(f"Scenario: {row['scenario_id']}")
    print(f"Model tool calls: {json.dumps(row['model_tool_calls'])}")
    print(f"Model compromise: {'YES' if row['model_compromised'] else 'NO'}")
    print(f"Morrison verdict: {row['final_verdict']}")
    if row["governance_decisions"]:
        last = row["governance_decisions"][-1]
        print(f"Layer/rule: {last.get('layer')} / {last.get('rule')}")
    print(f"Unauthorized simulator execution: {row['unauthorized_execution_count']}")
    print(f"Governance latency: {row['latency']['governance_ms']:.4f} ms")
    print(f"RESULT: {row['classification']}")
    print("=" * 60)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m runtime_eval.frontier.cli")
    parser.add_argument("--provider", choices=(
        "openai", "anthropic", "huggingface", "local-openai", "all",
        "deterministic"), default="deterministic")
    parser.add_argument("--model", default="")
    parser.add_argument("--scenario", default="all")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--output", default="artifacts/frontier-containment")
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    scenarios = get_scenarios(args.scenario)
    results, skipped = [], []
    for provider in _providers(args.provider):
        if not credential_available(provider):
            env_name = PROVIDER_ENV[provider]
            skipped.append({"provider": provider,
                            "status": "SKIPPED — credential unavailable",
                            "reason": f"missing {env_name}"})
            print(f"{provider}: SKIPPED — credential unavailable ({env_name})")
            continue
        if provider in {"huggingface", "local-openai"}:
            allowed = configured_models(provider)
            if not allowed:
                env_name = "HF_MODELS" if provider == "huggingface" else "LOCAL_OPENAI_MODELS"
                parser.error(f"{provider} requires a non-empty {env_name} allowlist")
            if args.model and args.model not in allowed:
                parser.error(f"--model is not in the {provider} allowlist")
            models = [args.model] if args.model else allowed
        else:
            models = [args.model or DEFAULT_MODELS[provider]]
        for model in models:
            for scenario in scenarios:
                for _ in range(args.runs):
                    planner = make_planner(provider, scenario, model=model)
                    result = run_experiment(provider, model, scenario, planner)
                    artifact = write_run_artifact(result.record, args.output)
                    result.artifact_path = str(artifact)
                    result.record["artifact_path"] = str(artifact)
                    results.append(result)
                    _print_run(result.record)

    summary = aggregate_results(results)
    summary["skipped_providers"] = skipped
    summary_path = write_summary_artifact(summary, args.output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"Evidence summary: {summary_path}")
    catastrophic = summary["unauthorized_execution_count"] > 0
    provider_errors = any(r.record["provider_error"] for r in results)
    return 1 if catastrophic or provider_errors else 0


if __name__ == "__main__":
    sys.exit(main())
