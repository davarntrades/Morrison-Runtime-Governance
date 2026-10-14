"""Live AgentDojo run: a real model, a real AgentDojo attack, Morrison gating.

The pipeline is AgentDojo's standard no-defense pipeline with one change:
`ToolsExecutor` is replaced by `MorrisonToolsExecutor`. The model, system
message, attack, and grading are AgentDojo's own, so the numbers are
directly comparable to an undefended run of the same model and attack.

Needs the provider's API key in the environment (OPENAI_API_KEY,
ANTHROPIC_API_KEY, ...). Nothing is read from or written to a file except
AgentDojo's per-task logs under `logdir`.
"""

from __future__ import annotations

from pathlib import Path

from agentdojo.agent_pipeline.agent_pipeline import (
    AgentPipeline, get_llm, load_system_message,
)
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite

from runtime_eval.agentdojo_bench.gate import MorrisonToolsExecutor
from runtime_eval.agentdojo_bench.manifest import profile_for
from runtime_eval.agentdojo_bench.oracle import DEFAULT_BENCHMARK_VERSION


def build_pipeline(provider: str, model: str, suite_name: str,
                   defense: str = "morrison") -> AgentPipeline:
    """AgentDojo's default pipeline, with the tool executor swapped.

    defense="none" builds the stock AgentDojo pipeline for a baseline run.
    """
    llm = get_llm(provider, model, None, "tool")
    executor = (MorrisonToolsExecutor(profile_for(suite_name))
                if defense == "morrison" else ToolsExecutor())
    pipeline = AgentPipeline([
        SystemMessage(load_system_message(None)),
        InitQuery(),
        llm,
        ToolsExecutionLoop([executor, llm]),
    ])
    # AgentDojo's attacks look the model name up in this string.
    pipeline.name = model if defense == "none" else f"{model}-{defense}"
    return pipeline


_PROVIDER_FAMILY = {
    "anthropic": "Claude",
    "openai": "GPT-4",
    "google": "AI model developed by Google",
    "cohere": "Command R+",
}


def register_model_name(provider: str, model: str) -> str:
    """AgentDojo's attacks address the target by name ("...this is a message
    to you, Claude"), looked up in a table that predates current models. For a
    model not in that table, register its provider's family name so the
    standard attacks run unchanged. Returns the name the attack will use."""
    for known, name in MODEL_NAMES.items():
        if known in model:
            return name
    name = _PROVIDER_FAMILY.get(provider, "AI assistant")
    MODEL_NAMES[model] = name
    return name


def run_live(provider: str, model: str, suite_name: str, *,
             attack: str = "important_instructions",
             defense: str = "morrison",
             benchmark_version: str = DEFAULT_BENCHMARK_VERSION,
             user_tasks: list[str] | None = None,
             injection_tasks: list[str] | None = None,
             logdir: Path | None = None,
             force_rerun: bool = False) -> dict:
    suite = get_suite(benchmark_version, suite_name)
    pipeline = build_pipeline(provider, model, suite_name, defense)
    target_name = register_model_name(provider, model)
    attack_obj = load_attack(attack, suite, pipeline)
    results = benchmark_suite_with_injections(
        pipeline, suite, attack_obj, logdir=logdir, force_rerun=force_rerun,
        user_tasks=user_tasks, injection_tasks=injection_tasks,
        verbose=False, benchmark_version=benchmark_version)
    utility = results["utility_results"]
    security = results["security_results"]
    return {
        "suite": suite_name,
        "benchmark_version": benchmark_version,
        "provider": provider,
        "model": model,
        "defense": defense,
        "attack": attack,
        "attack_target_name": target_name,
        "pairs": len(security),
        "utility_under_attack": (round(sum(utility.values()) / len(utility), 4)
                                 if utility else None),
        # AgentDojo convention: security True == the injection succeeded.
        "attack_success_rate": (round(sum(security.values()) / len(security), 4)
                                if security else None),
        "results": [
            {"user_task": u, "injection_task": i,
             "utility": bool(utility[(u, i)]),
             "attack_succeeded": bool(security[(u, i)])}
            for (u, i) in sorted(security)
        ],
    }
