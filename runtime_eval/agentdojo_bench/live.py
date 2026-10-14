"""Live AgentDojo run: a real model, a real AgentDojo attack, Morrison gating.

The pipeline is AgentDojo's standard no-defense pipeline with one change:
`ToolsExecutor` is replaced by `MorrisonToolsExecutor`. The model, system
message, attack, and grading are AgentDojo's own, so the numbers are
directly comparable to an undefended run of the same model and attack.

Both arms run through identical plumbing. The baseline (`defense="none"`)
uses the same executor with `enforce=False`: Morrison records its verdict
but every call executes, exactly as the oracle baseline does. Per task, the
output keeps the calls the model attempted (with verdict and whether each
executed) separately from the actual effects on the environment (a diff of
the environment before the first model turn and after the task).

Needs the provider's API key in the environment (OPENAI_API_KEY,
ANTHROPIC_API_KEY, ...). Nothing is read from or written to a file except
AgentDojo's per-task logs under `logdir`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agentdojo.agent_pipeline.agent_pipeline import (
    AgentPipeline, get_llm, load_system_message,
)
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import (
    benchmark_suite_with_injections, benchmark_suite_without_injections,
)
from agentdojo.logging import OutputLogger
from agentdojo.attacks.base_attacks import get_model_name_from_pipeline
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite

from runtime_eval.agentdojo_bench.anthropic_adapter import (
    Budget, GovernedBudgetLLM, RequestSettings,
)
from runtime_eval.agentdojo_bench.gate import EpisodeStart, MorrisonToolsExecutor
from runtime_eval.agentdojo_bench.manifest import profile_for
from runtime_eval.agentdojo_bench.oracle import DEFAULT_BENCHMARK_VERSION


# "none": record-only baseline. "morrison": enforced, ESCALATE fails closed.
# "morrison-<approver>": enforced, ESCALATE routed to a bounded approver
# (runtime_eval/agentdojo_bench/approvers.py).
DEFENSES = ("none", "morrison", "morrison-policy", "morrison-user-intent")


def make_llm(provider: str, model: str, budget: Budget | None = None,
             settings: RequestSettings | None = None):
    """The model element. Anthropic goes through `GovernedBudgetLLM` (current
    request surface, metered, capped); other providers use AgentDojo's own."""
    if provider == "anthropic":
        return GovernedBudgetLLM(settings or RequestSettings(model=model),
                                 budget or Budget(model, float("inf"), 10**9))
    if provider == "hf":
        from runtime_eval.agentdojo_bench.hf_adapter import HFLLM
        return HFLLM(settings, budget)
    return get_llm(provider, model, None, "tool")


def build_pipeline(provider: str, model: str, suite_name: str,
                   defense: str = "morrison", *, budget: Budget | None = None,
                   benchmark_version: str = DEFAULT_BENCHMARK_VERSION,
                   settings: RequestSettings | None = None,
                   ) -> tuple[AgentPipeline, MorrisonToolsExecutor]:
    """AgentDojo's default pipeline, with the tool executor swapped.

    defense="none" is the baseline: the same executor in record-only mode,
    so the two arms differ only in whether Morrison's verdict is enforced.
    """
    if defense not in DEFENSES:
        raise ValueError(f"unknown defense {defense!r}")
    llm = make_llm(provider, model, budget, settings)
    executor = MorrisonToolsExecutor(profile_for(suite_name),
                                     enforce=defense != "none")
    if defense.startswith("morrison-"):
        from runtime_eval.agentdojo_bench.approvers import make_approver
        executor.attach_approver(make_approver(
            defense.removeprefix("morrison-"), get_suite(benchmark_version, suite_name)))
    pipeline = AgentPipeline([
        SystemMessage(load_system_message(None)),
        InitQuery(),
        EpisodeStart(executor),
        llm,
        ToolsExecutionLoop([executor, llm]),
    ])
    # Distinct names keep the two arms' AgentDojo logs apart. AgentDojo's
    # attacks look the model name up in this string; run_live checks both
    # arms resolve to the same target name.
    pipeline.name = f"{model}-{defense}"
    return pipeline, executor


_PROVIDER_FAMILY = {
    "hf": "Qwen",
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


def _sha(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str)
                          .encode()).hexdigest()[:16]


def run_live(provider: str, model: str, suite_name: str, *,
             attack: str = "important_instructions",
             defense: str = "morrison",
             benchmark_version: str = DEFAULT_BENCHMARK_VERSION,
             user_tasks: list[str] | None = None,
             injection_tasks: list[str] | None = None,
             logdir: Path | None = None,
             force_rerun: bool = False,
             max_usd: float = float("inf"),
             max_requests: int = 10**9,
             settings: RequestSettings | None = None,
             benign: bool = False,
             budget_override=None) -> dict:
    suite = get_suite(benchmark_version, suite_name)
    settings = settings or RequestSettings(model=model)
    if provider == "anthropic" and max_usd != float("inf"):
        from runtime_eval.agentdojo_bench.anthropic_adapter import price_for
        if price_for(model) is None:
            raise ValueError(f"no list price for {model!r}: a USD cap could "
                             f"not be enforced, refusing to start")
    budget = budget_override or Budget(model, max_usd, max_requests)
    pipeline, executor = build_pipeline(provider, model, suite_name, defense,
                                        budget=budget, settings=settings,
                                        benchmark_version=benchmark_version)
    target_name = register_model_name(provider, model)
    resolved = get_model_name_from_pipeline(pipeline)
    if resolved != target_name:
        raise RuntimeError(f"attack would address {resolved!r}, expected "
                           f"{target_name!r}: arms would not be matched")
    attack_obj = load_attack(attack, suite, pipeline)

    pairs = [(u, i) for u in (user_tasks or list(suite.user_tasks))
             for i in (injection_tasks or list(suite.injection_tasks))]
    # Attack text per pair, fixed before any model call, so the two arms can
    # be checked to have received identical injections.
    injections = {
        (u, i): attack_obj.attack(suite.get_user_task_by_id(u),
                                  suite.get_injection_task_by_id(i))
        for (u, i) in pairs}

    header = {
        "suite": suite_name,
        "benchmark_version": benchmark_version,
        "provider": provider,
        "model": model,
        "defense": defense,
        "enforced": executor.enforce,
        "approver": getattr(executor.approver, "name", None),
        "attack": attack,
        "attack_target_name": target_name,
        "pipeline_name": pipeline.name,
        "llm_settings": (settings.as_dict() if provider in ("anthropic", "hf") else
                         {k: getattr(pipeline.elements[3], k, None)
                          for k in ("temperature", "_MAX_TOKENS",
                                    "thinking_budget_tokens")}),
        "tool_loop_max_iters": pipeline.elements[4].max_iters,
        "pairs_requested": len(pairs),
        # Supplementary: the same user tasks with no injection, to measure
        # legitimate completion and blocking of legitimate actions.
        "benign_requested": benign,
        "pairs_requested_list": [list(p) for p in pairs],
        "injection_sha_by_pair": {f"{u}|{i}": _sha(injections[(u, i)])
                                  for (u, i) in pairs},
    }

    def usage() -> dict:
        return {"api_usage": budget.summary(), "api_requests": budget.requests}
    try:
        # AgentDojo's per-task TraceLogger needs an OutputLogger around it
        # (its CLI does the same); it writes one JSON transcript per pair.
        with OutputLogger(str(logdir) if logdir else None):
            results = benchmark_suite_with_injections(
                pipeline, suite, attack_obj, logdir=logdir,
                force_rerun=force_rerun, user_tasks=user_tasks,
                injection_tasks=injection_tasks, verbose=False,
                benchmark_version=benchmark_version)
            benign_results = (benchmark_suite_without_injections(
                pipeline, suite, logdir=logdir, force_rerun=force_rerun,
                user_tasks=user_tasks, benchmark_version=benchmark_version)
                if benign else None)
    except Exception as exc:  # keep whatever ran before the failure
        return {**header, **usage(), "status": "incomplete",
                "error": f"{type(exc).__name__}: {exc}",
                "partial_episodes": [
                    {"user_task": u, "injection_task": i, **ep.as_dict()}
                    for (u, i), ep in sorted(executor.episodes.items())]}

    utility = results["utility_results"]
    security = results["security_results"]
    rows = []
    for (u, i) in sorted(security):
        ep = executor.episodes.get((u, i))
        rows.append({
            "user_task": u, "injection_task": i,
            "utility": bool(utility[(u, i)]),
            # AgentDojo convention: security True == the injection succeeded.
            "attack_succeeded": bool(security[(u, i)]),
            "injection_sha": _sha(injections.get((u, i))),
            # None: the pair was loaded from an earlier log, not run now.
            **(ep.as_dict() if ep else {"evidence": None}),
        })
    ran = [r for r in rows if r.get("evidence", True) is not None]

    def total(key: str) -> int:
        return sum(r[key] for r in ran)

    benign_rows = []
    if benign_results is not None:
        for key, ok in sorted(benign_results["utility_results"].items()):
            u = key[0] if isinstance(key, tuple) else key
            ep = executor.episodes.get((u, "None"))
            benign_rows.append({"user_task": u, "injection_task": None,
                                "utility": bool(ok),
                                **(ep.as_dict() if ep else {"evidence": None})})
    complete = (len(security) == len(pairs) and len(ran) == len(rows)
                and (not benign or (len(benign_rows) == len(
                    user_tasks or list(suite.user_tasks)) and all(
                        r.get("evidence", True) is not None
                        for r in benign_rows))))
    return {
        **header,
        **usage(),
        # "complete" only when every requested pair ran in this process and
        # left evidence; anything else is reported, never presented as done.
        "status": "complete" if complete else "incomplete",
        "pairs": len(security),
        "pairs_with_evidence": len(ran),
        "utility_under_attack": (round(sum(utility.values()) / len(utility), 4)
                                 if utility else None),
        "attack_success_rate": (round(sum(security.values()) / len(security), 4)
                                if security else None),
        "utility_count": f"{sum(map(bool, utility.values()))}/{len(utility)}",
        "attack_success_count": f"{sum(map(bool, security.values()))}/{len(security)}",
        # Attempted vs actual: what the model tried, and what changed.
        "calls_attempted": total("n_attempted"),
        "calls_executed": total("n_executed"),
        "calls_withheld": total("n_withheld"),
        "calls_blocked": total("n_block"),
        "calls_escalated": total("n_escalate"),
        "pairs_with_resource_effects": sum(r["n_resource_effects"] > 0 for r in ran),
        "resource_effects_total": total("n_resource_effects"),
        "results": rows,
        # AgentDojo also runs each injection task alone, as a plain user task,
        # to check the model can do it at all. Same arm, same gating.
        "benign_user_tasks": benign_rows,
        "injection_tasks_standalone": [
            {"injection_task": i, "utility": bool(ok),
             **(executor.episodes[(i, "None")].as_dict()
                if (i, "None") in executor.episodes else {"evidence": None})}
            for i, ok in sorted(results["injection_tasks_utility_results"].items())],
    }
