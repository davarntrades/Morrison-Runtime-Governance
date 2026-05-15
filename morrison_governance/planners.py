"""
Deterministic planner-style profiles.

The governance layer is model-agnostic: the *same* executable trajectory
must receive the *same* verdict regardless of which planner produced it.
Different LLM planners (GPT-, Claude-, Qwen-, Llama-style) express the
same intent with different surface structure — reordered safe prefixes,
inserted retries, paraphrased arguments, decomposed steps, verbose
context.

These profiles are deterministic structural transforms (no model calls,
no RNG without an explicit seed) standing in for that planner divergence,
used to assert governance invariance across planner identity.

Geometry does not change. Only Ω changes — and Ω is not touched here.
"""

import copy
import random
from typing import Callable


PlannerTransform = Callable[[list], list]


def _gpt_style(plan: list, seed: int = 0) -> list:
    """Concise: minimal restructuring, light arg paraphrase."""
    out = copy.deepcopy(plan)
    for step in out:
        a = step.get("args")
        if isinstance(a, dict):
            for k, v in list(a.items()):
                if isinstance(v, str):
                    a[k] = v.strip()
    return out


def _claude_style(plan: list, seed: int = 0) -> list:
    """Verbose: adds explanatory context fields, preserves ordering."""
    out = copy.deepcopy(plan)
    for i, step in enumerate(out):
        step.setdefault("rationale", f"step {i}: proceeding per plan")
        step.setdefault("planner", "claude-style")
    return out


def _qwen_style(plan: list, seed: int = 0) -> list:
    """Decomposes: splits the trailing step into a benign no-op + the step,
    a common 'think then act' decomposition. Intent is unchanged."""
    out = copy.deepcopy(plan)
    if out:
        out = out[:-1] + [{"tool": "analyze",
                           "args": {"q": "intermediate reasoning"}},
                          out[-1]]
    return out


def _llama_style(plan: list, seed: int = 0) -> list:
    """Retry-prone: inserts an idempotent retry of the first step."""
    out = copy.deepcopy(plan)
    if out:
        retry = copy.deepcopy(out[0])
        if isinstance(retry.get("args"), dict):
            retry["args"]["_retry"] = True
        out = [out[0], retry] + out[1:]
    return out


def _stochastic_style(plan: list, seed: int = 0) -> list:
    """Decoding-variance: deterministically permutes only a leading run of
    order-independent benign steps (never moves a sink past a source)."""
    rng = random.Random(seed)
    out = copy.deepcopy(plan)
    # find the contiguous benign prefix (steps with no path/url/sql/mode)
    def benign(s):
        a = s.get("args", {})
        keys = {str(k).lower() for k in a} if isinstance(a, dict) else set()
        return not (keys & {"path", "url", "sql", "mode", "to", "recipient"})
    i = 0
    while i < len(out) and benign(out[i]):
        i += 1
    prefix = out[:i]
    rng.shuffle(prefix)
    return prefix + out[i:]


PLANNER_PROFILES: dict[str, PlannerTransform] = {
    "gpt_style": _gpt_style,
    "claude_style": _claude_style,
    "qwen_style": _qwen_style,
    "llama_style": _llama_style,
    "stochastic_decoding": _stochastic_style,
}


def all_planner_renderings(plan: list, seed: int = 0) -> dict:
    """Return {profile_name: transformed_plan} for every planner profile.
    Determinism: identical (plan, seed) → identical renderings."""
    return {name: fn(plan, seed) for name, fn in PLANNER_PROFILES.items()}
