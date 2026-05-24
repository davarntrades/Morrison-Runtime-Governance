"""Planner registry — hot-swap planners by name from the CLI / Colab."""

from __future__ import annotations

from typing import Callable

from runtime_eval.planners.base import Planner


# A factory takes (**kwargs) and returns a Planner.
PlannerFactory = Callable[..., Planner]


PLANNER_REGISTRY: dict[str, PlannerFactory] = {}


def register_planner(name: str):
    def _wrap(factory: PlannerFactory):
        PLANNER_REGISTRY[name] = factory
        return factory
    return _wrap


def get_planner(name: str, **kwargs) -> Planner:
    if name not in PLANNER_REGISTRY:
        raise KeyError(
            f"unknown planner '{name}'. Known: "
            f"{sorted(PLANNER_REGISTRY)}"
        )
    return PLANNER_REGISTRY[name](**kwargs)


# ─────────────────────────────────────────────────────────────
# Built-ins — deterministic (always available)
# ─────────────────────────────────────────────────────────────

@register_planner("deterministic.scripted")
def _make_scripted(script=(), **_kw):
    from runtime_eval.planners.deterministic import ScriptedPlanner
    return ScriptedPlanner(script=list(script))


@register_planner("deterministic.profile.gpt_style")
def _make_gpt(base_plan=(), seed: int = 0, **_kw):
    from runtime_eval.planners.deterministic import ProfilePlanner
    return ProfilePlanner(base_plan=list(base_plan),
                          profile="gpt_style", seed=seed)


@register_planner("deterministic.profile.claude_style")
def _make_claude(base_plan=(), seed: int = 0, **_kw):
    from runtime_eval.planners.deterministic import ProfilePlanner
    return ProfilePlanner(base_plan=list(base_plan),
                          profile="claude_style", seed=seed)


@register_planner("deterministic.profile.qwen_style")
def _make_qwen_s(base_plan=(), seed: int = 0, **_kw):
    from runtime_eval.planners.deterministic import ProfilePlanner
    return ProfilePlanner(base_plan=list(base_plan),
                          profile="qwen_style", seed=seed)


@register_planner("deterministic.profile.llama_style")
def _make_llama_s(base_plan=(), seed: int = 0, **_kw):
    from runtime_eval.planners.deterministic import ProfilePlanner
    return ProfilePlanner(base_plan=list(base_plan),
                          profile="llama_style", seed=seed)


@register_planner("deterministic.profile.stochastic")
def _make_stoch(base_plan=(), seed: int = 0, **_kw):
    from runtime_eval.planners.deterministic import ProfilePlanner
    return ProfilePlanner(base_plan=list(base_plan),
                          profile="stochastic_decoding", seed=seed)


# ─────────────────────────────────────────────────────────────
# Live HF planners — production list (require GPU + transformers)
# ─────────────────────────────────────────────────────────────

_HF_PRIMARY = [
    ("hf.qwen2_5_7b",   "Qwen/Qwen2.5-7B-Instruct"),
    ("hf.llama3_1_8b",  "meta-llama/Llama-3.1-8B-Instruct"),
    ("hf.mistral7b_v3", "mistralai/Mistral-7B-Instruct-v0.3"),
    ("hf.deepseek_r1_qwen7b",  "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"),
    ("hf.phi4_mini",    "microsoft/Phi-4-mini-instruct"),
]
_HF_OPTIONAL = [
    ("hf.qwen2_5_14b",  "Qwen/Qwen2.5-14B-Instruct"),
    ("hf.hermes2_llama3_8b", "NousResearch/Hermes-2-Pro-Llama-3-8B"),
    ("hf.deepseek_r1_llama8b", "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"),
    ("hf.tinyllama_1_1b", "TinyLlama/TinyLlama-1.1B-Chat-v1.0"),
    ("hf.mixtral_8x7b", "mistralai/Mixtral-8x7B-Instruct-v0.1"),
]


def _register_hf(name: str, model_id: str):
    def _factory(**kw):
        from runtime_eval.planners.hf_planner import HuggingFaceTransformersPlanner
        return HuggingFaceTransformersPlanner(model_id=model_id, **kw)
    PLANNER_REGISTRY[name] = _factory


for _n, _m in (_HF_PRIMARY + _HF_OPTIONAL):
    _register_hf(_n, _m)


# ─────────────────────────────────────────────────────────────
# vLLM
# ─────────────────────────────────────────────────────────────

@register_planner("vllm")
def _make_vllm(model_id: str, **kw):
    from runtime_eval.planners.vllm_planner import VLLMPlanner
    return VLLMPlanner(model_id=model_id, **kw)
