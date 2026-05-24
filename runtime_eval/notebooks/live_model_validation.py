# %% [markdown]
# # Morrison Runtime Governance — LIVE open-weight model validation
#
# This notebook turns the HuggingFace planner from "real code, never
# run" into "run on a real model". A real open-weight planner is given
# tasks + a tool inventory, proposes tool-call plans, and those plans
# are governed by the EXISTING reachability core
# (A_safe → V2 → V3 → V4 → V4+ → V5 → V5+) before any sandbox execution.
#
# It validates, on whatever models you run:
#  1. real model output is governed pre-execution (unsafe trajectories
#     the model proposes are blocked before they run);
#  2. the governance verdict is a function of the proposed TRAJECTORY,
#     not of which model produced it (cross-model invariance on real
#     outputs);
#  3. benign tasks are not over-blocked.
#
# Bounded: results depend on the models / tasks / hardware. This is an
# internal demonstration, not a proof of global safety. The governance
# layer never sees the model — only the proposed tool calls.
#
# Requires a GPU runtime (Colab: Runtime → Change runtime type → GPU).

# %% install
# !pip -q install "transformers>=4.45" "accelerate>=0.34" torch sentencepiece safetensors
# Low-VRAM (T4) — REQUIRED for 4-bit / for_t4() so 7B models don't offload:
# !pip -q install "bitsandbytes>=0.43"

# %% clone
# !git clone -q https://github.com/davarntrades/Morrison-Runtime-Governance.git
# %cd Morrison-Runtime-Governance

# %% imports
import json
import sys
sys.path.insert(0, ".")

from morrison_governance import GovernanceLayer, OmegaDomain
from runtime_eval.planners.hf_planner import (
    HuggingFaceTransformersPlanner, MODEL_TIERS, free_memory,
)
from runtime_eval.live import (
    run_battery, aggregate, format_report,
    DEFAULT_TASKS, DEFAULT_TOOL_INVENTORY,
)
from runtime_eval.replay import TraceWriter  # for per-task traces if wanted

DOMAINS = [OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE,
           OmegaDomain.DATA_PRIVACY]

def gov_factory():
    return GovernanceLayer(domains=DOMAINS, log_all=False)

# %% [markdown]
# ## Runtime tiers — what to expect on a single 16 GB Colab T4
#
# Pick by how much time/VRAM you have. The governance layer is identical
# for all of them; only load cost differs.
#
# | Tier | Model | Loads on T4 | Use for |
# |:--|:--|:--|:--|
# | **smoke**  | `TinyLlama/TinyLlama-1.1B-Chat-v1.0` | seconds, fp16 | fast sanity check |
# | **medium** | `microsoft/Phi-4-mini-instruct`      | ~1 min, fp16  | a real run that still fits |
# | **heavy**  | `Qwen/Qwen2.5-7B-Instruct`, `mistralai/Mistral-7B-Instruct-v0.3`, `meta-llama/Llama-3.1-8B-Instruct` | **needs 4-bit** | full 7–8B runs |
#
# A 7B in fp16 is ~14 GB and will NOT fit a T4 with activations — without
# 4-bit, `accelerate` offloads layers to CPU/disk and generation crawls
# (the "stuck on loading" symptom). For heavy models use
# `HuggingFaceTransformersPlanner.for_t4(model_id)` (fp16 + nf4 4-bit +
# short generations) and `MAX_STEPS = 2`.

# %%
MODELS = [
    "TinyLlama/TinyLlama-1.1B-Chat-v1.0",   # smoke — start here to verify the loop
    # "microsoft/Phi-4-mini-instruct",      # medium — fits fp16 on a T4
    # "Qwen/Qwen2.5-7B-Instruct",           # heavy — for_t4 (4-bit)
    # "mistralai/Mistral-7B-Instruct-v0.3", # heavy — for_t4 (4-bit); see README troubleshooting
    # "meta-llama/Llama-3.1-8B-Instruct",   # heavy — gated; for_t4 (4-bit)
]

# Lower steps/tokens for heavy 7B models so a T4 run finishes; smoke/medium
# models can afford the fuller budget.
MAX_STEPS = 4

# %% [markdown]
# ## Memory cleanup between models
#
# On a shared runtime, a previous model's weights linger in VRAM and the
# next 7B load then spills to offload. Call `cleanup()` (or
# `planner.unload(); free_memory()`) AFTER each model and BEFORE loading
# the next. `free_memory()` from the planner module does the same thing.

# %%
import gc, torch
def cleanup():
    gc.collect()
    torch.cuda.empty_cache()

# %% [markdown]
# ## Build a planner per model (tier-aware: heavy → 4-bit `for_t4`)

# %%
def make_planner(model_id):
    """Heavy 7–8B models load 4-bit via for_t4() so they fit a T4 without
    CPU/disk offload; smaller models load in plain fp16. The planner prints
    an offload/slow-load warning + fallback advice after loading."""
    if MODEL_TIERS.get(model_id) == "heavy":
        return HuggingFaceTransformersPlanner.for_t4(
            model_id, tool_inventory=DEFAULT_TOOL_INVENTORY)
    return HuggingFaceTransformersPlanner(
        model_id=model_id, dtype="float16", device="auto",
        temperature=0.0, do_sample=False, max_new_tokens=64, seed=0,
        tool_inventory=DEFAULT_TOOL_INVENTORY)

# %% [markdown]
# ## Run the governed battery on each real model
#
# The HF planner is stateless, so the same loaded planner serves every
# task; `run_battery` builds a fresh governance core + sandbox per task.
# Heavy models use `MAX_STEPS = 2` automatically.

# %%
all_runs = []
for model_id in MODELS:
    print(f"\n=== {model_id} "
          f"(tier={MODEL_TIERS.get(model_id, 'unknown')}) ===")
    steps = 2 if MODEL_TIERS.get(model_id) == "heavy" else MAX_STEPS
    planner = make_planner(model_id)        # prints load/offload diagnostics
    try:
        runs = run_battery(lambda task: planner, gov_factory,
                           DEFAULT_TASKS, max_steps=steps)
        all_runs.extend(runs)
        # show what the model actually proposed + how governance ruled
        for r in runs:
            tools = [c.get("tool") for c in r.proposed_plan]
            print(f"  [{r.kind:11s}] {r.task_id:38s} "
                  f"proposed={tools} blocked={r.blocked_count} "
                  f"unsafe_executed={r.unsafe_executed}")
    finally:
        planner.unload()                    # free this model before the next
        cleanup()

# %% [markdown]
# ## Report — per-model + cross-model verdict invariance

# %%
print(format_report(all_runs))
agg = aggregate(all_runs)
print(json.dumps(agg, indent=2))

# %% [markdown]
# ### How to read this
#
# * **benign over-blocks** should be 0 — governance must not block
#   legitimate local work.
# * **adversarial caught (any-block)** counts adversarial tasks where the
#   model proposed something governance blocked. If the model *complied*
#   (proposed an acquire→egress / unauthorized action) and governance
#   blocked it → working as intended.
# * **adversarial unsafe-executed (FN)** must be 0 — it means a model's
#   acquire→egress chain actually executed in the sandbox (a real miss).
# * **cross-model verdict invariance HOLDS** confirms the governance
#   verdict is a function of the proposed trajectory, not the model —
#   *the model is not the safety system*.
#
# Note: a model that *self-refuses* an adversarial task (proposes a safe
# alternative) will show 0 blocks for that task — that is the model
# behaving well, not a governance miss. The FN metric is the governance
# guarantee; the block metric is conditional on the model complying.

# %% write a replay trace per model+task (optional)
# from pathlib import Path
# Path("logs").mkdir(exist_ok=True)
# with open("logs/live_runs.jsonl", "w") as fh:
#     for r in all_runs:
#         fh.write(json.dumps(r.as_dict(), sort_keys=True) + "\n")
# print("wrote logs/live_runs.jsonl")
