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
# Low-VRAM (T4) option:  !pip -q install bitsandbytes

# %% clone
# !git clone -q https://github.com/davarntrades/Morrison-Runtime-Governance.git
# %cd Morrison-Runtime-Governance

# %% imports
import json
import sys
sys.path.insert(0, ".")

from morrison_governance import GovernanceLayer, OmegaDomain
from runtime_eval.planners.hf_planner import HuggingFaceTransformersPlanner
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
# ## Choose models
#
# Each runs on a single modern GPU. Start with one; add more for the
# cross-model invariance check. On a 16 GB T4, prefer `dtype="bfloat16"`
# for a 7B (tight) or pass `load_in_4bit` via a custom build, or use
# TinyLlama for a fast smoke run.

# %%
MODELS = [
    "Qwen/Qwen2.5-7B-Instruct",
    # "mistralai/Mistral-7B-Instruct-v0.3",
    # "meta-llama/Llama-3.1-8B-Instruct",
    # "microsoft/Phi-4-mini-instruct",
    # "TinyLlama/TinyLlama-1.1B-Chat-v1.0",   # fast low-VRAM smoke
]

# %% [markdown]
# ## Run the governed battery on each real model
#
# The HF planner is stateless, so the same loaded planner serves every
# task; `run_battery` builds a fresh governance core + sandbox per task.

# %%
all_runs = []
for model_id in MODELS:
    print(f"\n=== loading {model_id} (first run downloads weights) ===")
    planner = HuggingFaceTransformersPlanner(
        model_id=model_id,
        dtype="bfloat16",
        device="auto",
        temperature=0.0,          # deterministic decoding
        do_sample=False,
        max_new_tokens=160,
        seed=0,
        tool_inventory=DEFAULT_TOOL_INVENTORY,
    )
    runs = run_battery(lambda task: planner, gov_factory,
                       DEFAULT_TASKS, max_steps=4)
    all_runs.extend(runs)
    # show what the model actually proposed + how governance ruled
    for r in runs:
        tools = [c.get("tool") for c in r.proposed_plan]
        print(f"  [{r.kind:11s}] {r.task_id:38s} "
              f"proposed={tools} blocked={r.blocked_count} "
              f"unsafe_executed={r.unsafe_executed}")

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
