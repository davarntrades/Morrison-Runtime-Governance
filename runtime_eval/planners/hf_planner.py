"""HuggingFace transformers planner — live open-weight planners.

Loads any chat-template-capable instruction-tuned model via
`transformers.AutoModelForCausalLM` and asks it to emit a JSON
tool-call object. The harness then routes the parsed tool calls
through the existing reachability-based governance middleware; this
file does NO safety filtering itself.

GPU is required for the production models. The deterministic
stand-ins in `deterministic.py` are the right choice for CI / sandboxes
without GPU; this adapter raises a clear error if `transformers` is
not available.

Determinism: with `temperature=0`, `do_sample=False`, fixed seed, the
underlying tokenizer + model + generation_config produce identical
output for identical input on the same hardware AND the same load config
(dtype / quantisation). 4-bit (`load_in_4bit`) changes the numerics, so
its outputs are self-consistent but need not match an fp16 load. Replay
is byte-identical per (model, hardware, load-config); cross-hardware or
cross-quantisation replay is NOT guaranteed.

Low-VRAM / Colab-T4 note: a 7B model in fp16 is ~14 GB and does not fit a
16 GB T4 alongside activations — `accelerate` then offloads layers to
CPU/disk, which does not crash but makes generation crawl (the "stuck
load" symptom). Use the `for_t4(...)` preset (fp16 + 4-bit + short
generations) for 7B-class models, call `free_memory()` between models on
a shared runtime, and watch for the offload warning printed after load.
None of this touches the governance core — it only changes how the
planner's weights are loaded."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from runtime_eval.planners.base import Planner, PlannerInfo, ToolCall


_TOOL_CALL_RE = re.compile(
    r"\{[^{}]*\"tool\"\s*:\s*\"[^\"]+\"[^{}]*\"args\"\s*:\s*\{[^{}]*\}[^{}]*\}",
    re.DOTALL,
)


# Runtime tier of each model on a single 16 GB T4, so evaluators know what
# to expect before they load anything. "smoke" = seconds; "medium" = a
# minute-ish; "heavy" = needs 4-bit (`for_t4`) or it offloads and crawls.
MODEL_TIERS = {
    "TinyLlama/TinyLlama-1.1B-Chat-v1.0": "smoke",
    "microsoft/Phi-4-mini-instruct":      "medium",
    "Qwen/Qwen2.5-7B-Instruct":           "heavy",
    "mistralai/Mistral-7B-Instruct-v0.3": "heavy",
    "meta-llama/Llama-3.1-8B-Instruct":   "heavy",
}

# Models to fall back to when a heavy model offloads / stalls on a T4.
_FALLBACK_MODELS = (
    "TinyLlama/TinyLlama-1.1B-Chat-v1.0  (smoke; ~1 GB, seconds to load)",
    "microsoft/Phi-4-mini-instruct       (medium; fits fp16 on a T4)",
    "or keep the model but pass load_in_4bit=True / use for_t4(...)",
)


def free_memory():
    """Release Python + CUDA caches between model loads.

    On a shared Colab/T4 runtime, call this AFTER you are done with one
    planner and BEFORE loading the next (and after `planner.unload()`),
    otherwise the previous model's VRAM lingers and the next 7B load
    spills to CPU/disk offload. No-op when torch/CUDA is unavailable."""
    import gc
    gc.collect()
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.ipc_collect()
    except Exception:                                    # noqa: BLE001
        pass


def recommend_fallback(reason: str = "") -> None:
    """Print an actionable low-VRAM recommendation (no auto-switching —
    the evaluator stays in control of which model runs)."""
    print("    ↳ recommendation"
          + (f" ({reason})" if reason else "") + ":")
    for line in _FALLBACK_MODELS:
        print(f"        • {line}")
    print("        • or restart the runtime to reclaim leaked VRAM "
          "(Runtime → Restart), then load one model at a time")


def _required_imports():
    try:
        import torch  # noqa: F401
        from transformers import AutoModelForCausalLM, AutoTokenizer  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "HuggingFaceTransformersPlanner requires `transformers`, "
            "`torch`, `accelerate`. Install them via "
            "`pip install -r runtime_eval/requirements.txt` on a GPU box "
            "or Colab. For offline CI use "
            "runtime_eval.planners.deterministic instead."
        ) from e


@dataclass
class HuggingFaceTransformersPlanner:
    """Live HF planner. Hot-swap models via `model_id`.

    Typical primary models (require GPU):
      - Qwen/Qwen2.5-7B-Instruct
      - meta-llama/Llama-3.1-8B-Instruct
      - mistralai/Mistral-7B-Instruct-v0.3
      - deepseek-ai/DeepSeek-R1-Distill-Qwen-7B
      - microsoft/Phi-4-mini-instruct

    The planner asks the model to emit a JSON `{"tool", "args"}`
    object. Output is parsed defensively; malformed output produces an
    empty proposal (fail-closed at the planner boundary)."""

    model_id: str
    device: str = "auto"
    dtype: str = "auto"
    temperature: float = 0.0
    do_sample: bool = False
    max_new_tokens: int = 256
    seed: int = 0
    system_prompt: Optional[str] = None
    tool_inventory: Optional[list[dict]] = None      # [{"name", "description", "args_schema"}]
    load_in_4bit: bool = False                       # T4-friendly nf4 quantisation
    bnb_4bit_quant_type: str = "nf4"                 # "nf4" | "fp4"
    slow_load_warn_s: float = 180.0                  # warn past this load time
    info: Optional[PlannerInfo] = None
    _model: object = field(default=None, repr=False)
    _tokenizer: object = field(default=None, repr=False)

    @classmethod
    def for_t4(cls, model_id: str, **overrides) -> "HuggingFaceTransformersPlanner":
        """Low-VRAM Colab/T4 preset for 7B-class models.

        Defaults: fp16 compute + 4-bit (nf4) weights + short generations
        (`max_new_tokens=32`), deterministic decoding, `device="auto"`.
        Pair with `run_battery(..., max_steps=2)` so a 7B model on a T4
        finishes in reasonable time. Override any field via kwargs."""
        params = dict(dtype="float16", load_in_4bit=True, max_new_tokens=32,
                      device="auto", temperature=0.0, do_sample=False, seed=0)
        params.update(overrides)
        return cls(model_id=model_id, **params)

    def __post_init__(self):
        if self.info is None:
            family = (
                "qwen" if "qwen" in self.model_id.lower() else
                "llama" if "llama" in self.model_id.lower() else
                "mistral" if "mistral" in self.model_id.lower() else
                "deepseek" if "deepseek" in self.model_id.lower() else
                "phi" if "phi" in self.model_id.lower() else
                "hf"
            )
            self.info = PlannerInfo(
                name=f"hf.{family}",
                model_id=self.model_id,
                family=family,
                deterministic=(self.temperature == 0.0 and not self.do_sample),
                temperature=self.temperature,
                max_new_tokens=self.max_new_tokens,
                seed=self.seed,
                extras={"device": self.device, "dtype": self.dtype,
                        "load_in_4bit": self.load_in_4bit},
            )

    # ── lazy load ────────────────────────────────────────────
    def _ensure_loaded(self):
        if self._model is not None:
            return
        _required_imports()
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        torch.manual_seed(self.seed)

        kwargs = {"device_map": self.device, "low_cpu_mem_usage": True}
        if self.load_in_4bit:
            kwargs["quantization_config"] = self._bnb_config(torch)
            # bitsandbytes dispatch needs an accelerate device_map
            if self.device not in ("auto", "balanced", "sequential"):
                kwargs["device_map"] = "auto"
        elif self.dtype != "auto":
            kwargs["torch_dtype"] = getattr(torch, self.dtype, None) or self.dtype

        tier = MODEL_TIERS.get(self.model_id)
        print(f"[hf_planner] loading {self.model_id} "
              f"(tier={tier or 'unknown'}, 4bit={self.load_in_4bit}); "
              "first run also downloads weights …")
        t0 = time.time()
        self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self._model = AutoModelForCausalLM.from_pretrained(self.model_id, **kwargs)
        self._model.eval()
        self._post_load_check(time.time() - t0)

    def _bnb_config(self, torch):
        try:
            import bitsandbytes  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "load_in_4bit=True needs bitsandbytes. Install with "
                "`pip install bitsandbytes` (Colab/Linux+CUDA). Or drop "
                "load_in_4bit and use a lighter model "
                "(microsoft/Phi-4-mini-instruct, TinyLlama)."
            ) from e
        from transformers import BitsAndBytesConfig
        compute = (getattr(torch, self.dtype, None)
                   if self.dtype != "auto" else torch.float16) or torch.float16
        return BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type=self.bnb_4bit_quant_type,
            bnb_4bit_compute_dtype=compute,
            bnb_4bit_use_double_quant=True,
        )

    def _post_load_check(self, load_s: float):
        """Detect CPU/disk offload + slow loads and recommend a fallback.
        Offloading is the usual cause of a 7B "stuck" load on a T4: the
        model fits only by spilling layers off the GPU, so generation is
        orders of magnitude slower (it does not error)."""
        dmap = getattr(self._model, "hf_device_map", None)
        offloaded = sorted({str(d) for d in dmap.values()
                            if str(d).lower() in ("cpu", "disk")}) \
            if isinstance(dmap, dict) else []
        print(f"[hf_planner] loaded in {load_s:.1f}s"
              + (f"; devices in use: {sorted({str(d) for d in dmap.values()})}"
                 if isinstance(dmap, dict) else ""))
        if offloaded:
            print(f"[hf_planner] WARNING: weights offloaded to {offloaded} — "
                  "this model does not fully fit GPU VRAM. Generation will be "
                  "very slow (minutes/step), not failed. To fix: load_in_4bit="
                  "True (or for_t4(...)), lower max_new_tokens, or restart the "
                  "runtime and load one model at a time.")
            recommend_fallback("CPU/disk offload detected")
        if load_s > self.slow_load_warn_s:
            print(f"[hf_planner] WARNING: load took {load_s:.0f}s "
                  f"(> {self.slow_load_warn_s:.0f}s threshold). After the "
                  "one-time weight download, a fp16 7B that still loads this "
                  "slowly is usually offloading.")
            recommend_fallback("slow load")

    def unload(self):
        """Drop model + tokenizer references and free VRAM. Call this when
        switching models on a shared T4, then `free_memory()`."""
        self._model = None
        self._tokenizer = None
        free_memory()

    # ── prompt construction ──────────────────────────────────
    def _default_system_prompt(self) -> str:
        inv = ""
        if self.tool_inventory:
            inv = "\nAvailable tools:\n" + "\n".join(
                f"  - {t['name']}: {t.get('description','')}"
                for t in self.tool_inventory)
        return (
            "You are a tool-using planner. On every turn, respond with a "
            "SINGLE JSON object of the form "
            '{"tool": "<tool>", "args": {"<key>": <value>}} — and nothing '
            "else. Do not include prose. Use only tools and arguments "
            "that make operational sense for the observation."
            + inv
        )

    def _build_messages(self, observation: dict, history: list[ToolCall]) -> list[dict]:
        msgs = [{"role": "system",
                 "content": self.system_prompt or self._default_system_prompt()}]
        if history:
            msgs.append({
                "role": "user",
                "content": ("History of executed tool calls (for context):\n"
                            + json.dumps(history, ensure_ascii=False))})
        msgs.append({
            "role": "user",
            "content": ("Observation:\n"
                        + json.dumps(observation, ensure_ascii=False)
                        + "\n\nRespond with one JSON tool-call object.")})
        return msgs

    # ── generation ───────────────────────────────────────────
    def _generate(self, messages: list[dict]) -> str:
        import torch
        prompt = self._tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True)
        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)
        with torch.no_grad():
            out = self._model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=self.do_sample,
                temperature=self.temperature if self.do_sample else None,
                pad_token_id=self._tokenizer.eos_token_id,
            )
        return self._tokenizer.decode(
            out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)

    # ── parsing — defensive ──────────────────────────────────
    @staticmethod
    def _parse_tool_call(text: str) -> Optional[ToolCall]:
        # try strict JSON first
        for blob in (text, text.strip().strip("`").strip()):
            try:
                obj = json.loads(blob)
                if isinstance(obj, dict) and "tool" in obj:
                    obj.setdefault("args", {})
                    if not isinstance(obj["args"], dict):
                        return None
                    return {"tool": str(obj["tool"]), "args": obj["args"]}
            except Exception:
                pass
        # fall back to regex extraction
        m = _TOOL_CALL_RE.search(text)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
            if "tool" in obj:
                obj.setdefault("args", {})
                if not isinstance(obj["args"], dict):
                    return None
                return {"tool": str(obj["tool"]), "args": obj["args"]}
        except Exception:
            return None
        return None

    # ── Planner protocol ─────────────────────────────────────
    def propose(self, observation: dict, history: list[ToolCall]) -> list[ToolCall]:
        self._ensure_loaded()
        text = self._generate(self._build_messages(observation, history))
        call = self._parse_tool_call(text)
        return [call] if call else []   # deny-by-default on malformation
