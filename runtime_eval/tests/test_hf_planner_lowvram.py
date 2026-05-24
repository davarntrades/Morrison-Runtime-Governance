"""GPU-free tests for the low-VRAM / T4 hardening of the HF planner.

These pin the loading-config surface (preset, tiers, cleanup helpers)
without importing torch or loading any weights — the parts an evaluator
relies on before a Colab run. The governance core is not exercised here;
it is unchanged by this work.

Run:  python3 runtime_eval/tests/test_hf_planner_lowvram.py
"""

import os
import sys

sys.path.insert(0,
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))

from runtime_eval.planners.hf_planner import (
    HuggingFaceTransformersPlanner as P, MODEL_TIERS, free_memory,
    recommend_fallback,
)


def test_for_t4_preset_is_low_vram():
    p = P.for_t4("mistralai/Mistral-7B-Instruct-v0.3")
    assert p.dtype == "float16"
    assert p.load_in_4bit is True
    assert p.max_new_tokens == 32
    assert p.device == "auto"
    assert p.do_sample is False and p.temperature == 0.0


def test_for_t4_overrides_apply():
    p = P.for_t4("Qwen/Qwen2.5-7B-Instruct", max_new_tokens=16,
                 load_in_4bit=False)
    assert p.max_new_tokens == 16
    assert p.load_in_4bit is False           # override wins
    assert p.model_id == "Qwen/Qwen2.5-7B-Instruct"


def test_info_extras_record_quantisation():
    p = P.for_t4("mistralai/Mistral-7B-Instruct-v0.3")
    assert p.info.extras["load_in_4bit"] is True
    assert p.info.extras["dtype"] == "float16"
    # default (non-preset) planner reports no quantisation
    q = P(model_id="microsoft/Phi-4-mini-instruct")
    assert q.info.extras["load_in_4bit"] is False


def test_model_tiers_cover_heavy_and_smoke():
    assert MODEL_TIERS["mistralai/Mistral-7B-Instruct-v0.3"] == "heavy"
    assert MODEL_TIERS["Qwen/Qwen2.5-7B-Instruct"] == "heavy"
    assert MODEL_TIERS["microsoft/Phi-4-mini-instruct"] == "medium"
    assert MODEL_TIERS["TinyLlama/TinyLlama-1.1B-Chat-v1.0"] == "smoke"


def test_free_memory_is_safe_without_cuda():
    # must be a no-op (not raise) when torch/CUDA is unavailable
    free_memory()


def test_recommend_fallback_prints_actionable_advice(capsys=None):
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        recommend_fallback("offload")
    out = buf.getvalue()
    assert "TinyLlama" in out and "Phi-4-mini" in out
    assert "4bit" in out or "load_in_4bit" in out


def test_default_planner_unchanged_for_non_t4_use():
    # constructing without the preset keeps the original defaults
    p = P(model_id="Qwen/Qwen2.5-7B-Instruct")
    assert p.load_in_4bit is False
    assert p.dtype == "auto"
    assert p.max_new_tokens == 256


if __name__ == "__main__":
    T = [
        test_for_t4_preset_is_low_vram,
        test_for_t4_overrides_apply,
        test_info_extras_record_quantisation,
        test_model_tiers_cover_heavy_and_smoke,
        test_free_memory_is_safe_without_cuda,
        test_recommend_fallback_prints_actionable_advice,
        test_default_planner_unchanged_for_non_t4_use,
    ]
    print("\n" + "=" * 64 +
          "\n  HF planner low-VRAM / T4 hardening — GPU-free tests\n" +
          "=" * 64 + "\n")
    p = f = 0
    for t in T:
        try:
            t(); print(f"  ok  {t.__name__}"); p += 1
        except Exception as e:                           # noqa: BLE001
            print(f"  XX  {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "=" * 64)
    sys.exit(1 if f else 0)
