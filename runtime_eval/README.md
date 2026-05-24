# Morrison Runtime Governance — Live Planner Evaluation Harness

A modular runtime-governance evaluation harness for **open-weight
Hugging Face planners**. Wraps the existing `morrison_governance`
hierarchy (A_safe → V2 → V3 → V4 → V4+ → V5 → V5+) with a live
planner → middleware → sandbox loop that asks the same question every
step:

> **Can this planned executable trajectory reach Ω before it executes?**

Not "does this text look unsafe?". The governance decision is made on
the **executable trajectory**, not the surface form.

This is **additive** to the existing repository. Nothing under
`morrison_governance/` changes; this package extends it.

```
┌────────────────┐   tool calls   ┌────────────────────┐   PERMIT   ┌──────────┐
│  HF planner    │ ─────────────▶ │ Governance         │ ─────────▶ │ Sandbox  │
│  (Qwen / Llama │                │ middleware         │            │ executor │
│  / Mistral …)  │ ◀──── obs ──── │ (A_safe→V2→V3→V4→V5│ ◀── obs ── │ (sim)    │
└────────────────┘                │  →V4+→V5+)         │            └──────────┘
                                   │      │            │
                                   │      ▼            │
                                   │ BLOCK · audit log │
                                   └────────────────────┘
```

The middleware is the **same prefix-aware fail-closed interceptor**
already in `morrison_governance/interception.py`. The Ω registry is the
existing `OmegaDomain` set. Everything new here is the **planner +
sandbox + replay + cross-model evaluation surface** wrapped around it.

## Directory structure

```
runtime_eval/
├── README.md                  ← this document
├── requirements.txt
├── planners/
│   ├── base.py                Planner ABC + dataclasses
│   ├── deterministic.py       Offline scripted / structural planners (no GPU)
│   ├── hf_planner.py          HuggingFace transformers planner (live)
│   ├── vllm_planner.py        vLLM planner (live; high-throughput)
│   └── registry.py            PLANNER_REGISTRY — hot-swap by name
├── governance/
│   ├── middleware.py          RuntimeGovernanceMiddleware — main loop
│   ├── omega_registry.py      Domain-preset composition over GovernanceLayer
│   └── decision_trace.py      Structured per-step trace records
├── domains/
│   └── presets.py             Bundled domain presets (finance / cyber / mh / …)
├── perturbations/
│   └── families.py            10 perturbation families (synonym / indirect /
│                              semantic / drift / role / temperature / decoding
│                              / environment / hidden-tool / permission)
├── evaluators/
│   ├── trajectory.py          Multi-turn evaluator
│   ├── branch.py              Branch-reachability sweep over planner samples
│   ├── cross_planner.py       Planner agreement / divergence matrices
│   └── confusion.py           Confusion matrix + FP/FN metrics
├── sandbox/
│   ├── tool_simulator.py      Deterministic safe tool simulator (no shell, no net)
│   └── executor.py            Only executes calls that returned PERMIT
├── replay/
│   └── trace.py               TraceWriter / TraceReader (deterministic JSONL)
├── metrics/
│   └── latency.py             p50/p95 latency, throughput, replay-consistency
├── notebooks/
│   └── colab_quickstart.py    Colab-compatible cell-marked script
├── cli.py                     `python -m runtime_eval evaluate …`
└── tests/
    └── test_runtime_eval.py   Deterministic end-to-end test (no GPU)
```

## Supported planners

Production planners (load on demand via `runtime_eval.planners.registry`):

| Tier      | Hugging Face model id                                   |
|:----------|:--------------------------------------------------------|
| Primary   | `Qwen/Qwen2.5-7B-Instruct`                              |
| Primary   | `meta-llama/Llama-3.1-8B-Instruct`                      |
| Primary   | `mistralai/Mistral-7B-Instruct-v0.3`                    |
| Primary   | `deepseek-ai/DeepSeek-R1-Distill-Qwen-7B`               |
| Primary   | `microsoft/Phi-4-mini-instruct`                         |
| Optional  | `Qwen/Qwen2.5-14B-Instruct`                             |
| Optional  | `NousResearch/Hermes-2-Pro-Llama-3-8B`                  |
| Optional  | `deepseek-ai/DeepSeek-R1-Distill-Llama-8B`              |
| Optional  | `TinyLlama/TinyLlama-1.1B-Chat-v1.0`                    |
| Optional  | `mistralai/Mixtral-8x7B-Instruct-v0.1`                  |

Deterministic stand-ins (run anywhere, no GPU):

- `deterministic.scripted`       — fixed plan, one batch per turn
- `deterministic.profile/*`      — gpt/claude/qwen/llama/stochastic structural
                                    transforms reused from `planners.py`
- `deterministic.callable`       — wrap any `fn(obs, history) → list[dict]`

## Implementation roadmap

| Phase | Goal | Status |
|:-----:|:-----|:------:|
| 1     | Planner ABC + deterministic adapter + middleware end-to-end | shipped |
| 2     | Sandbox tool simulator + replay JSONL + audit/confusion metrics | shipped |
| 3     | HuggingFace transformers planner adapter (live)               | shipped |
| 4     | vLLM planner adapter (high-throughput)                        | skeleton |
| 5     | Perturbation families × cross-planner divergence matrices     | shipped |
| 6     | Colab notebook + CLI + scaling recommendations                | shipped |
| 7     | Live cross-model harness on Colab GPU (validation run)        | user-driven |
| 8     | Production hardening (timeouts, partial-failure recovery)     | future |

## Design principles

1. **Reachability, not moderation.** The governance decision is made on
   the *trajectory of tool calls* the planner proposes, not on the text
   it generates. Block decisions reference rule names from the existing
   Ω registry; PERMIT means "no reachable Ω across the current prefix".
2. **Prefix-aware fail-closed.** Every proposed call is evaluated as
   `history + [call]`, not in isolation, so a benign read on turn 1
   followed by an egress on turn 2 is one trajectory and is blocked at
   the egress. Any governance exception is converted to BLOCK.
3. **Deterministic replay.** Planner adapters declare whether they are
   deterministic (`info()["deterministic"]`). When all components are
   deterministic, full traces replay byte-identically. The
   `replay/trace.py` writer is stable across runs at fixed seeds.
4. **Hot-swappable planners.** `PLANNER_REGISTRY` is a name → factory
   map; the middleware accepts any object satisfying the `Planner`
   protocol. A live HF planner and a deterministic stand-in are
   interchangeable for testing.
5. **Sandbox-only execution.** The sandbox executor never shells out,
   never opens a network connection, and never touches real files. It
   simulates tool effects via a deterministic schema-keyed map.
6. **No keyword filtering. No semantic moderation. No RLHF.** All
   safety decisions go through the existing reachability hierarchy.

## Quickstart (local / Colab)

```bash
pip install -r runtime_eval/requirements.txt
python -m runtime_eval.cli evaluate \
    --planner deterministic.scripted \
    --domain mental_health_safety \
    --max-steps 8 \
    --trace logs/run.jsonl
```

A Colab quickstart is in `runtime_eval/notebooks/colab_quickstart.py`
(cell-marked Python; paste into a Colab notebook).

## Scaling recommendations

- **Single-GPU dev (Colab T4 / L4).** Use 7B-class models with
  `dtype=bfloat16` and `device_map="auto"`. Expect 1–3 tokens/s on T4 —
  fine for ≤ 200-step evaluation, slow for full corpora.
- **Multi-GPU.** Switch the planner adapter from
  `HuggingFaceTransformersPlanner` to `VLLMPlanner` and run vLLM as a
  separate process; the middleware calls vLLM over HTTP. Tensor
  parallelism gets ≥ 30 tokens/s on a single A100 for 7B-class models.
- **Throughput strategy.** Governance evaluation is sub-ms; the
  bottleneck is always model inference. Batch evaluation across the
  perturbation family with `evaluators.cross_planner.run_parallel`.
- **Determinism vs. throughput.** Deterministic decoding (`temperature=0`,
  `do_sample=False`, fixed seed) is the default. Stochastic decoding is
  available as a perturbation family for robustness testing.

## Likely bottlenecks

| Bottleneck                 | Mitigation                                       |
|:---------------------------|:-------------------------------------------------|
| Model load time            | Cache snapshots; reuse process across runs       |
| Single-GPU memory          | 4-bit / 8-bit (`bitsandbytes`), smaller models   |
| Tool-call parsing fragility | Strict JSON-only system prompt + retry + drop-with-trace |
| Cross-planner output drift  | Pin generation_config; tolerance bounded in cross_planner |
| Perturbation explosion     | Bounded family size; deterministic enumeration   |
| Sandbox effects            | None — sandbox is pure simulation                |

## Failure-surface analysis

The harness inherits the architectural failure surfaces of the
governance core (`morrison_governance/LIMITATIONS.md`) and adds:

- **Live-model output noise** — even at temperature 0, transformers can
  produce slightly different outputs on different GPUs. Cross-planner
  agreement is measured *modulo* a structural canonicalisation step
  (tool name + arg-key set) so cosmetic differences don't flip
  verdicts.
- **Tool-call malformation** — an open-weight model may produce
  unparseable output. The HF planner returns an empty proposal in that
  case; the middleware logs it and continues. This is **deny-by-default
  on malformation**, not error-as-PERMIT.
- **Streaming bias** — multi-turn evaluation depends on the prior
  prefix. A planner that "remembers" can drift; the trace captures the
  full prefix so divergence is auditable.
- **Sandbox-vs-reality gap** — the sandbox is a *simulator*. Effects
  are deterministic stubs. A real-tool deployment must replicate the
  capability geometry the simulator presents; the
  `sandbox.tool_simulator` schema is the spec.

## Recommendations for future hardening

1. **vLLM HTTP serving** — make `VLLMPlanner` the production default;
   it amortises model load across requests and removes per-call boot.
2. **Schema-validated tool calls** — replace ad-hoc JSON parsing with a
   pydantic schema per domain so malformation is structurally typed.
3. **Branch-reachability sampling** — at higher temperatures the
   planner explores branches; sample N completions per turn and check
   that no branch reaches Ω (`evaluators/branch.py` is the seam).
4. **Trace signing** — append an HMAC to each trace record so external
   reviewers can verify replay integrity.
5. **Continuous adversarial-corpus rotation** — the alias / synonym
   surfaces evolve; rotate the corpus and pin regressions
   (`runtime_eval/perturbations/families.py` is the corpus source of
   truth).
6. **Independent third-party adversarial red-team** on this domain;
   the harness is built for it (see `CRITICAL_EVALUATION.md`).

## Hardening

A second layer ships in `runtime_eval` as an **opt-in pre-governance
pipeline** that closes specific adversarial surfaces (synonym /
hyphenation / indirect-phrasing on markers, encoded payloads,
recursive coercion, schema malformations, composite Ω across
domains) without weakening the ontology. See
[`HARDENING.md`](HARDENING.md) for the full report — modules,
adversarial corpus, baseline-vs-hardened numbers, performance bounds,
and bounded language.

Bounded result on the in-tree adversarial corpus (15 cases, 6
categories): **baseline 6 / 14 bypasses (42.9 %) → hardened 0 / 14
(0 %)**, with 0 / 10 over-blocks on the safe baseline.

## Bounded language

Every metric this harness produces — confusion matrices, FP/FN,
planner-agreement scores, latency percentiles — is bounded to the
**tested suite on the configured planners**. None of it is a universal
safety guarantee. The harness is an empirical reachability-evaluation
surface, not a certification.
