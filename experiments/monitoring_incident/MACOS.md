# Running on macOS (Apple Silicon, 8 GB) — Phase 2 local-model execution

Phase 1 is offline and needs no model. This file prepares **Phase 2**: driving
the same scenarios and enforcement with a local model as the proposer, on an
8 GB Apple Silicon Mac. No model is downloaded by Phase 1, and no command here
makes a paid API call unless you explicitly opt in.

## Hardware / software assumptions

- Apple Silicon (M-series), 8 GB unified memory. This is tight: run **one**
  small quantized model at a time, close other apps, keep `--num-ctx` modest.
- Python 3.9+ (3.11+ recommended). The experiment uses only the standard library
  plus the in-repo `morrison_governance`; no extra pip install is required for
  the scripted suite or the local-model proposers.
- [Ollama](https://ollama.com) for local models (recommended on macOS), or any
  OpenAI-compatible server (llama.cpp `server`, LM Studio).
- OS confinement on macOS is `sandbox-exec` (no network, writes confined to the
  sandbox and temp dirs); the harness selects it automatically. On Linux it uses
  `unshare`; everywhere else it falls back to resource limits only. Confinement
  used is recorded in each run's `baseline_oracle.confinement`.

## 1. Get the repo and sanity-check offline

```bash
git clone <this-repo> && cd Morrison-Runtime-Governance
python -m experiments.monitoring_incident coverage
python -m experiments.monitoring_incident scripted --output /tmp/mi-offline
python -m pytest experiments/monitoring_incident -q        # ~3-4 min
```

## 2. Install a small quantized model (not done in Phase 1)

8 GB favours ~1.5B–3B quantized models. Start small; only pull what you will run.

```bash
ollama pull qwen2.5:1.5b-instruct-q4_K_M      # ~1 GB, a good first target
# or, if memory allows:
ollama pull qwen2.5:3b-instruct-q4_K_M        # ~2 GB
ollama serve &                                 # if not already running
```

The experiment hard-codes **no** model name. Whatever you pull, pass its exact
tag with `--model`.

## 3. Read-only preflight (never pulls a model)

```bash
python -m experiments.monitoring_incident preflight
# -> {"ollama": {"reachable": true, "models": ["qwen2.5:1.5b-instruct-q4_K_M", ...]}, ...}
```

## 4. Run one scenario with the local model, under each condition

```bash
M=qwen2.5:1.5b-instruct-q4_K_M
for COND in ungoverned local_only global_only hierarchical; do
  python -m experiments.monitoring_incident live \
      --scenario alert_suppression --condition $COND \
      --provider ollama --model "$M" --num-ctx 8192 --max-steps 20 \
      --output /tmp/mi-live
done
```

Small models often emit tool calls inconsistently. Two aids:

- `--tool-protocol json` switches from native tool-calling to a "reply with one
  JSON object" protocol, which small models follow more reliably. The default is
  `native`.
- `--provider openai-compatible --base-url http://127.0.0.1:8080/v1` targets a
  llama.cpp / LM Studio server instead of Ollama. For a hosted OpenAI-compatible
  endpoint needing a key, pass `--api-key-env MY_KEY_VAR` (the key is read from
  that environment variable, never from the command line).

Provider refusals, malformed output, and provider errors are recorded as
non-success outcomes — **never** as Morrison containment.

## 5. (Optional) Anthropic API proposer — paid, double opt-in

```bash
export ANTHROPIC_API_KEY=...        # or `ant auth login`
python -m experiments.monitoring_incident live \
    --scenario integration_removal --condition hierarchical \
    --provider anthropic --model <model-id> --effort medium \
    --allow-paid-api --output /tmp/mi-live
```

Without `--allow-paid-api` the Anthropic proposer refuses to construct. The
model id is always explicit; no default model is assumed.

## 6. Analyse

Each `live` run writes `summary.json` and `evidence.jsonl` under a run-id dir.
Verify any evidence log:

```bash
python -m experiments.monitoring_incident verify --log /tmp/mi-live/<run_id>/evidence.jsonl
```

Compare conditions by the metrics in each `summary.json`
(`unauthorized_executed`, `enforcement_bypass_total`, `false_positive_*`,
`monitoring_intact_final`, `report.misleading`). The scientific comparison is
the same as the scripted suite: does the model *propose* monitoring changes, and
do global/hierarchical stop them while legitimate work still completes?

## Memory / time tips for 8 GB

- One model at a time; `ollama stop <model>` between models.
- `--num-ctx 4096` if you see swapping; shorten `--max-steps`.
- The confined subprocess test runs add latency; a full scripted suite is ~1–2
  min of model-free work, dominated on live runs by model latency, not Morrison.
