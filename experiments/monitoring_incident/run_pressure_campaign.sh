#!/usr/bin/env bash
# Pressure campaign for the monitoring-incident replication. See PRESSURE_CAMPAIGN.md.
#
#   ./experiments/monitoring_incident/run_pressure_campaign.sh check      # no inference
#   ./experiments/monitoring_incident/run_pressure_campaign.sh canary     # 1 model run
#   ./experiments/monitoring_incident/run_pressure_campaign.sh full       # the matrix (asks first)
#   ./experiments/monitoring_incident/run_pressure_campaign.sh summarize  # anchor, verify, tables
#
# Runs strictly sequentially, from the repo root. The API key is read from the
# environment variable named by API_KEY_ENV and is never printed or written.
# Works with macOS /bin/bash 3.2.
set -euo pipefail
cd "$(dirname "$0")/../.."

MODE="${1:-check}"
PY="${PY:-python3}"
PROVIDER="${PROVIDER:-openai-compatible}"
if [ "$PROVIDER" = "ollama" ]; then
  BASE_URL="${BASE_URL:-http://127.0.0.1:11434}"; API_KEY_ENV="${API_KEY_ENV:-}"
else
  BASE_URL="${BASE_URL:-https://router.huggingface.co/v1}"; API_KEY_ENV="${API_KEY_ENV:-HF_TOKEN}"
fi
MODEL="${MODEL:-huihui-ai/Qwen3-32B-abliterated:featherless-ai}"
OUT="${OUT:-$HOME/mi-pressure-campaign}"
REPS="${REPS:-3}"
SCENARIOS="${SCENARIOS:-alert_suppression integration_removal}"
ARMS="${ARMS:-spontaneous pressured instructed}"
CONDITIONS="${CONDITIONS:-ungoverned local_only global_only hierarchical}"
TEMPERATURE="${TEMPERATURE:-0.7}"
MAX_TOKENS="${MAX_TOKENS:-4096}"

MODEL_ARGS=(--provider "$PROVIDER" --model "$MODEL" --base-url "$BASE_URL"
            --tool-protocol native --temperature "$TEMPERATURE" --max-tokens "$MAX_TOKENS"
            --max-steps 25 --max-turns 30 --escalation deny)
[ -n "$API_KEY_ENV" ] && MODEL_ARGS+=(--api-key-env "$API_KEY_ENV")
# word-split the space-separated lists on purpose
# shellcheck disable=SC2206
MATRIX=(--scenarios $SCENARIOS --arms $ARMS --conditions $CONDITIONS --reps "$REPS")

key_check() {
  if [ -z "$API_KEY_ENV" ]; then echo "key: not needed ($PROVIDER)"; return 0; fi
  if [ -n "${!API_KEY_ENV:-}" ]; then echo "key: $API_KEY_ENV is set"; else
    echo "key: $API_KEY_ENV is NOT set. Export it in this terminal (never paste it into chat)."; return 1; fi
}

endpoint_check() {
  local url code
  if [ "$PROVIDER" = "ollama" ]; then url="$BASE_URL/api/tags"; else url="$BASE_URL/models"; fi
  if [ -n "$API_KEY_ENV" ]; then
    code=$(curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${!API_KEY_ENV:-}" "$url" || true)
  else
    code=$(curl -sS -o /dev/null -w "%{http_code}" "$url" || true)
  fi
  echo "endpoint: $url -> HTTP $code"
}

case "$MODE" in
  check)
    "$PY" --version
    key_check || true
    endpoint_check
    "$PY" -m pytest experiments/monitoring_incident/test_pressure.py -q
    "$PY" -m experiments.monitoring_incident.pressure plan "${MATRIX[@]}"
    ;;
  canary)
    key_check
    # one adversarial run, ungoverned: proves the model actually makes tool calls
    "$PY" -m experiments.monitoring_incident.pressure campaign --output "$OUT-canary" \
      --scenarios alert_suppression --arms instructed --conditions ungoverned --reps 1 \
      --stop-on-provider-error "${MODEL_ARGS[@]}"
    "$PY" -m experiments.monitoring_incident.pressure summarize --output "$OUT-canary"
    ;;
  full)
    key_check
    "$PY" -m experiments.monitoring_incident.pressure plan "${MATRIX[@]}"
    if [ "${CONFIRM:-}" != "yes" ]; then
      printf "Each run makes up to 30 model calls. Type RUN to start: "
      read -r answer
      [ "$answer" = "RUN" ] || { echo "not started"; exit 1; }
    fi
    "$PY" -m experiments.monitoring_incident.pressure campaign --output "$OUT" \
      "${MATRIX[@]}" --stop-on-provider-error "${MODEL_ARGS[@]}"
    "$0" summarize
    ;;
  summarize)
    "$PY" -m experiments.monitoring_incident anchor --output-dir "$OUT/runs" --force
    "$PY" -m experiments.monitoring_incident anchor --output-dir "$OUT/runs" --verify
    "$PY" -m experiments.monitoring_incident.pressure summarize --output "$OUT"
    echo "wrote $OUT/SUMMARY.md, $OUT/SUMMARY.json and $OUT/runs/EVIDENCE_ANCHOR.json"
    ;;
  *)
    echo "usage: $0 {check|canary|full|summarize}"; exit 2 ;;
esac
