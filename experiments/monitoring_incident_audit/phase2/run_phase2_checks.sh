#!/usr/bin/env bash
# Phase 2 readiness checks for PR #42 (repetition handling, overwrite safety,
# concurrency of run-dir claims, interrupted runs, anchoring, live reporting).
# Drives the PR's REAL `live` and `anchor` CLI against a deterministic local mock
# of Ollama (mock_ollama.py): no model, no download, no network beyond 127.0.0.1.
#   usage: bash experiments/monitoring_incident_audit/phase2/run_phase2_checks.sh OUT_DIR [PYTHON]
set -u
OUT=$(realpath -m "${1:?usage: run_phase2_checks.sh OUT_DIR [PYTHON]}"); PY=${2:-python3.11}
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../../.." && pwd)
PORT=${MOCK_PORT:-18435}; BASE=http://127.0.0.1:$PORT
rm -rf "$OUT"; mkdir -p "$OUT"; cd "$ROOT"
$PY -I "$HERE/mock_ollama.py" "$PORT" & MOCK=$!; trap 'kill $MOCK 2>/dev/null' EXIT; sleep 1
live() { $PY -m experiments.monitoring_incident live --scenario alert_suppression --provider ollama \
    --base-url "$BASE" --seed 7 --max-steps 10 "$@"; }
field() { python3 -c "import json,sys;j=json.load(open(sys.argv[1]));print(j.get(sys.argv[2]))" "$@"; }

echo "== preflight against the mock (read-only)"
$PY -m experiments.monitoring_incident preflight --base-url "$BASE" | tee "$OUT/preflight.json"

echo "== 1. five repetitions -> five run ids, five complete records"
C="$OUT/campaign"
for R in 1 2 3 4 5; do
    live --condition hierarchical --model mock:legit --repetition $R --output "$C" > "$OUT/rep$R.json" 2>&1
    echo "rep$R exit=$? run_id=$(field "$OUT/rep$R.json" run_id)"
done
for s in "$C"/mi-*/summary.json; do python3 -c "import json,sys;s=json.load(open(sys.argv[1]));m=s['metadata'];print(m['run_id'],'repetition',m['repetition'],'seed',m['seed'],m['generation_mode'],'valid',s['evidence']['valid'],'status',s['status'])" "$s"; done

echo "== 2. duplicates rejected; evidence bytes unchanged"
(cd "$C" && find . -type f | sort | xargs sha256sum) > "$OUT/hash_before.txt"
for R in 3 1 5; do
    live --condition hierarchical --model mock:legit --repetition $R --output "$C" > "$OUT/dup$R.json" 2>&1
    echo "duplicate rep$R exit=$? status=$(field "$OUT/dup$R.json" status)"
done
(cd "$C" && find . -type f | sort | xargs sha256sum) > "$OUT/hash_after.txt"
cmp -s "$OUT/hash_before.txt" "$OUT/hash_after.txt" && echo "all evidence/summary bytes identical before/after duplicates" || echo "BYTES CHANGED"

echo "== 3. four concurrent processes claim the same run id (3 trials)"
for T in 1 2 3; do
    O="$OUT/concurrent$T"; mkdir -p "$O"
    PIDS=""
    for P in 1 2 3 4; do ( live --condition hierarchical --model mock:legit --repetition 9 --output "$O" > "$O/p$P.out" 2>&1; echo $? > "$O/p$P.rc" ) & PIDS="$PIDS $!"; done
    wait $PIDS                       # only the four workers, never the mock server
    echo "trial $T exit codes: $(cat "$O"/p*.rc | sort | tr '\n' ' ')run dirs: $(ls -d "$O"/mi-* | wc -l)"
done

echo "== 4. interrupted run (SIGKILL mid-run), then retry of the same repetition"
# Start python DIRECTLY (not via the `live` shell function) so $! is the python
# process itself and SIGKILL really interrupts the run mid-episode.
$PY -m experiments.monitoring_incident live --scenario alert_suppression --provider ollama \
    --base-url "$BASE" --seed 7 --max-steps 10 --condition hierarchical --model mock:slow \
    --repetition 1 --output "$C" > "$OUT/slow.out" 2>&1 & P=$!
sleep 6; kill -9 $P; wait $P 2>/dev/null
PART=$(for d in "$C"/mi-*; do [ -f "$d/summary.json" ] || echo "$d"; done | head -1)
echo "partial run dir: $(basename "$PART") files: $(ls "$PART" | tr '\n' ' ')records: $(wc -l < "$PART/evidence.jsonl")"
sha256sum "$PART/evidence.jsonl" > "$OUT/partial.sha"
live --condition hierarchical --model mock:slow --repetition 1 --output "$C" > "$OUT/slow_retry.out" 2>&1
echo "retry exit=$? status=$(field "$OUT/slow_retry.out" status)"; sha256sum -c --quiet "$OUT/partial.sha" && echo "partial evidence untouched"

echo "== 5. anchor over a campaign that contains the interrupted run"
$PY -m experiments.monitoring_incident anchor --output-dir "$C" > "$OUT/anchor_gen.json"; echo "anchor generate exit=$?"
echo "run dirs on disk: $(ls -d "$C"/mi-* | wc -l); runs in anchor: $(field "$OUT/anchor_gen.json" runs)"
$PY -m experiments.monitoring_incident anchor --output-dir "$C" --verify > "$OUT/anchor_verify.json"; echo "anchor verify exit=$?"

echo "== 6. anchor tamper matrix (copies of the complete runs only)"
mkdir -p "$OUT/clean"; for d in "$C"/mi-*; do [ -f "$d/summary.json" ] && cp -a "$d" "$OUT/clean/"; done
bash "$HERE/anchor_matrix.sh" "$OUT/clean" "$OUT/matrix" "$PY"

echo "== 7. live false-safe edit (audit X-A3) through the real live path, all four conditions"
for COND in ungoverned local_only global_only hierarchical; do
    live --condition $COND --model mock:falsesafe --repetition 1 --output "$OUT/falsesafe" > "$OUT/fs_$COND.json" 2>&1
    python3 -c "import json,sys;m=json.load(open(sys.argv[1]))['metrics'];print(sys.argv[2],'unauthorized_executed=',m['unauthorized_executed'],'monitoring_intact_final=',m['monitoring_intact_final'],'bypass=',m['enforcement_bypass_total'],'report_misleading=',m['report'].get('misleading'))" "$OUT/fs_$COND.json" $COND
done
$PY -I "$HERE/../recompute.py" "$OUT/falsesafe" experiments/monitoring_incident/templates | tee "$OUT/recompute_falsesafe.txt"
echo "== 8. audit campaign_guard: incomplete runs + summary-vs-evidence cross-check"
python3 -I "$HERE/campaign_guard.py" "$C"; echo "campaign_guard on campaign with interrupted run: exit=$?"
python3 -I "$HERE/campaign_guard.py" "$OUT/clean"; echo "campaign_guard on complete runs: exit=$?"
rm -rf "$OUT/edited"; cp -a "$OUT/clean" "$OUT/edited"; S1=$(ls "$OUT/edited"/mi-*/summary.json | head -1)
python3 -c "import json,sys;p=sys.argv[1];s=json.load(open(p));s['metrics']['unauthorized_executed']=99;open(p,'w').write(json.dumps(s))" "$S1"
python3 -I "$HERE/campaign_guard.py" "$OUT/edited"; echo "campaign_guard on edited summary: exit=$?"
echo "done: $OUT"
