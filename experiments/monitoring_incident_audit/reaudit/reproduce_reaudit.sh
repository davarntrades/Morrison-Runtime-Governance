#!/usr/bin/env bash
# Re-audit of PR #42 head 99e6b08. Runs the ORIGINAL audit (../reproduce.sh,
# unchanged tools) against the repaired code, then the re-audit checks.
#   usage: bash experiments/monitoring_incident_audit/reaudit/reproduce_reaudit.sh OUT_DIR [PYTHON]
set -euo pipefail
OUT=$(realpath -m "${1:?usage: reproduce_reaudit.sh OUT_DIR [PYTHON]}")
PY=${2:-python3.11}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
mkdir -p "$OUT"
bash "$HERE/../reproduce.sh" "$OUT/original_audit" "$PY"
$PY "$HERE/../alias_probe.py" "$OUT/original_audit/alias_probe.json" | grep -v '^INFO' > "$OUT/original_audit/alias_probe.txt"
cd "$ROOT"
echo "== R1. PR counterexamples command (all four conditions)"
$PY -m experiments.monitoring_incident counterexamples --output "$OUT/pr_counterexamples" \
    --conditions ungoverned local_only global_only hierarchical | tee "$OUT/pr_counterexamples.txt"
echo "== R2. published evidence vs committed anchor, then independent recomputation"
$PY -I "$HERE/verify_anchor.py" experiments/monitoring_incident/results "$OUT/published" | tee "$OUT/verify_anchor.txt"
for s in scripted-deny scripted-oracle counterexamples; do
    $PY -I "$HERE/../recompute.py" "$OUT/published/$s" experiments/monitoring_incident/templates \
        | tee "$OUT/recompute_published_$s.txt"
done
echo "== R3. differential on the false-safe end-states; non-regular file scan"
$PY "$HERE/differential_xc.py" | grep -v '^INFO' | tee "$OUT/differential_xc.txt"
$PY "$HERE/scan_probe.py" | tee "$OUT/scan_probe.txt"
echo "done: $OUT"
