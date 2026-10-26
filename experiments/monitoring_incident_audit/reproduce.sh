#!/usr/bin/env bash
# Regenerate every result in AUDIT_REPORT.md from this branch.
#   usage: bash experiments/monitoring_incident_audit/reproduce.sh OUT_DIR [PYTHON]
# Disposable sandboxes only; nothing under experiments/monitoring_incident/ or
# morrison_governance/ is modified. Takes ~6 minutes on one core.
set -euo pipefail
OUT=$(realpath -m "${1:?usage: reproduce.sh OUT_DIR [PYTHON]}")
PY=${2:-python3.11}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
mkdir -p "$OUT"
cd "$ROOT"
TEMPLATES=experiments/monitoring_incident/templates

echo "== 1. PR #42 scripted suite (96 episodes x 2 escalation policies) + differential"
$PY -m experiments.monitoring_incident scripted --output "$OUT/run_deny" --escalation deny | tee "$OUT/run_deny.txt"
$PY -m experiments.monitoring_incident scripted --output "$OUT/run_oracle" --escalation oracle | tee "$OUT/run_oracle.txt"
$PY -m experiments.monitoring_incident differential --output "$OUT/differential.json" | tee "$OUT/differential.txt"

echo "== 2. independent recomputation from raw evidence (stdlib only, run isolated)"
$PY -I "$HERE/recompute.py" "$OUT/run_deny" "$TEMPLATES" | tee "$OUT/recompute_deny.txt"
$PY -I "$HERE/recompute.py" "$OUT/run_oracle" "$TEMPLATES" | tee "$OUT/recompute_oracle.txt"

echo "== 3. kernel classification (item 8) and C05 trajectory variants"
$PY "$HERE/kernel_probe.py" | grep -v '^INFO' | tee "$OUT/kernel_probe.jsonl"
$PY "$HERE/c05_probe.py" "$OUT/c05_probe.json" | grep -v '^INFO' | tee "$OUT/c05_probe.txt"

echo "== 4. counterexample cases through the unmodified harness (4 conditions, deny)"
$PY "$HERE/run_audit_cases.py" "$OUT/xcases_deny" deny | grep -v '^INFO' | tee "$OUT/xcases_deny.txt"
$PY -I "$HERE/recompute.py" "$OUT/xcases_deny" "$TEMPLATES" | tee "$OUT/recompute_xcases.txt"
$PY "$HERE/symlink_probe.py" "$OUT/xsym" | grep -v '^INFO' | tee "$OUT/symlink_probe.txt"

echo "== 5. enforcement-boundary probes"
$PY "$HERE/boundary_probe.py" "$OUT/boundary_probe.json" | grep -v '^INFO' | tee "$OUT/boundary_probe.txt"
$PY "$HERE/race_final.py" 30 | grep -E 'RACE|^ +[0-9]|2b-redo' | tee "$OUT/race_final.txt"
$PY "$HERE/alias_probe.py" "$OUT/alias_probe.json" | grep -v '^INFO' | tee "$OUT/alias_probe.txt"

echo "== 6. evidence tampering (on a copy of the C05 hierarchical deny log)"
C05=$($PY - "$OUT/run_deny" <<'EOF'
import glob, json, sys
for f in sorted(glob.glob(sys.argv[1] + "/*/evidence.jsonl")):
    m = json.loads(open(f).readline())["payload"]
    if m["case_id"] == "C05-profile-two-step" and m["condition"] == "hierarchical":
        print(f.rsplit("/", 1)[0])
EOF
)
$PY "$HERE/tamper.py" "$C05" "$OUT/tamper_c05" | grep -v '^INFO' | tee "$OUT/tamper.txt"
echo "done: $OUT"
