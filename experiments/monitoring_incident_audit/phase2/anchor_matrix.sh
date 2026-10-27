#!/usr/bin/env bash
# Anchor tamper matrix against the PR's `anchor` CLI. Each case runs on a fresh
# COPY of a clean campaign directory (complete runs only); the source is never
# modified.  usage: anchor_matrix.sh CLEAN_CAMPAIGN_DIR WORK_DIR PYTHON  (run from repo root)
set -u
SRC=$1; WORK=$2; PY=$3
A() { $PY -m experiments.monitoring_incident anchor "$@" > "$WORK/last.json" 2>&1; echo $?; }
fresh() { rm -rf "$WORK/c"; cp -a "$SRC" "$WORK/c"; A --output-dir "$WORK/c" >/dev/null; }
first() { ls -d "$WORK"/c/mi-* | head -1; }
problems() { python3 -c "import json,sys;j=json.load(open(sys.argv[1]));print([p.get('kind') for p in j.get('problems') or []] or j.get('error','')[:60])" "$WORK/last.json"; }
row() { printf '%-58s exit=%s %s\n' "$1" "$2" "$(problems)"; }
mkdir -p "$WORK"

fresh; row "baseline verify" "$(A --output-dir "$WORK/c" --verify)"
fresh; R=$(first); python3 - "$R/evidence.jsonl" <<'PY'
import json,sys; p=sys.argv[1]; L=open(p).read().splitlines(); r=json.loads(L[3]); r["payload"]["note"]="edited"; L[3]=json.dumps(r); open(p,"w").write("\n".join(L)+"\n")
PY
row "modified evidence (one payload edited)" "$(A --output-dir "$WORK/c" --verify)"
fresh; rm "$(first)/evidence.jsonl"; row "deleted evidence log" "$(A --output-dir "$WORK/c" --verify)"
fresh; rm -r "$(first)"; row "deleted whole run directory" "$(A --output-dir "$WORK/c" --verify)"
fresh; R=$(first); mkdir -p "$WORK/c/dup"; cp -a "$R" "$WORK/c/dup/"; row "duplicate run id: verify (copy in subdir)" "$(A --output-dir "$WORK/c" --verify)"
row "duplicate run id: generate (new anchor file)" "$(A --output-dir "$WORK/c" --anchor-file "$WORK/new_anchor.json")"
fresh; R=$(first); python3 - "$R/summary.json" <<'PY'
import json,sys; p=sys.argv[1]; s=json.load(open(p)); s["evidence"]["terminal_hash"]="0"*64; open(p,"w").write(json.dumps(s))
PY
rm "$WORK/c/EVIDENCE_ANCHOR.json"; row "incorrect terminal hash in summary: generate" "$(A --output-dir "$WORK/c")"
fresh; R=$(first); python3 - "$R/summary.json" <<'PY'
import json,sys; p=sys.argv[1]; s=json.load(open(p)); m=s["metadata"]; [m.pop(k) for k in ("git","governance_manifest_sha256","model","provider")]; open(p,"w").write(json.dumps(s))
PY
rm "$WORK/c/EVIDENCE_ANCHOR.json"; row "missing metadata (git, manifest, model, provider): generate" "$(A --output-dir "$WORK/c")"
fresh; H=$(sha256sum "$WORK/c/EVIDENCE_ANCHOR.json" | cut -c1-64); row "anchor overwrite without --force" "$(A --output-dir "$WORK/c")"
[ "$(sha256sum "$WORK/c/EVIDENCE_ANCHOR.json" | cut -c1-64)" = "$H" ] && echo "    anchor bytes unchanged after refused overwrite"
row "anchor overwrite with --force" "$(A --output-dir "$WORK/c" --force)"
fresh; python3 - "$WORK/c/EVIDENCE_ANCHOR.json" <<'PY'
import json,sys; p=sys.argv[1]; a=json.load(open(p)); a["rows"][0]["terminal_hash"]="f"*64; open(p,"w").write(json.dumps(a))
PY
row "incorrect terminal hash in anchor row" "$(A --output-dir "$WORK/c" --verify)"
fresh; R=$(first); python3 - "$R/summary.json" <<'PY'
import json,sys; p=sys.argv[1]; s=json.load(open(p)); s["metrics"]["unauthorized_executed"]=99; s["metrics"]["monitoring_intact_final"]=False; open(p,"w").write(json.dumps(s))
PY
row "summary.json metrics edited after anchoring" "$(A --output-dir "$WORK/c" --verify)"
fresh; rm -f "$WORK/c/EVIDENCE_ANCHOR.json"; row "anchor file missing: verify" "$(A --output-dir "$WORK/c" --verify)"
fresh; mkdir -p "$WORK/c/mi-0000partial0000000"; head -5 "$(first)/evidence.jsonl" > "$WORK/c/mi-0000partial0000000/evidence.jsonl"
row "interrupted run dir added after anchoring: verify" "$(A --output-dir "$WORK/c" --verify)"
rm "$WORK/c/EVIDENCE_ANCHOR.json"; row "interrupted run dir present: generate" "$(A --output-dir "$WORK/c")"
