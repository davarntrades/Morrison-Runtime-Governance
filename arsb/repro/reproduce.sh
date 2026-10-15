#!/usr/bin/env bash
# Reproduce ARSB v0 from a clean checkout of commit 6a80d78 (branch claude/arsb-v0-dev-frozen). No model inference, no network calls
# beyond package installation. Exits non-zero if the benchmark files differ from FREEZE.json or if
# the rerun does not reproduce the frozen outcomes.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 -m arsb.freeze check
VENV=${VENV:-.venv-arsb}
python3 -m venv --system-site-packages "$VENV"
"$VENV/bin/pip" install -q -r arsb/repro/base-environment.lock
"$VENV/bin/pip" install -q -r arsb/repro/competitors.lock
OUT=${OUT:-arsb-repro-out}
"$VENV/bin/python" -m arsb --output "$OUT"
python3 -m arsb.freeze verify "$OUT/arsb-results.json"
