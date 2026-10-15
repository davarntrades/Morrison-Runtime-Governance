#!/usr/bin/env bash
# Export this app as a standalone public hackathon repository.
#
#   scripts/export_standalone.sh /path/to/new-repo
#   cd /path/to/new-repo && git remote add origin git@github.com:<you>/morrison-stripe-collection-agent.git
#   git push -u origin main
#
# Morrison is included UNMODIFIED as a git submodule pinned to the commit the
# app was built and tested against.
set -euo pipefail
DEST="${1:?usage: export_standalone.sh DEST}"
MORRISON_URL="https://github.com/davarntrades/Morrison-Runtime-Governance.git"
MORRISON_COMMIT="06b9b55"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$DEST"
cd "$DEST"
git init -q -b main
(cd "$SRC" && git ls-files -z | xargs -0 tar cf -) | tar xf -
git submodule add -q "$MORRISON_URL" vendor/Morrison-Runtime-Governance
git -C vendor/Morrison-Runtime-Governance checkout -q "$MORRISON_COMMIT"

mkdir -p .github/workflows
sed -e 's#stripe-collection-agent/##g' \
    -e 's#PYTHONPATH: .*#PYTHONPATH: ${{ github.workspace }}:${{ github.workspace }}/vendor/Morrison-Runtime-Governance#' \
    -e 's#working-directory: stripe-collection-agent#working-directory: .#' \
    -e 's#branches: \[.*\]#branches: [main]#' \
    -e 's#      - uses: actions/checkout@v4#      - uses: actions/checkout@v4\n        with:\n          submodules: true#' \
    "$SRC/../.github/workflows/stripe-collection-live.yml" > .github/workflows/stripe-collection-live.yml

# Standalone quick-start ahead of the README (the README's paths describe the
# in-repo layout, where Morrison is the parent directory).
{
  printf '%s\n' \
    '> **Standalone hackathon repository.** Morrison Runtime Governance is included unmodified as a git submodule' \
    "> (\`vendor/Morrison-Runtime-Governance\`, pinned to \`$MORRISON_COMMIT\`). Development history, CI runs and live-run" \
    '> evidence provenance live in [davarntrades/Morrison-Runtime-Governance](https://github.com/davarntrades/Morrison-Runtime-Governance/tree/claude/stripe-morrison-collection-agent-7y0a6p/stripe-collection-agent).' \
    '>' \
    '> ```bash' \
    '> git clone --recurse-submodules https://github.com/davarntrades/morrison-stripe-collection-agent.git' \
    '> cd morrison-stripe-collection-agent' \
    '> pip install -r requirements.txt pytest' \
    '> export PYTHONPATH=$PWD:$PWD/vendor/Morrison-Runtime-Governance' \
    '> python -m pytest -q        # offline suite (local Stripe double)' \
    '> ```' \
    '>' \
    '> Demo video (94 s, live Stripe test mode): https://github.com/davarntrades/Morrison-Runtime-Governance/raw/demo-media/morrison-stripe-collection-demo.mp4' \
    ''
  cat README.md
} > README.tmp && mv README.tmp README.md

git add -A
git commit -q -m "Morrison-governed autonomous Stripe collection agent (Stripe × Briefcase hackathon)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
echo "standalone repository ready at $DEST"
