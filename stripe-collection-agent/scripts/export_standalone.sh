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

git add -A
git commit -q -m "Morrison-governed autonomous Stripe collection agent (Stripe × Briefcase hackathon)"
echo "standalone repository ready at $DEST"
