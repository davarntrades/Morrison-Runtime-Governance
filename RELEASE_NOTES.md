# Release Notes — Morrison Runtime Governance v0.2.0

Branch `claude/list-repo-files-AdvDm` → `main`. Five commits on top of the
already-merged v0.1.0 (PR #1). All work is additive plus one source-quality
repair; legacy behaviour is preserved.

## Highlights

- **Enforcement hierarchy completed.** Added V4 (state-space admissibility),
  V4+ (feasibility / NO_VALID_SOLUTION), V5 (environment-wide stability),
  and V5+ (hard adversarial framework) on top of A_safe → V2 → V3.
- **Biggest failure surface fixed.** `multi_turn_chain` adversarial bypass
  went **100 % → 0 %** via V2 source→sink data-flow taint plus broad
  privilege-mutation detection. Deny-by-default with internal allowlists;
  toggleable.
- **Production deployment adapters.** Fail-closed, dependency-free
  integrations for OpenAI, Claude, LangChain, AutoGen, browser agents,
  MCP servers, shell execution, and enterprise workflows.
- **Source repair.** Recovered the package from Markdown-paste corruption
  (smart quotes, mangled dunders, lost indentation) — shipped in PR #1,
  underpins everything here.

## What changed

| Area | Detail |
|------|--------|
| `admissibility.py` | V4 checks: role, resource scope, required fields, quota, schema |
| `feasibility.py`   | V4+ candidate selection; returns NO_VALID_SOLUTION instead of guessing |
| `stability.py`     | V5 seeded perturbation set; ENVIRONMENT_SENSITIVE on verdict flip |
| `adversarial.py`   | V5+ 7 attack classes + per-class bypass reporting |
| `reachability.py`  | V4 wired into chain; **V2 data-flow taint**; `evaluate_all()` diagnostic; V3 set-iteration determinism fix |
| `integrations.py`  | 8 deployment adapters + `GovernanceGuard` (raise/deny + audit hook) |
| `core.py`          | `find_admissible`, `evaluate_stable`, `adversarial_test`, `evaluate_all`, taint config |
| domains            | ENTERPRISE / COMPLIANCE / FRAUD rule sets |
| visualizations     | v2 sweep, latency benchmark, layer-firing matrix + adversarial attribution |
| docs               | `LIMITATIONS.md`, `DEPLOYMENT.md`, this file |

## Test status

| Suite | Result |
|-------|--------|
| `test_governance.py` (legacy) | 14 passed, **0 FP / 0 FN** |
| `test_extended_layers.py` (V4/V4+/V5/V5+ + taint) | 29 passed |
| `test_integrations.py` (adapters) | 13 passed |
| **Total** | **56 passed, 0 failed** |

Determinism verified: identical adversarial signatures across
`PYTHONHASHSEED=0,1,2`; `layer_firing_summary.json` reproducible (non-timing).

## Audit results (this release)

- ✅ All tests pass.
- ✅ All 46 exports resolve; all submodules import; no langchain/openai/
  autogen/mcp/anthropic hard-dependency leaked on import.
- ✅ README quick-start executes; documented verdicts/layers/reasons match.
- ✅ LIMITATIONS.md figures match a fresh run (multi-turn 0 %,
  hidden_substitution 86 %, obfuscation 60 %).
- ✅ Three demos run clean.
- ✅ Merge into `main` is **conflict-free**; main's deletion of the
  nested-duplicate `morrison_governance/morrison_governance/` is preserved
  (our branch never touched it).

## Unresolved failure surfaces (carried forward)

| Surface | Severity | Status |
|---------|----------|--------|
| `hidden_substitution` — tool-name spoofing (case/hyphen/zero-width/Cyrillic) | high | **open** — needs NFKC+casefold tool-name normalisation |
| `obfuscation` — base64/hex/url/unicode keyword evasion | high | **open** — needs decode-then-match pass; full coverage undecidable (runtime string construction) |
| V3 forward reachability sparse | medium | open — only co-fires with A_safe; no standalone coverage |
| V4+ bounded by caller's candidate set | medium | by design — cannot prove global infeasibility |
| V5 bounded by finite ℰ | medium | by design — "stable" is relative to the tested perturbations |
| Taint not cleared by sanitisation steps | low | accepted under deny-by-default; allowlist is the escape hatch |

None of the open items are regressions; all are documented in
`morrison_governance/LIMITATIONS.md` with concrete mitigations.

## Merge recommendation

**Ready to merge.** Conflict-free, additive, fully tested, deterministic,
documented. Recommend a standard (non-fast-forward) merge commit since
`main` has diverged by a cleanup commit. The two highest-severity open
surfaces (tool-name spoofing, keyword obfuscation) are pre-existing,
documented, and scoped as the next iteration — not merge blockers.
