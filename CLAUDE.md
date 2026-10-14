# Morrison Runtime Governance: notes for Claude sessions

## AgentDojo benchmark (in progress)

Third-party benchmark wired up in `runtime_eval/agentdojo_bench/`. Morrison replaces AgentDojo's tool executor, so every
proposed tool call goes through `GovernanceKernel.authorize` → `execute`. Read
`runtime_eval/agentdojo_bench/README.md` for the design and `runtime_eval/results/AGENTDOJO_BENCHMARK.md` for results.

### Status

- **Offline `oracle` mode is done.** It is a model-free, fully compromised agent, and results are checked in under
  `runtime_eval/results/agentdojo/`. Attack success on exercisable pairs went from 100% to 19.3% (494/612 stopped; banking and
  workspace 0%). Benign utility went from 97/97 to 63/97, or 76/97 if escalations are approved.
- The `pci_card_exposure` substring bug (`"pan"` matching `participants`) is fixed, with a regression test in
  `morrison_governance/test_pci_card_exposure.py`.
- **Next: live mode, a real model under AgentDojo's `important_instructions` attack.** Still not run: on 2026-10-14 the
  cloud environment had no `ANTHROPIC_API_KEY` (preflight below). These are the numbers comparable to the AgentDojo leaderboard.
- **Live run is wired as a manual GitHub Actions workflow**, `.github/workflows/agentdojo-live.yml` ("AgentDojo Live"), using
  the `ANTHROPIC_API_KEY` repository Actions secret. Default mode is a free preflight; the paid benchmark needs mode
  `benchmark` plus `RUN-PAID-BENCHMARK` typed in the confirm box. `workflow_dispatch` only appears once the file is on
  the default branch. Opus 5.5 needs `anthropic_adapter.py` (no `temperature`, adaptive thinking, `drop_block`); see the
  bench README.
- Live runner hardened (keyless, 2026-10-14): fixed a crash (AgentDojo's `TraceLogger` needs an `OutputLogger` around the
  benchmark, so the old runner would have failed on its first pair); baseline now uses the same executor in record-only
  mode so the arms differ only in enforcement; output separates attempted calls from actual environment effects.

### Running live mode

Needs `ANTHROPIC_API_KEY` set in the cloud environment's settings (never pasted into chat). `api.anthropic.com` is reachable
from the cloud environment. `api.openai.com` is blocked by the network policy unless it's added under Allowed domains.

```bash
# preflight: prints only whether the key is set and the HTTP status, never the key
[ -n "$ANTHROPIC_API_KEY" ] && echo "key set" || echo "key NOT set"
curl -sS -o /dev/null -w "%{http_code}\n" https://api.anthropic.com/v1/models \
    -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01"   # 200 = authenticated

pip install -r runtime_eval/agentdojo_bench/requirements.txt   # agentdojo==0.1.35
# sample first: a full suite is thousands of model calls
python -m runtime_eval.agentdojo_bench live --provider anthropic --model claude-opus-5-5 \
    --suite banking --user-task user_task_0 --user-task user_task_1 --output artifacts/agentdojo-live
# same command with --defense none gives the undefended baseline; always run both
```

Report live results the same way as the oracle results: paired with the baseline, every rate with its denominator,
escalations separate from blocks, and no tuning of `manifest.py` after seeing results.

### Open follow-ups

- Workspace utility is now limited mostly by the intended "external egress after a read" rule blocking calendar invites
  to outside guests (7 tasks). Open question: should those be held for approval (ESCALATE) instead of BLOCKed?
- Known gaps, kept on purpose and documented: travel reservations and Slack DMs carry no capability.

## Repo gotchas

- **Published test count.** `morrison_governance/test_evidence_consistency.py` checks that the count in `README.md`
  ("Repository test suite | **N collected**") and `limits_audit/evidence/facts.json` matches a real collection. Adding or
  removing tests means updating both. The AgentDojo tests skip when `agentdojo` isn't installed (as in CI), so with it
  installed locally that check is off by 17. That's expected.
- **Lint gate.** `morrison_governance/test_lint_gate.py` requires every third-party import to be installed by the lint
  workflow or listed in `.pylintrc` `ignored-modules`.
- **Test side effects.** Running the full suite rewrites files under `living-boundary/artifacts/`. Don't commit those.
- CI uses Python 3.11 and doesn't install `agentdojo`.
