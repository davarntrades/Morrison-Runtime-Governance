# Independent audit of PR #42 (monitoring-incident Phase 1)

**Audit material only. This directory is not part of the PR #42 experiment.** It sits on the audit branch
`claude/morrison-audit-pr42-b2rg8t`, which is the PR #42 head (`c1d19a1`) plus this directory. No file in
`experiments/monitoring_incident/`, `morrison_governance/` or the frozen governance manifest is modified.

* [AUDIT_REPORT.md](AUDIT_REPORT.md): findings, metrics, proposition verdicts, Phase 2 decision
  (audit of `c1d19a1`; left unchanged).
* [REAUDIT_99e6b08.md](REAUDIT_99e6b08.md): re-audit of the measurement repairs at `99e6b08`;
  tools in `reaudit/`, outputs in `results_reaudit/`.
* [FINAL_e370b3f.md](FINAL_e370b3f.md): final verification at `e370b3f` (sequential guard,
  corrections, evidence, macOS readiness and Phase 2 checklist); outputs in `results_final/`.
* [PHASE2_READINESS_4a22faf.md](PHASE2_READINESS_4a22faf.md): Phase 2 readiness at `4a22faf`
  (repetitions, overwrite and concurrency safety, anchoring, corrected macOS commands); tools in
  `phase2/` (mock Ollama, checks script, anchor matrix, `campaign_guard.py`), outputs in
  `results_phase2/`.
* `reproduce.sh OUT [PYTHON]`: regenerates every result (≈6 min, disposable sandboxes only).
* `results/`: the outputs cited in the report, plus `raw_evidence.tar.gz` (every regenerated
  `evidence.jsonl` / `summary.json`).

| tool | what it checks | depends on PR code? |
|---|---|---|
| `recompute.py` | hash chains, action hashes, real-tool replay of every executed action, own behavioural probe, metric recomputation | **no** (stdlib only, run with `python -I`) |
| `kernel_probe.py` | how the unchanged kernel classifies write/delete/move/run actions | uses `LocalAdmissibility` |
| `c05_probe.py` | C05 trajectory dependence under 10 harmless variants | uses the tiers + oracle |
| `audit_cases.py`, `run_audit_cases.py` | new scripted cases through the unmodified harness, 4 conditions | uses `run_episode` |
| `symlink_probe.py` | effect of `run_tests` that evidence and oracle cannot see | uses `run_episode` |
| `boundary_probe.py`, `race_final.py` | substitution, replay, forgery, stale state, concurrency, cross-session, direct calls | uses `Authorizer` / `Executor` |
| `alias_probe.py` | protected-path aliases and case behaviour | uses the tiers |
| `tamper.py` | evidence chain and anchor tampering, on a copy of a log | uses the PR's `verify` CLI |

None of these files is named `test_*.py`, so the repository's published test count is unchanged.
