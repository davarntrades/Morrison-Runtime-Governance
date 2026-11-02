# Reproductions of the independent-review findings (pre-repair)

These scripts reproduce findings A–D against the **unmodified** baseline,
`claude/performance-benchmark` at `cf06f3c`. Their captured output, produced
at that commit before any repair, is in `pre-repair-output/`.

They are not tests and pytest does not collect them. Two of them call
harness functions whose signatures the repair changed (`e2e.run`), so run
them from a checkout of the baseline:

```bash
git worktree add /tmp/mrg-baseline cf06f3c
cd /tmp/mrg-baseline
export BENCH_WORKDIR=/tmp/mrg-bench PYTHONPATH=.
R=<this repo>/benchmarks/performance/review_repro
python $R/repro_approval_sql.py                    # finding A
python $R/repro_e2e_evidence.py                    # finding B
python $R/repro_completion.py                      # finding C
python -m morrison_governance.global_verification.tla_export --out /tmp/tla-deny \
    --escalations deny
python $R/repro_tlc_false_success.py /tmp/tla-deny tla2tools.jar /tmp/tlc-repro   # finding D
```

| Script | Finding | What the pre-repair output shows |
|---|---|---|
| `repro_approval_sql.py` | A | All four destructive-SQL forms and `find /data -delete`: ESCALATE without approval, **PERMIT and executed** with a genuine approval. The benchmark deployment sets no `capability_policy`, so `data.destructive` is APPROVAL. |
| `repro_e2e_evidence.py` | B | Persisted e2e evidence: 40 records, 27–28 resource effects, **0 records with `executed=true`**, keyless recomputation fails with 69–77 problems (chain breaks, sequence discontinuities). |
| `repro_completion.py` | C | Session workload: legitimate `double_execute` BLOCKed (V2), excluded from the published denominator → 6/7 = 85.714%. e2e: 1350/1800 = 75.0% … 1376/1808 = 76.106%; the refused legitimate proposals are V2 "Multi-step escalation detected". |
| `repro_tlc_false_success.py` | D | `governed_safety.cfg` naming an undefined invariant: real TLC exits **151**, no state count, and `run_tlc` returns **`agree: true`**. |

Post-repair, the same conditions are exercised by
`morrison_governance/test_independent_review_remediation.py`,
`morrison_governance/global_verification/test_tlc_wrapper_fail_closed.py`,
`benchmarks/performance/test_remediation.py` and
`benchmarks/performance/falsify_remediation.py`.
