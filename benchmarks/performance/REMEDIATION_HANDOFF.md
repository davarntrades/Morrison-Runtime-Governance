# Handoff: independent-review remediation

Status as of 2026-11-02. Full analysis:
[INDEPENDENT_REVIEW_REMEDIATION.md](../../INDEPENDENT_REVIEW_REMEDIATION.md).
Corrected claims: [CORRECTED_RESULTS.md](CORRECTED_RESULTS.md).

## Branch and commits

| | |
|---|---|
| Branch | `claude/independent-review-remediation`, branched from `claude/performance-benchmark` at `cf06f3c` |
| `fe83313` | repairs and tests (kernel: `evidence.py`, `gate.py`, `attestation.py`, `sql.py`; verification: `tla_export.py`; benchmark harness; CI step) |
| Following commit(s) | `results-remediation/`, this handoff, the report, the corrected-results page, a banner on `BENCHMARK_HANDOFF.md` |
| Untouched | `claude/performance-benchmark`, `claude/external-review-fixes` (PR #45), `main`, and `benchmarks/performance/results/` (`SHA256SUMS` verifies) |
| PR | none opened; nothing merged |

## What changed, by finding

* **A.** `hard-deny` policy variant, prohibition classes from case kind, and an
  approval-stress arm (benchmark). Kernel: SQL that destroys or rewrites audit
  evidence now carries `log.tamper`, so the shipped DENY applies (new finding N1).
* **B.** Evidence records carry `decision_id`, `session_id`, `refers_to` and
  `outcome`. Opt-in write-ahead `JsonlEvidenceSink`. Keyless
  `reconcile_execution_evidence`. e2e persists whole chains, and the resource
  files mediated effects under the verified lease's decision.
* **C.** `corrected_accounting` (four quantities, no denominator filter) in
  `load.py` and `e2e.py`, and a read-only recomputation of the frozen data.
* **D.** A fail-closed `run_tlc` / `classify_tlc_run`, 31 tests (fake and real
  TLC), and a per-state Python↔TLA+ invariant test. CI runs them against real TLC.
* **E.** Documentation and one measurement-only diagnostic (`profile_history.py`).
  No optimisation.

## Verification (this machine; commands in the report, section 6)

| Check | Result |
|---|---|
| Baseline suite at `cf06f3c` | 1959 passed, 9 skipped |
| Suite at `fe83313` (with `MORRISON_TLC_JAR` set) | **2036 passed, 9 skipped**, 0 failed. The 9 skips are optional `inspect_ai`/`agentdojo` and the absent governance-service checkout, identical to baseline |
| New tests | 77 (36 kernel, 31 TLC wrapper, 10 harness); published count updated to 2,043 collected |
| Frozen falsification (`falsify.py`) | 43/43 held, at `cf06f3c` |
| Remediation falsification (`falsify_remediation.py`) | **58/58 held** (8 positive controls), 9 characterisations, 0 unverified |
| Real TLC, both modes | agree, 0 errors; the review's reproduction now `agree: False` |
| Load and e2e regressions | 0 prohibited executed without approvals; under `hard-deny` with genuine approvals, 0 of 1,808 approved hard cases executed (648 isolated + 1,160 session); every level's evidence reconciles |
| flake8 CI gate (`E9,F63,F7,F82`) | 0 |

**Not verified:**

* The new CI step. It runs only when the workflow runs on GitHub.
* Pylint score (pylint not installed here; `test_lint_gate` passes).
* 1,024 isolated threads, ≥256 processes, mediated mode above 64 workers.
* Open-loop arrival workloads.
* Cross-host deployment.

## Unresolved

1. **Review artifacts unavailable.** The mapping covers the brief's summary only.
   Supply `Morrison_Benchmark_Independent_Review.md` and the evidence zip and
   re-check every finding against section 2 of the report.
2. **N2:** a genuine-approval PERMIT issued after a BLOCK of the same transition
   spends its nonce, but `execute` refuses it for `decision_ttl_s`. Fail-closed;
   the proposed fix is in the report. Not changed, because it touches
   revocation state on the enforcement path.
3. **N7:** the TLC jar is not pinned. CI downloads a rolling build and never
   checks its sha256.
4. **Policy decision for the owner:** keep destructive SQL/shell delegable
   (default APPROVAL), or ship DENY for them (`hard-deny`)? The benchmark oracle
   assumes DENY. Under `hard-deny`, dynamic or unreadable SQL is denied too.
5. **Utility:** V2's multi-step rule blocks 25% of legitimate e2e proposals and
   the legitimate `double_execute` in session workloads. That is a real false
   positive, left as is.
6. **Evidence independence:** recomputation detects inconsistency, not a
   consistent rewrite. The Ed25519 head attestation and external anchors exist
   (`attestation.py`) but are not deployed by the benchmark.
7. Frozen-handoff open items (handoff §5) remain open: OOM at 1,024 isolated
   threads, processes ≥256, open-loop workload, lock-contention counters, and
   `REPORT.md`.

## Recommended next steps

1. Obtain the review artifacts, and add any finding not covered here.
2. Decide the default posture for `data.destructive` / `code.execute` /
   `statement.unclassified`. If DENY, re-run the frozen workloads under
   `hard-deny` as the new baseline.
3. Fix N2 on its own branch, with a falsification run.
4. Pin TLC by sha256 in `finite-verification.yml`.
5. Only then start the performance work in report section E (read the ledger
   once per decision; incremental trajectory evaluation; indexed store). Each
   item must be benchmarked against `results/` and re-run both falsification
   suites.
