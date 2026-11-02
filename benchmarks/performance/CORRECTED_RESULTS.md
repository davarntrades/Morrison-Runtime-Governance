# Corrected benchmark reporting

This page **adds to** [BENCHMARK_HANDOFF.md](BENCHMARK_HANDOFF.md); it does not
replace it. The handoff and every file under `results/` are the original
measurements and are unchanged (`results/SHA256SUMS` verifies). Where a claim in
the handoff is corrected, the original wording, the corrected claim, the evidence
and the independent-review finding are given side by side. The full analysis is
in [INDEPENDENT_REVIEW_REMEDIATION.md](../../INDEPENDENT_REVIEW_REMEDIATION.md).
Post-repair runs are in `results-remediation/`.

The independent review document itself was not available to this remediation
(see section 0 of the remediation report). Finding letters refer to the
remediation brief's summary of it.

## Original measurements that stand

These are re-verified from the frozen raw data or re-run, and need no correction:

* **Latency tables** (handoff 4.1), including the disclosed pooled p99 of 1.27 ms
  and the super-linear history sweep.
* **Throughput, verdict latency and outflow** per concurrency level (4.2).
* **BLOCK rates**: 30.8% isolated = 4/13 per worker; 53.8% session = 7/13. The
  remainder are ESCALATE and were never counted as BLOCK.
* **0 prohibited proposals executed, 0 global-invariant violations, 0 duplicate
  commits** in every completed frozen run. This holds with approvals withheld,
  under the default policy (see the first correction).
* **Governance overhead** at 1 worker (4.3), with the caveat in the last
  correction about evidence cost.
* **43/43 falsification attempts held** (4.4), re-run at `cf06f3c`.
* **TLC agrees with the Python verifier** (4.5), re-run with real TLC through the
  repaired, fail-closed wrapper.

## Corrected claims

### 1. Prohibited cases and approvals (finding A)

* **Original:** prohibited means "must not execute under any interleaving"
  (README, handoff 3), and "0 prohibited transitions executed" (4.2).
* **Corrected:** under the measured (default) policy, 7 of the 13 per-worker
  prohibited kinds are ESCALATE, and 5 of them (4 destructive SQL plus
  destructive shell) **execute under a genuine approval**. "Must not execute
  under any interleaving" is **UNSUPPORTED** for those kinds. It is
  **SUPPORTED** under the new `hard-deny` policy (DENY), with genuine approvals
  presented on every hard case, and with legitimate completion unchanged.
* **Evidence:** `results-remediation/load-*-default-approved.json` and
  `load-*-hard-deny-approved.json`; `falsification-remediation.json` groups A1–A7.

### 2. Legitimate completion (finding C)

* **Original:** "100% of legitimate proposals executed" at every level (4.2,
  finding 9).
* **Corrected:** 100% isolated; **85.714%** session (6/7 per worker; the
  legitimate `double_execute` case is BLOCKed by V2 and was excluded from the
  denominator); e2e **75.0–76.1%** (V2 multi-step rule), which was never reported.
* **Evidence:** `results-remediation/corrected-accounting-frozen.json`
  (recomputed read-only from the frozen raw files).

### 3. Evidence (finding B)

* **Original:** "0 effects without an executed record, 0 evidence-chain
  failures" (4.2), and P9 "evidence corresponds to the transition" (4.4).
* **Corrected:** those checks ran on in-memory chains and harness records. The
  **persisted** e2e evidence had no execution outcomes and failed recomputation,
  and decision records carried no decision id, so effects could not be joined to
  evidence. After the repair, persisted chains recompute and every effect binds
  to its decision (in-process and mediated).
* **Evidence:** `review_repro/pre-repair-output/e2e_evidence_pre.json`;
  `results-remediation/e2e.json` (`evidence`), `load-*.json`
  (`evidence_reconciliation`).

### 4. TLA+ agreement (finding D)

* **Original:** agrees in both modes (4.5).
* **Corrected:** the agreement itself is confirmed. Before the repair, however,
  an errored TLC run could also have reported agreement. That is now impossible.
* **Evidence:** `review_repro/pre-repair-output/tlc_false_success_pre.json`;
  `results-remediation/tlc-false-success-post-repair.json`,
  `tla-crosscheck-*.json`.

### 5. Evidence cost (methodology E, N9)

* **Original:** "Evidence fsync p50 0.23–0.26 ms" (4.3).
* **Corrected:** that timed one decision record per proposal. Durable evidence
  of the whole chain (decision, intent, outcome or lease export) is now in the
  measured path and timed per record (`evidence_record_fsync`).
* **Evidence:** `results-remediation/e2e.json`.

### 6. Causes of latency growth (finding E)

* **Original:** trajectory analysis re-evaluates the whole prefix
  (interpretation, finding 11).
* **Corrected:** now measured. 1 Ω evaluation over h+1 states per decision, and
  2h+3 ledger reads per decision (≈2h² rows). Store-lock contention as the cause
  of process collapse remains a **hypothesis**.
* **Evidence:** `results-remediation/profile-history.json`.

## Re-running without touching the frozen evidence

Every driver now takes `--out DIR` (or `BENCH_RESULTS_DIR`), and `write_json`
refuses to write any file listed in `results/SHA256SUMS`. The README's original
reproduce commands therefore fail rather than overwrite the evidence. Add
`--out`.
