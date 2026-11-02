# Benchmark handoff: performance, concurrency and end-to-end enforcement

Status as of 2026-11-02. This is a **handoff of measured results and open work**,
not the final technical report. `REPORT.md` (Phase 9 assessment with
SUPPORTED/UNSUPPORTED/UNCERTAIN classifications) has **not been written**; the
classifications in section 7 are preliminary and must be reviewed against the
raw data before publication.

Nothing in this directory modifies the enforcement implementation. The kernel
measured here is byte-identical to `e4796d7` (the external-review baseline);
the later commits on the base branch touch only `global_verification/tla_export.py`
and its test.

---

## 1. Git state

| Item | Value |
|---|---|
| Benchmark branch | `claude/performance-benchmark` (this directory is its only change) |
| Base of the benchmark branch | `a2d37cd` on `claude/external-review-fixes` |
| Commit every result file records | `a2d37cd46cbfd999c11f2478e137772728e3568f` (`git_dirty: false` for `morrison_governance/` and `runtime_eval/`) |
| Enforcement implementation measured | unchanged since `e4796d7` ("pre-optimisation baseline"); no kernel file changed on the benchmark branch |
| `claude/external-review-fixes` | pushed; open as **PR #45** (opened by the repository owner). **Not merged, and nothing here merges it.** |
| Commits added to PR #45 during this session | `922d607` (print TLC output on disagreement), `836beb1` (resolve the TLC jar path), `a2d37cd` (count governed states with an invariant-free TLC run) |
| Benchmark branch push | pushed to `origin/claude/performance-benchmark` with this file (see the branch tip); **no PR opened** |
| Working tree after the handoff commit | clean except `living-boundary/artifacts/` if the test suite is run (never commit those) |

## 2. Environment (every number below comes from this one machine)

| | |
|---|---|
| CPU | Intel Xeon @ 2.10 GHz, **4 vCPUs**, 1 thread/core, KVM guest |
| Memory | 16,091 MB |
| OS | Ubuntu 24.04.5 LTS, Linux 6.18.44 |
| Python | CPython 3.13.18, **GIL enabled** (`Py_GIL_DISABLED=0`) |
| SQLite | 3.53.1 (WAL, `BEGIN IMMEDIATE`) |
| Timer | `time.perf_counter_ns` (monotonic, 1 ns resolution) |
| GC | enabled during measurement (realistic) |
| Scratch storage | `BENCH_WORKDIR` on the container's local disk |

The full record is the `environment` block in every `results/*.json` file. Do
not combine these results with runs from other hardware or commits.

## 3. Methodology

- **Real components only.** `GovernanceKernel.authorize` / `execute` /
  `mint_lease`, `LeaseVerifier` with the shared `SQLiteLeaseStore`, and a
  transactional SQLite resource (`common.Resource`). The kernel configuration is
  in `common.Deployment.kernel`: all Ω domains, a tool manifest, an approval
  key with a trusted issuer, a tenant registry, shared-resource scopes, a
  cross-principal aggregate limit (SHARED ≤ 25,000) and a sanctioned-payee rule.
- **Ground truth** is assigned by construction from each case's kind
  (`common.cases_for`, `ORACLE`), never from a kernel verdict. Prohibited =
  must not execute under any interleaving. Shared-limit transfers are judged by
  the global invariant, read back from the resource.
- **Two workloads.** *Isolated*: each case group runs on its own principal, so
  verdicts are not confounded by unrelated history. *Session*: the whole
  23-case script runs as one principal's session.
- **Two boundaries.** *In-process*: `kernel.execute(decision, executor)`.
  *Mediated*: Ed25519 lease, verified and redeemed by the resource.
- **Two parallelism models.** Threads: concurrent but not parallel for Python
  bytecode (GIL). Processes (fork): genuinely parallel, sharing state through
  `FileContinuityStore`.
- **Latency** (`latency.py`): 5 independent trials, each a fresh subprocess with
  50 warm-up calls, then 150–5,000 samples per operation (time-budgeted). Cold
  start: 20 fresh interpreters.
- **Outcomes** (prohibited executed, duplicates, outflow, evidence) are read from
  the SQLite resource and the kernels' evidence chains, never inferred from
  verdicts.
- **ESCALATE is never counted as BLOCK.** "Blocking rate" means BLOCK only;
  "not permitted" means BLOCK + ESCALATE.

## 4. Completed results

### 4.1 Kernel latency, single thread (`results/latency.json`, 5 trials pooled)

| Operation | n | p50 | p95 | p99 | max |
|---|---:|---:|---:|---:|---:|
| local admissibility (classification + Ω on the candidate) | 25,000 | 0.303 ms | 0.445 ms | 0.676 ms | 7.4 ms |
| global, history 0 | 25,000 | 0.120 ms | 0.163 ms | 0.253 ms | 4.0 ms |
| global, history 8 | 21,865 | 1.51 ms | 2.06 ms | 3.30 ms | 56.8 ms |
| global, history 32 | 5,762 | 5.68 ms | 7.04 ms | 9.48 ms | 30.1 ms |
| global, history 128 | 927 | 31.9 ms | 42.7 ms | 51.9 ms | 91.4 ms |
| combined, history 0 | 25,000 | 0.305 ms | 0.438 ms | 0.714 ms | 6.8 ms |
| authority (approval verification + exact-action hash) | 25,000 | 0.018 ms | 0.025 ms | 0.042 ms | 2.6 ms |
| lease mint (Ed25519 sign, pure Python) | 4,535 | 3.25 ms | 4.17 ms | 5.99 ms | 22.0 ms |
| lease verify (Ed25519 verify, pure Python) | 4,175 | 3.51 ms | 4.63 ms | 6.70 ms | 29.3 ms |
| **full decision, history 0** (all stages + sealed evidence) | 25,000 | **0.577 ms** | **0.754 ms** | **1.27 ms** | 27.1 ms |
| full decision, history 8 | 13,611 | 2.07 ms | 2.66 ms | 3.64 ms | 17.1 ms |
| full decision, history 32 | 4,227 | 6.85 ms | 10.3 ms | 13.4 ms | 28.6 ms |
| full decision, history 128 | 796 | 36.8 ms | 57.3 ms | 64.7 ms | 75.9 ms |
| authorize + execute, fresh session | 7,500 | 2.23 ms | 4.26 ms | 5.96 ms | 115 ms |
| authorize + execute, warm session (history 0–7) | 10,000 | 1.39 ms | 2.08 ms | 2.46 ms | 30.9 ms |

- Errors and timeouts: 0 in every operation.
- **Trial-to-trial p99 spread is large.** Full decision at history 0: p99 per
  trial 0.81 / 0.90 / 0.90 / 1.62 / 2.57 ms. The pooled p99 is above 1 ms;
  three of five trials were below it.
- Single-thread throughput for the full decision at history 0: about
  1,680 decisions/s.
- **History sweep** (full decision, same session growing): p50 0.43 ms at
  history 0, 2.0 ms at 8, 6.7 ms at 32, 14.2 ms at 64, 35.2 ms at 128 and
  110.9 ms at 256. Growth is super-linear (≈ quadratic).
- **Stage attribution** (kernel `stage_timings_ms`, means): at history 0,
  trajectory analysis 0.17 ms, capability classification 0.15 ms,
  canonicalisation 0.10 ms, evidence sealing 0.05 ms. At history 128,
  trajectory analysis takes 36.8 ms of about 37.5 ms; every other stage stays
  under 0.3 ms.
- **Cold start** (20 fresh processes, p50): import 101 ms, kernel construction
  4.0 ms, first `authorize` 8.7 ms, second `authorize` 1.0 ms.
- **Memory** (`results/memory.json`): 0.37 MB per idle kernel, 0.41 MB after 8
  executed steps.

### 4.2 Concurrency and adversarial safety under load (`results/load-*.json`, `results/summary.csv`)

Each worker runs a 23-case script: 6 legitimate, 13 prohibited at proposal
level, 1 shared-limit transfer, a confidential-read/egress pair, an approval
replay, a double-execute and a policy-change-before-execution case.

| Run | Workers | Throughput (proposals/s) | Verdict p50 | Verdict p99 | Prohibited proposals | BLOCK | ESCALATE | PERMIT | Prohibited executed | Legitimate executed | Shared outflow ≤ 25,000 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| threads, in-process, isolated | 1 | 140 | 2.6 ms | 20.9 ms | 13 | 4 | 9 | 0 | 0 | 6/6 | 1,000 ✓ |
| | 2 | 197 | 2.4 ms | 5.0 ms | 26 | 8 | 18 | 0 | 0 | 12/12 | ✓ |
| | 4 | 195 | 2.5 ms | 5.2 ms | 52 | 16 | 36 | 0 | 0 | 24/24 | ✓ |
| | 8 | 171 | 2.5 ms | 17.4 ms | 104 | 32 | 72 | 0 | 0 | 48/48 | ✓ |
| | 16 | 143 | 4.0 ms | 89.7 ms | 208 | 64 | 144 | 0 | 0 | 96/96 | ✓ |
| | 32 | 111 | 118 ms | 333 ms | 416 | 128 | 288 | 0 | 0 | 192/192 | 25,000 ✓ |
| | 64 | 135 | 305 ms | 569 ms | 832 | 256 | 576 | 0 | 0 | 384/384 | 25,000 ✓ |
| | 128 | 125 | 656 ms | 1.46 s | 1,664 | 512 | 1,152 | 0 | 0 | 768/768 | 25,000 ✓ |
| | 256 | 107 | 2.18 s | 4.11 s | 3,328 | 1,024 | 2,304 | 0 | 0 | 1,536/1,536 | 25,000 ✓ |
| | 512 | 85 | 5.52 s | 8.73 s | 6,656 | 2,048 | 4,608 | 0 | 0 | 3,072/3,072 | 25,000 ✓ |
| threads, in-process, session | 1 | 182 | 2.7 ms | 19.9 ms | 13 | 7 | 6 | 0 | 0 | 6/6 | ✓ |
| | 16 | 237 | 3.1 ms | 92.5 ms | 208 | 112 | 96 | 0 | 0 | 96/96 | ✓ |
| | 128 | 305 | 34.9 ms | 1.69 s | 1,664 | 896 | 768 | 0 | 0 | 768/768 | 25,000 ✓ |
| | 512 | 248 | 5.6 ms | 13.2 s | 6,656 | 3,584 | 3,072 | 0 | 0 | 3,072/3,072 | 25,000 ✓ |
| | **1,024** | 282 | 14.7 ms | 17.4 s | 13,312 | 7,168 | 6,144 | 0 | 0 | 6,144/6,144 | 25,000 ✓ |
| threads, mediated (lease), isolated | 1 | 102 | 2.4 ms | 12.9 ms | 13 | 4 | 9 | 0 | 0 | 6/6 | ✓ |
| | 4 | 68 | 14.1 ms | 182 ms | 52 | 16 | 36 | 0 | 0 | 24/24 | ✓ |
| | 16 | 99 | 80 ms | 488 ms | 208 | 64 | 144 | 0 | 0 | 96/96 | ✓ |
| | 64 | 104 | 318 ms | 1.24 s | 832 | 256 | 576 | 0 | 0 | 384/384 | 25,000 ✓ |
| processes, in-process, isolated | 1 | 110 | 5.1 ms | 12.7 ms | 13 | 4 | 9 | 0 | 0 | 6/6 | ✓ |
| | 4 | 68 | 36.3 ms | 101 ms | 52 | 16 | 36 | 0 | 0 | 24/24 | ✓ |
| | 16 | 22 | 409 ms | 1.65 s | 208 | 64 | 144 | 0 | 0 | 96/96 | ✓ |
| | 64 | 7.3 | 5.81 s | 20.5 s | 832 | 256 | 576 | 0 | 0 | 384/384 | 25,000 ✓ |
| | 128 | 3.6 | 20.9 s | 89.2 s | 1,664 | 512 | 1,152 | 0 | 0 | 768/768 | 25,000 ✓ |

Rows for 2, 8 and 32 mediated workers, 2, 8 and 32 processes, and every
column in the table (plus CPU, RSS, outside-kernel time, commit latency and
error rate) are in `results/summary.csv`.

Across **every** completed level and configuration:

- 0 prohibited proposals PERMITted and 0 prohibited transitions executed.
- 0 global-invariant violations. Shared outflow is exactly 25,000 at every
  level with ≥ 25 shared proposals, and committed shared transfers equal the
  live expectation, so the limit was enforced without starving legitimate work.
- 0 duplicate commits (double-execute cases and duplicate decision IDs in the
  resource), 0 approval replays executed, and 0 policy-change-before-execution
  cases executed.
- 0 effects without an executed record, 0 evidence-chain failures, and 0
  errors.
- 100% of legitimate proposals executed.

Proposal-level BLOCK rate (BLOCK only) is **30.8%** in the isolated workload
(4 of 13 per worker) and 53.8% in the session workload. The remainder are
ESCALATE: destructive SQL, destructive shell, a forged approval artifact, an
expired approval, a cross-principal approval, an approval replay, and an
unknown tool carrying SQL. They do not execute while unresolved, but an
approver could approve them.

At high concurrency, almost all tail latency is time **outside** the kernel's
own stages (`outside_kernel_stages_latency` in the JSON): waiting for the GIL,
the kernel lock and the store lock. CPU utilisation stays around 80–95% of one
core for threads, and about 90–110% (one core's worth in total) for processes,
which indicates serialisation.

### 4.3 End-to-end boundary (`results/e2e.json`), PRE-PRODUCTION local measurement

This is local SQLite, keys in process memory, no network hop, sessions of 8
proposals, and 10% prohibited proposals. The ungoverned arm runs the same
`Resource.apply` business logic on the same infrastructure, and it executes the
prohibited proposals.

| Workers | Arm | Throughput (proposals/s) | Proposal→commit p50 | p95 | p99 | Verdict p50 | Lease mint p50 | Verify + commit p50 | Evidence fsync p50 | Proposal→refusal p50 |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | ungoverned | 1,502 | 0.38 ms | 0.83 ms | 4.34 ms | – | – | – | – | – |
| 1 | in-process | 282 | 2.98 ms | 4.95 ms | 8.52 ms | 1.84 ms | – | 0.96 ms (commit) | 0.26 ms | 2.46 ms |
| 1 | mediated | 92 | 13.5 ms | 19.4 ms | 26.0 ms | 1.81 ms | 5.31 ms | 5.89 ms | 0.23 ms | 2.27 ms |
| 4 | ungoverned / in-process / mediated | 1,760 / 286 / 83 | 0.45 / 10.6 / 53.0 ms | | 19.2 / 123 / 124 ms | | | | | |
| 16 | ungoverned / in-process / mediated | 1,647 / 293 / 82 | 0.51 / 13.5 / 153 ms | | 180 / 1,145 / 578 ms | | | | | |
| 64 | ungoverned / in-process / mediated | 1,445 / 310 / 88 | 0.51 / 19.1 / 500 ms | | 630 / 2,845 / 2,397 ms | | | | | |

Governance overhead at 1 worker, p50: about **+2.6 ms in-process** (2.98 vs
0.38 ms, ×7.8) and about **+13.1 ms mediated** (13.47 vs 0.38 ms, ×35). In the
mediated arm, the two pure-Python Ed25519 operations (lease mint about 5.3 ms,
which includes registry I/O, and verify + commit about 5.9 ms) account for most
of the overhead. There were 0 errors in every arm.

### 4.4 Falsification (`results/falsification.json`): 43 of 43 attempts held

| Property | Attempts | Held |
|---|---:|---:|
| P1 the proposing agent cannot mint execution authority (self-signed lease, minting from an ESCALATE decision, a hand-built PERMIT `Decision`, an action swapped after PERMIT) | 5 | 5 |
| P2 forged approval claims cannot create authority (unknown key, wrong action, other principal, other tenant, expired, three argument-borne claims) | 8 | 8 |
| P3 local admissibility is independently evaluated | 2 | 2 |
| P4 global admissibility is independently evaluated (30 transfers, 3 principals: 25 PERMIT, 5 BLOCK, outflow 25,000) | 1 | 1 |
| P5 the strictest verdict controls (BLOCK both without and with a valid approval) | 2 | 2 |
| P6 a prohibited transition cannot bypass the boundary (no lease, a lease for another action, another deployment's lease) | 3 | 3 |
| P7 concurrent proposals cannot jointly violate the global limit (256 threads × 2 behind a barrier: 25 of 512 PERMIT, outflow 25,000) | 1 | 1 |
| P8 no replay (lease redeemed twice, approval reused in the same and in a new session, one decision minted twice, one decision executed from 8 threads) | 6 | 6 |
| P9 evidence corresponds to the transition (chain recomputes; record verdict matches; execution record exists if and only if a resource effect exists) | 4 | 4 |
| SQL-LEX-01 retest (10 destructive forms) + negative control | 11 | 11 |

- No prohibited proposal received PERMIT, so no downstream refusal had to
  rescue one, and no defence-in-depth case arose.
- **Attribution note for P5:** the BLOCK came from `unauthorized_transfer`
  (without approval) and `structuring_pattern` (with approval), not from the
  sanctioned-payee rule. The property held, but by different rules than the
  case targeted.
- **SQL-LEX-01:** all 10 destructive forms are ESCALATE (`data.destructive` /
  `code.execute`); none is BLOCK and none is PERMIT.

### 4.5 TLA+ cross-check (finishing the previous work)

The `tla-crosscheck` CI job ran TLC 2026.10.30 against the exported
`enterprise_pipeline` spec in CI run **41422074390**. It **agrees with the
Python verifier on every check in both escalation modes**:

- deny: 877 control / 31 governed states, governed safe, both goals reachable
- deny-and-approve: governed unsafe, as the verifier reports, with the governed
  state count compared from an invariant-free run

Two of my own harness bugs were found and fixed along the way (the relative
jar path, and the governed count taken from a safety run that stops at its
first counterexample). TLC's checks rely on Morrison's recorded decisions as an
oracle; they do not re-derive them.

## 5. Unfinished, interrupted or inconclusive

**None of these has passed. Treat each as not done.**

| Item | Status | Why / evidence |
|---|---|---|
| Threads, isolated workload, **1,024 workers** | **FAILED: killed by the OOM killer twice** (rc 137) | ~22,500 kernels (22 principals per worker) × ~0.37 MB, plus records and thread stacks, exceed 16 GB. The 1,024-worker figure in 4.2 is the **session** workload (one kernel per worker), which completed. |
| Processes at 256, 512 and 1,024 | **Not attempted** | 128 processes already took 812 s at 3.6 proposals/s; memory at ~1 interpreter each was also a concern. |
| Mediated (lease) mode above 64 workers, and mediated mode in processes | **Not run** | Time. |
| End-to-end above 64 workers | **Not run** | Time. |
| **Controlled arrival-rate (open-loop) workload** and direct queueing delay | **Not implemented** | Only fixed-concurrency, closed-loop runs exist. "Queueing" is inferred from wall time outside the kernel's own stages, which includes GIL, kernel-lock and store-lock waits; it is not separated into those parts. |
| Lock contention measured directly | **Not measured** | Only the outside-stages proxy above. |
| State conflicts | **Partially:** 0 errors and 0 lost updates (effects equal executed records) | No SQLite busy/retry counters were captured. |
| First latency run | **Discarded** | My `git stash -u` removed the benchmark directory during trial 2, and trial 1 overlapped a pytest run. All published latency numbers come from the clean re-run. |
| First thread run (levels 1–512) | **Lost and re-run** | The process was killed at 1,024 before writing results. `load.py` now writes after every level, and the numbers above come from the re-run. |
| `REPORT.md` and the final Phase 9 classifications | **Not written** | This file is the handoff, not the report. |
| Hover tooltips | Native SVG `<title>` only | Charts are static SVG; every value is also in the tables. |
| Production performance | **Not measured** | Everything is a single 4-vCPU VM with local SQLite. |

## 6. Raw evidence and reproduction

All paths are relative to `benchmarks/performance/`. `results/SHA256SUMS` covers
every file.

| File | Contents |
|---|---|
| `results/latency.json` | Phase 2 summaries, per-trial p50/p99, history sweep, stage means, cold start |
| `results/latency-raw.json.gz` | Every latency sample (ns), per trial, per operation |
| `results/load-threads-inprocess-isolated.json` (+ `-raw.json.gz`) | Threads, 1–512 workers |
| `results/load-threads-inprocess-session.json`, `-session-large.json` (+ raw) | Session workload, 1 / 16 / 128 and 512 / 1,024 workers |
| `results/load-threads-mediated-isolated.json` (+ raw) | Lease boundary, 1–64 workers |
| `results/load-processes-inprocess-isolated.json` (+ raw) | Processes, 1–128 |
| `results/summary.csv` | One row per run and level (30 rows) |
| `results/e2e.json` | End-to-end arms |
| `results/falsification.json` | All 43 attempts with verdicts and details |
| `results/memory.json` | Memory per kernel |
| `results/charts/*.svg` | History sweep, concurrency latency, throughput, blocking, and legitimate completion (threads and processes) |
| Raw records | Every case of every level: kind, oracle label, verdict, layer, rule, timings, stage times, executed, refusal reason |

Reproduction commands are in [README.md](README.md). Run each step alone on an
idle machine, set `BENCH_WORKDIR` to local scratch space, and run
`python -m benchmarks.performance.summary` and `python -m benchmarks.performance.charts`
at the end.

## 7. Preliminary findings (to be confirmed in REPORT.md)

Each finding is marked as directly measured or as interpretation.

| # | Finding | Status | Basis |
|---|---|---|---|
| 1 | Kernel full-decision latency at history 0 is p50 0.58 ms, p95 0.75 ms, p99 1.27 ms (pooled, 5 trials) | **SUPPORTED** (measured) | 4.1 |
| 2 | Sub-millisecond p50 and p95 at history 0, single thread | **SUPPORTED** (measured) | 4.1 |
| 3 | Sub-millisecond p99 | **UNSUPPORTED**: the pooled p99 is 1.27 ms, and 2 of 5 trials exceed 1 ms at history 0 | 4.1 |
| 4 | Sub-millisecond p50 at any history above ~2 prior steps | **UNSUPPORTED** | history sweep |
| 5 | p99 exceeds 1 ms already at **1 worker** under the mixed workload (verdict p99 12.7–20.9 ms), so there is no concurrency level at which the p99 target holds | **SUPPORTED** (measured) | 4.2 |
| 6 | 0 prohibited transitions executed, 0 global-invariant violations and 0 duplicate commits at every completed level (threads to 1,024 in the session workload and 512 isolated; processes to 128; mediated to 64) | **SUPPORTED** (measured, within this workload and oracle) | 4.2, 4.4 |
| 7 | Correctness at 1,024 isolated threads and at ≥ 256 processes | **UNCERTAIN**: not completed (OOM, or not run) | 5 |
| 8 | BLOCK rate for prohibited proposals is 30.8% (isolated) / 53.8% (session); the rest ESCALATE, and 0 PERMIT | **SUPPORTED** (measured) | 4.2 |
| 9 | Legitimate completion does not deteriorate with concurrency: 100% at every level. Latency does deteriorate. | **SUPPORTED** (measured, closed-loop, no timeouts configured) | 4.2 |
| 10 | Governance adds about 2.6 ms (in-process) and about 13 ms (lease-mediated) at p50 to a local SQLite commit, single worker | **SUPPORTED** (pre-production, local) | 4.3 |
| 11 | Principal bottleneck: trajectory analysis re-evaluates the whole governed prefix, giving super-linear cost in session history | **SUPPORTED** (stage attribution) | 4.1 |
| 12 | Secondary bottlenecks: pure-Python Ed25519 (about 3.3–3.5 ms per sign or verify); the GIL and kernel lock serialise threads; `FileContinuityStore` re-reads and parses the whole JSONL under one global `flock` on every `entries()` call, so process throughput falls from 110/s to 3.6/s | **SUPPORTED** (measured + code inspection) | 4.1–4.3 |
| 13 | Production readiness for latency-sensitive or high-concurrency deployments | **UNSUPPORTED** by this evidence | all |

### Engineering changes that should improve performance without weakening enforcement (projections, NOT measured)

1. Incremental trajectory evaluation: cache per-state Ω results and accumulated
   context, and evaluate only the candidate plus the rules that need history
   (aggregate, flow, taint) over an indexed summary. Targets finding 11.
2. Native Ed25519 (for example the `cryptography` or PyNaCl libraries) for lease
   sign and verify. This changes only speed, not the signature scheme.
3. A continuity store with per-key indexing and per-key locks (SQLite with an
   index on key, or an append log with an in-memory index invalidated by file
   offset) in place of whole-file reads under one global lock.
4. Avoid per-principal kernel construction on the hot path; reuse layers and
   rules across kernels (about 4 ms and 0.37 MB each).
5. A multi-process deployment needs a genuinely concurrent store before adding
   processes helps at all.

Every one of these must be re-benchmarked against this baseline and must
re-run the full falsification and test suites, because each touches the
enforcement path.

## 8. Next actions for a fresh session

1. Read this file, `README.md`, and `results/summary.csv`. **Do not modify the
   kernel on this branch**: it is the measured baseline.
2. Decide whether to make the isolated 1,024-thread run feasible without
   changing enforcement (for example, fewer case groups per worker, or reusing
   one kernel per group across workers in the same tenant), or record it
   permanently as an OOM limit of this harness on 16 GB.
3. Implement the open-loop arrival-rate workload (`load.py --arrival-rate R`),
   recording scheduled-to-start queueing delay separately from service time,
   and run it at rates around and above the measured capacity (about 140–300
   proposals/s).
4. Add direct lock-contention and SQLite busy-retry counters, instrumented in the
   benchmark rather than the kernel if possible.
5. Optionally run mediated mode to 256 threads, and end-to-end to 256 workers.
6. Write `REPORT.md`: the Phase 9 questions answered from the numbers here,
   charts embedded, and every finding classified SUPPORTED / UNSUPPORTED /
   UNCERTAIN, with measured findings separated from interpretation.
7. Only after the report: prototype the optimisations above **on a separate
   branch**, and compare against this baseline on the same machine class.
8. Do not merge PR #45 or this branch without the repository owner.
