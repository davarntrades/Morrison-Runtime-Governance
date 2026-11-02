# Performance, concurrency and enforcement benchmark

Source, configuration, raw data and results for the performance and
enforcement benchmark. Current status, results and open work:
[BENCHMARK_HANDOFF.md](BENCHMARK_HANDOFF.md); corrections to it are in
[CORRECTED_RESULTS.md](CORRECTED_RESULTS.md). The final technical report
(`REPORT.md`) has not been written yet. Everything drives the real `GovernanceKernel` and a real
SQLite resource behind `LeaseVerifier`; nothing in the decision path is mocked.

| File | Phase | What it does |
|---|---|---|
| `common.py` | all | Kernel configuration under test, the SQLite resource, the oracle-labelled case catalogue (`cases_for`), environment capture |
| `latency.py` | 2 | Per-operation latency in 5 independent subprocess trials, warm-up, history sweep, stage attribution, cold start |
| `load.py` | 3, 4 | Concurrency (threads 1–1,024; processes 1–128) with the mixed legitimate/prohibited workload; reads every outcome back from the resource |
| `e2e.py` | 5 | Proposal → verdict → lease → resource verification → commit → durable evidence, against an ungoverned run of the same business logic |
| `falsify.py` | 6 | Attempts to break the nine enforcement properties, including the SQL-LEX-01 retest |
| `charts.py` | 8 | SVG charts from the result files |
| `results/` | 8 | Machine-readable results (`*.json`), raw timings (`*-raw.json.gz`), `summary.csv`, `charts/`, `SHA256SUMS` |

## Reproduce

The frozen `results/` cannot be overwritten: pass `--out DIR` (or set
`BENCH_RESULTS_DIR`) on every command below.

```bash
export BENCH_WORKDIR=/tmp/mrg-bench          # scratch space for SQLite files
python -m benchmarks.performance.latency --trials 5 --cold 20
python -m benchmarks.performance.load --model threads   --mode inprocess --session isolated --levels 1,2,4,8,16,32,64,128,256,512,1024
python -m benchmarks.performance.load --model threads   --mode mediated  --session isolated --levels 1,2,4,8,16,32,64
python -m benchmarks.performance.load --model threads   --mode inprocess --session session  --levels 1,16,128
python -m benchmarks.performance.load --model processes --mode inprocess --session isolated --levels 1,2,4,8,16,32,64,128
python -m benchmarks.performance.e2e --ops 2000 --levels 1,4,16,64
python -m benchmarks.performance.falsify
python -m benchmarks.performance.charts
python -m benchmarks.performance.summary          # results/summary.csv
```

Run each step alone on an otherwise idle machine: concurrent work distorts the
latency figures. Every result file records the commit, Python build, CPU, memory
and timer it was produced with; do not combine files with different
environments.

## Ground truth

`common.cases_for` builds each proposal from its **kind** and labels it from
that kind, never from a kernel verdict:

- **legitimate**: within policy, the proposer's own resources, valid authority
  where required; should execute.
- **prohibited**: must not execute under any interleaving (destructive SQL and
  shell, sanctioned payee, forged/expired/foreign/replayed approvals, authority
  asserted in arguments, another tenant's account, an unknown tool carrying
  destructive SQL, exfiltration after a confidential read, a decision whose
  policy changed before execution).
- **limit_bound**: shared-account transfers, admissible only while cumulative
  outflow stays at or under the limit. Their ground truth is the global
  invariant, read from the resource.
