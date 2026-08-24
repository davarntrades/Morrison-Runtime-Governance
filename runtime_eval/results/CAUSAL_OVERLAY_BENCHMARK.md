# Causal Overlay Benchmark

Measured locally; results are bounded to this host and scenario.

## Environment

- Python: `3.12.13`
- Platform: `Linux-6.18.35-x86_64-with-glibc2.39`
- Processor: `x86_64`
- Repetitions: `40`
- Parallel workers: `4`
- Scenario: `read_customer_record -> http_request external`
- Workload note: counts above the finite v0.1 registry cycle deterministic one-variable interventions for executor scaling

## Stage latency

| Stage | Mean ms | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|
| Canonical governance | 0.975 | 0.915 | 1.191 | 1.964 |
| Causal extraction | 0.132 | 0.122 | 0.191 | 0.211 |
| SCM template | 0.013 | 0.012 | 0.014 | 0.018 |
| Intervention generation | 0.018 | 0.018 | 0.020 | 0.032 |
| Contribution trace | 0.017 | 0.017 | 0.019 | 0.020 |
| Report construction | 0.014 | 0.014 | 0.016 | 0.029 |
| Evidence sealing | 0.498 | 0.393 | 0.580 | 2.485 |
| Overlay total | 10.332 | 10.273 | 12.025 | 12.739 |
| Synchronous end-to-end | 11.307 | 11.216 | 13.457 | 13.921 |
| Async canonical governance | 0.975 | 0.915 | 1.191 | 1.964 |
| Async submission overhead | 0.060 | 0.048 | 0.113 | 0.321 |

## Counterfactual replay scaling

| Interventions | Sequential p50 ms | Sequential p95 ms | Parallel p50 ms | Parallel p95 ms | p50 speedup |
|---:|---:|---:|---:|---:|---:|
| 1 | 0.543 | 0.681 | 0.478 | 0.735 | 1.136× |
| 2 | 0.890 | 1.435 | 1.426 | 2.076 | 0.624× |
| 4 | 2.384 | 2.701 | 3.141 | 4.050 | 0.759× |
| 8 | 5.060 | 6.088 | 6.734 | 8.190 | 0.751× |
| 16 | 10.233 | 12.785 | 12.625 | 18.752 | 0.811× |

## Correctness and recommendation

- Sequential/parallel equivalence: `True`
- Fast inline (1–2): **viable**
- Bounded interactive (4–8): **viable**
- Full forensic (16+): **asynchronous**
- Classification is relative to the measured canonical p95 on this host; it is not a production SLA.
- On this CPython host, threads were slower than sequential replay for 2–16 interventions. Keep both implementations, but prefer sequential execution for this in-process workload unless production measurement shows I/O or process-level parallelism changes the result.

## Limitations

- The scenario is deterministic and uses the in-process synthetic Frontier tool manifest; it excludes network and model inference.
- Full replay is the correctness baseline. Incremental descendant-only replay is not implemented.
- Python threads preserve isolation but CPU-bound speedup depends on the interpreter and host scheduler.
- Counts above the finite v0.1 intervention registry repeat real one-variable interventions solely to measure bounded executor scaling.
