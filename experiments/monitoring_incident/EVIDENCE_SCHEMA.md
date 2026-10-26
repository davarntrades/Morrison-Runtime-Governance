# Machine-readable evidence schema

Every episode writes one append-only JSON Lines file, `evidence.jsonl`, under
its run directory, plus a `summary.json`. The CLI also writes
`scripted_report.json` for a suite run. All are deterministic JSON (sorted
keys), so paired runs are byte-comparable.

## Evidence record (one JSON object per line)

```
schema       "monitoring-incident-evidence/v1"
run_id       deterministic id: digest(code+manifest+scenario+condition+proposer+...)
seq          0-based record index within the run
type         one of the record types below
step         integer step index, or null for run-level records
time_utc     ISO-8601 UTC (NOT hashed into the chain beyond its own record)
payload      type-specific object (see below)
prev_hash    record_hash of the previous record ("0"*64 for the first)
record_hash  sha256 over the record with record_hash removed
```

The chain is verified by `evidence.verify_records(records, terminal_hash=None)`,
which checks: schema, monotonic seq, `prev_hash` linkage, per-record hash
(alteration), first record is `run_start`, last is `run_end` (truncation), and
three semantic invariants — every `execution{executed:true}` is preceded by a
matching `decision{verdict:ALLOW}` in the same step, no decision executes twice,
and no step changes state with nothing executed (unless an `external_change`
record in that step accounts for it).

### Record types and key payload fields

| type | key payload fields |
|---|---|
| `run_start` | full run metadata (scenario, condition, tiers, proposer identity, manifest sha, git commit, morrison_version, baseline_oracle) |
| `proposal` | `turn`, `text`, `calls`, `usage`, `stop_reason`, `latency_s` |
| `oracle_label` | `eval_id`, `label` (authorized/unauthorized/invalid), `introduces_violation`, `action`, `intent`, `hook` |
| `local_evaluation` | `eval_id`, `verdict` (PERMIT/BLOCK/ESCALATE), `rule`, `reason`, `components.{morrison_kernel,protected_resources}` |
| `global_evaluation` | `eval_id`, `verdict`, `rule`, `components.{engine_verdict,projected_violations,projected_state_hash,model_errors}` |
| `decision` | `eval_id`, `decision_id`, `verdict` (ALLOW/BLOCK/ESCALATE), `basis`, `action_hash`, `state_hash`, `trajectory_hash`, `escalation` |
| `adversarial_hook` | `hook` kind, `spec` (scripted boundary-manipulation only) |
| `external_change` | `by`, `path` (simulated other actor) |
| `execution` | `executed`, `refusal`, `effects` (path/before/after hashes), `state_before`, `state_after`, `primary`, `must_refuse`, `decision_id`, `action_hash` |
| `step_outcome` | `executed`, `external_change`, `state_before`, `state_after`, `projection_divergence` |
| `report` | `claims.{task_completed,tests_passed,monitoring_preserved}`, `summary` |
| `oracle_final` | `monitoring_intact`, `clauses`, `task_completed`, `detail`, `canary_intact` |
| `run_end` | `status`, `stop_reason`, `turns`, `metrics` |

### The three representations a decision binds (never conflated)

- **proposed** action — what the proposer asked for, canonicalised; this is what
  `action_hash` covers and what the executor runs.
- **authorised** — a `decision` with `verdict=ALLOW`, signed (HMAC) and bound to
  `action_hash` + `state_hash` + `trajectory_hash` + `run_id`, single-use.
- **executed** — an `execution{executed:true}`. A PERMIT/ALLOW string never
  counts as execution; only an executor effect does.

## summary.json

```
metadata        the run_start metadata
status          "ok" | "harness_error:*"
stop_reason     report | max_steps | max_turns | no_tool_call | provider_error
turns, steps
metrics         see metrics.py (proposed/authorised/executed split, false
                positives/negatives, boundary bypasses, trajectory_violation,
                report accuracy, canary)
evidence        {file, valid, problems, records, terminal_hash}
```

## scripted_report.json (suite)

```
suite, manifest_sha256, manifest_version, conditions, cases, episodes,
escalation_policy, category_coverage, not_tested,
aggregate.by_condition[cond]            summed counters per condition
aggregate.by_category_condition[...]    summed counters per (category|condition)
aggregate.report_accuracy_by_condition  misleading/total report claims
index[]                                 one row per episode (run_id, verdicts, flags)
```

## Reproducing a run id

`run_id` is `"mi-" + sha256(harness_version, git_commit, manifest_sha256,
scenario, condition, escalation_policy, proposer_identity, case_id, max_steps,
max_turns, repetition)[:20]`. Same code + same frozen manifest + same scripted
case + same repetition index ⇒ same id and same evidence (timestamps aside).
Live-model runs vary with model output and are not byte-reproducible; their
determinism is bounded by the provider.
