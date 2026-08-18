# Codex Prompt — Dynamical + SCM Causal Analysis Overlay

Paste the prompt below into Codex while working inside the existing `davarntrades/Morrison-Runtime-Governance` repository.

---

## Prompt

You are working inside the existing **Morrison Runtime Governance** codebase.

The repository already contains the Morrison governance kernel, Ω rules, policy hierarchy, executable-trajectory evaluation, reachability analysis, source→sink taint, admissibility, evidence generation, runtime evaluation infrastructure, and existing allow/block/escalate semantics.

**Do not rebuild any of that.**

**Do not modify Morrison's governance kernel, Ω semantics, policy hierarchy, execution semantics, or existing canonical verdicts to support this feature.**

Your task is to implement an **additive, non-authoritative Dynamical + Structural Causal Model (SCM) analysis overlay**.

Read `DYNAMICAL_SCM_CAUSAL_PROTOTYPE.md` first and treat it as the design specification.

### Objective

After Morrison has already evaluated a real trajectory, consume the existing governed trajectory/evidence and answer bounded causal questions such as:

- Why was the forbidden state reachable?
- Which causal variables contributed to that reachability?
- Which intervention would have prevented the forbidden transition?
- Would Ω still have been reachable if a permission, safeguard, monitoring state, approval requirement, trust boundary, capability, or other causal parent had changed?

The causal overlay must be able to represent both:

1. **Dynamical structure** — state, trajectory, reachability, constraints, transition geometry, taint, capability state, policy/admissibility state.
2. **SCM structure** — explicit causal parents, intervenable variables, `do(X=x')` interventions, factual/counterfactual outcomes, and contribution traces.

The prototype must be **shadow/post-decision by default**. Failure, timeout, or slowness in the causal overlay must never change or delay Morrison's canonical ALLOW/BLOCK/ESCALATE result.

### Required package

Create an additive package similar to:

```text
runtime_eval/
  causal_overlay/
    __init__.py
    models.py
    variable_extractor.py
    causal_templates.py
    intervention_engine.py
    counterfactual_replay.py
    contribution_trace.py
    latency.py
    report.py
```

Add focused tests under `runtime_eval/tests/` or the repository's existing test structure. Reuse existing conventions rather than forcing this exact path if the current codebase has a better established layout.

### v0.1 causal graphs

Do **not** use an LLM to invent causal graphs in v0.1.

Use deterministic, explicit, scenario-specific causal templates keyed to existing Morrison incident/Ω categories.

Start with:

1. secret / credential exfiltration;
2. unauthorized financial transfer.

Then, only if the first two are correct and tested, add privilege escalation and delayed multi-step exfiltration.

Every extracted causal variable and edge must carry provenance back to canonical Morrison evidence.

### Data model

Implement immutable equivalents of:

- `CausalVariable`
- `CausalEdge`
- `CausalIntervention`
- `CounterfactualResult`
- `CausalAnalysisReport`

The report should contain at minimum:

```text
trajectory_id
causal_variables
causal_edges
interventions
necessary_contributors
sufficient_interventions
resolution_score
source_evidence_hash
```

Do not mutate canonical evidence. Emit a separate causal-analysis artifact that references canonical evidence by hash/id.

### Intervention engine

For v0.1, generate only bounded **one-variable interventions** on variables explicitly marked intervenable.

Examples:

```text
external_egress_enabled: true -> false
permission_transfer: true -> false
approval_required: false -> true
safeguard_active: false -> true
```

Represent these conceptually as:

```text
do(X = x')
```

For each intervention:

1. copy the factual governed trajectory/context;
2. apply exactly one intervention;
3. recompute the affected derived state;
4. replay the modified case through the **existing Morrison evaluation path** without modifying that path;
5. compare factual and counterfactual verdicts, Ω reachability, first blocked step, risk, and policy attribution;
6. record whether the intervention prevented the forbidden trajectory.

Full replay through the existing Morrison evaluator is the **correctness baseline**.

### Non-interference invariant

The following must always hold:

```text
canonical Morrison verdict without overlay
==
canonical Morrison verdict with overlay enabled
```

The overlay is explanatory/analytical in v0.1, never authoritative.

If the overlay throws an exception, times out, produces no graph, or cannot answer a counterfactual, Morrison's original result remains unchanged.

### Contribution trace

For each intervention record, where available:

- verdict changed: yes/no;
- Ω reachability changed: yes/no;
- reachable-state-set delta;
- risk delta;
- first blocked step change;
- constraint/admissibility margin delta;
- policy layer responsible;
- canonical evidence refs.

### Latency — mandatory acceptance criterion

Latency is part of the feature, not a later optimization.

Instrument and report stage-level timing for:

| Stage | Metric |
|---|---|
| Canonical Morrison evaluation | ms |
| Causal-variable extraction | ms |
| SCM template construction | ms |
| Intervention generation | ms |
| Each counterfactual replay | ms |
| Sequential replay total | ms |
| Parallel replay wall time | ms |
| Contribution-trace construction | ms |
| Evidence sealing / serialization | ms |
| Total causal-overlay latency | ms |
| Synchronous end-to-end latency | ms |
| Async canonical-governance latency | ms |

Benchmark at least these intervention counts:

```text
1, 2, 4, 8, 16
```

Run sufficient repetitions to report **p50 / p95 / p99** where practical.

Implement a bounded parallel executor for independent one-variable interventions and compare:

```text
sequential replay
vs
parallel replay
```

Parallel and sequential modes must return identical causal results.

Do not parallelize in a way that mutates shared governance state or breaks determinism.

### Deployment classification

Based on measured latency, classify the prototype into three operating modes:

1. **Fast inline causal explanation** — top 1–2 highest-value interventions.
2. **Bounded interactive causal analysis** — approximately 4–8 concurrent interventions.
3. **Full forensic analysis** — larger intervention sets, multi-variable interventions, minimal-cut-set search, representation-ablation work; asynchronous/post-decision by default.

Do not invent latency targets before measurement. Report the actual observed numbers and recommend the mode from evidence.

### Incremental replay experiment

Only after full replay is correct and tested, investigate whether SCM dependency structure can avoid recomputing unaffected descendants.

Compare:

```text
full counterfactual replay
vs
incremental descendant-only replay
```

Incremental replay is acceptable only if it produces identical:

- counterfactual verdict;
- Ω reachability;
- relevant evidence attribution;
- preventive-intervention result.

If equivalence cannot be proven, keep full replay as the implementation.

### Tests required

At minimum add tests equivalent to:

```text
test_causal_overlay_does_not_change_verdict
test_secret_exfiltration_disable_egress_prevents_omega
test_secret_exfiltration_remove_source_permission_prevents_omega
test_transfer_require_approval_changes_reachability
test_irrelevant_intervention_does_not_change_verdict
test_causal_report_is_deterministic
test_causal_report_links_to_source_evidence_hash
test_overlay_failure_is_non_authoritative
test_shadow_overlay_does_not_block_canonical_response
test_parallel_replay_matches_sequential_results
test_latency_metrics_are_emitted
```

If incremental replay is implemented, also add:

```text
test_incremental_replay_matches_full_replay
```

### Benchmark report

Produce a checked-in Markdown benchmark report containing:

- environment / hardware / Python version;
- exact scenario set;
- number of repetitions;
- intervention counts;
- stage-level p50/p95/p99 latency;
- sequential vs parallel wall-clock comparison;
- any throughput numbers that are meaningful;
- whether overlay execution changed canonical governance latency;
- whether 1–2 interventions are viable inline;
- whether 4–8 are viable interactively;
- when analysis should remain asynchronous;
- any determinism or equivalence failures;
- explicit limitations.

### Acceptance criteria

Do not call the prototype complete until all of these hold:

1. Existing Morrison governance tests still pass.
2. Existing canonical verdicts are unchanged.
3. Causal variables are derived deterministically from real existing evidence.
4. Secret-exfiltration and unauthorized-transfer causal templates work end-to-end.
5. At least four bounded interventions can be replayed on a blocked case.
6. At least one meaningful intervention demonstrably makes Ω unreachable in the appropriate known case.
7. Irrelevant interventions do not falsely appear preventive.
8. Causal reports are deterministic and provenance-linked.
9. Overlay failure cannot alter a canonical verdict.
10. Shadow mode introduces no blocking dependency into the canonical decision path.
11. Latency is measured per stage and across 1/2/4/8/16 interventions.
12. Sequential and parallel counterfactual results are identical.
13. A benchmark report is checked in.
14. No optimization weakens Morrison checks, skips Ω evaluation, or changes evidence semantics.

### Final output

When finished, report:

- files added/changed;
- architecture used;
- causal variables/templates implemented;
- example factual and counterfactual result;
- tests run and pass/fail counts;
- canonical-verdict invariance result;
- latency table;
- sequential vs parallel speedup;
- recommended deployment mode;
- blockers or unresolved assumptions.

Do not hide failures. If a causal assumption is unsupported by existing evidence, record it explicitly rather than inventing a value.

---

## Design reference

See [`DYNAMICAL_SCM_CAUSAL_PROTOTYPE.md`](DYNAMICAL_SCM_CAUSAL_PROTOTYPE.md) for the research rationale, hybrid representation, UI concept, evidence schema, and longer-term direction.
