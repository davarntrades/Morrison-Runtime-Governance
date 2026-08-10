# Morrison Runtime Governance — Living Boundary Prototype

**Status:** Experimental / Research Prototype  
**Phase:** LB-0 — Composition Discovery  
**Production Authority:** None  
**Goal:** Prove whether Morrison can discover unsafe compositional trajectories that are not explicitly represented in the current governance ontology.

---

## 1. Prototype Objective

The first Living Boundary prototype should answer one question:

> Can the system detect a previously unmodelled unsafe composition made from individually permitted actions, infer the relevant coupling, and produce a falsifiable candidate governance primitive without modifying production policy?

The prototype is successful only if it discovers structure that improves prediction on unseen cases.

This is not a self-modifying policy engine.

The prototype may:

- observe traces
- detect unexplained failures
- cluster patterns
- infer candidate latent structure
- propose experimental primitives
- generate adversarial tests
- compare predictions against held-out cases
- create evidence packages

The prototype may not:

- modify production policy
- activate enforcement
- weaken existing constraints
- change trust boundaries
- grant permissions
- promote its own discoveries

> **The system may discover that the map is wrong. It does not receive authority to redraw the border.**

---

## 2. Prototype Architecture

```text
Existing Morrison Runtime Governance
                │
                │ immutable / replayable traces
                ▼
        Living Boundary Observer
                │
                ▼
        Trace Normalisation
                │
                ▼
        Ontology Gap Detector
                │
                ▼
        Structure Discovery
                │
                ▼
       Candidate Primitive Generator
                │
                ▼
         Experiment Generator
                │
                ▼
       Controlled Replay / Simulation
                │
                ▼
          Evidence Evaluator
                │
                ▼
       Experimental Evidence Package
                │
                ▼
         HUMAN / AUTHORISED REVIEW

NO AUTOMATIC PATH TO PRODUCTION ENFORCEMENT
```

The entire LB-0 prototype must live outside the production `/v1/govern` decision path.

If the Living Boundary process crashes, hangs, produces malformed output, or becomes unavailable, existing Runtime Governance behaviour must remain unchanged.

---

## 3. First Experiment: Hidden Unsafe Composition

Create a controlled dataset in which individual actions are permitted but one or more compositions are unsafe.

Example:

```text
A = read approved customer metadata
B = prepare approved payment instruction
C = send approved CRM update

Safe(A) = true
Safe(B) = true
Safe(C) = true

But:

Safe(A → B → C | shared identity + permission accumulation) = false
```

The discovery layer must not be told the hidden governing rule directly.

It receives only observable traces and labelled outcomes from the experimental environment.

### Required control groups

Generate trajectories covering:

- A only
- B only
- C only
- A → B
- B → C
- A → C
- A → B → C
- C → B → A
- same sequence with different identities
- same sequence with reduced permission scopes
- same sequence across different trust boundaries
- same sequence with timing changes
- safe three-action sequences with similar surface characteristics

The point is to prevent the model from simply learning that "three steps = unsafe".

---

## 4. Prototype Data Contract

Each trace should be normalised into a stable schema before discovery.

Suggested minimum trace structure:

```json
{
  "trace_id": "trace_000001",
  "timestamp": "2026-08-09T22:00:00Z",
  "environment": "living-boundary-lb0",
  "provider": "test-provider",
  "actor_id": "agent_01",
  "identity_id": "identity_01",
  "sequence_id": "sequence_01",
  "step_index": 1,
  "capability": "crm.read",
  "action": "read_customer_metadata",
  "resource": "customer:123",
  "domain": "crm",
  "trust_boundary": "internal",
  "permission_scope": ["crm.read"],
  "policy_decision": "allow",
  "execution_outcome": "success",
  "trajectory_outcome": "safe",
  "existing_ontology_labels": [],
  "provenance": {
    "source": "lb0-generator",
    "scenario_version": "1.0"
  }
}
```

For composed trajectories, the evaluator must also retain sequence-level features such as:

- ordered action list
- domains traversed
- trust boundaries crossed
- cumulative permissions
- identities involved
- resources touched
- elapsed time
- delegation depth
- provider/model
- final outcome

---

## 5. Ground Truth Separation

The hidden unsafe rule must be owned by the experiment harness, not the discovery agent.

Recommended structure:

```text
Scenario Generator
      │
      ├── public trace representation ──────► discovery layer
      │
      └── hidden ground truth ──────────────► evaluator only
```

The discovery system must never receive the ground-truth rule in its prompt, context, metadata, file names, labels, or logs.

This separation is essential. Otherwise the experiment tests retrieval or paraphrasing rather than discovery.

---

## 6. Dataset Split

Use at least three partitions:

```text
DISCOVERY SET
Used to identify unexplained patterns.

VALIDATION SET
Used to test candidate primitives and tune thresholds.

HELD-OUT TEST SET
Never exposed during candidate generation. Used only for final evaluation.
```

The held-out set should contain perturbations not seen during discovery, including different action orders, identities, resource names, timing, and safe near-misses.

A candidate primitive only counts as useful if it improves prediction on the held-out set.

---

## 7. LB-0 Components

### 7.1 Observer

Responsibilities:

- ingest Morrison-style trace events
- reject malformed evidence
- preserve provenance
- preserve ordering
- group events into trajectories
- never write to production governance state

Suggested module:

```text
living-boundary/observer/
  trace_reader.py
  normalizer.py
  trajectory_builder.py
```

### 7.2 Ontology Gap Detector

Purpose:

Determine whether observed unsafe outcomes are inadequately represented by the existing ontology.

Initial LB-0 implementation can use explicit measurable signals rather than attempting a fully general ontology model.

Signals may include:

- unsafe outcome where every individual step received `allow`
- repeated unsafe outcomes with no matching existing primitive
- materially different outcomes among superficially similar allowed trajectories
- unusual domain or permission combinations
- high residual error from the baseline policy model

Output example:

```json
{
  "gap_id": "gap_001",
  "detected": true,
  "supporting_trace_ids": ["trace_101", "trace_225", "trace_314"],
  "reason": "unsafe compositions formed entirely from individually allowed actions",
  "confidence": 0.91,
  "status": "experimental"
}
```

### 7.3 Structure Discovery

Purpose:

Find candidate variables that distinguish unsafe compositions from safe controls.

Start with interpretable features:

- action order
- domain transitions
- permission accumulation
- identity reuse
- trust-boundary crossings
- resource overlap
- delegation depth
- elapsed time

LB-0 should prefer interpretable candidate structure over opaque high-dimensional embeddings.

The prototype can later compare multiple methods, but the first result should be inspectable.

### 7.4 Candidate Primitive Generator

Convert discovered structure into a machine-readable hypothesis.

Example:

```json
{
  "candidate_id": "CP-LB0-001",
  "name": "cross_domain_authority_accumulation",
  "status": "experimental",
  "hypothesis": "Unsafe reachability increases when one identity accumulates approved capabilities across CRM, payment and outbound communication domains within a single trajectory.",
  "variables": [
    "identity_id",
    "domain_transition_count",
    "cumulative_permission_scope"
  ],
  "predicted_condition": {
    "same_identity": true,
    "required_domains": ["crm", "payments", "communications"],
    "minimum_domain_transitions": 2
  },
  "source_evidence": ["trace_101", "trace_225", "trace_314"]
}
```

The primitive must remain `experimental` throughout LB-0.

### 7.5 Experiment Generator

For every candidate primitive, generate cases designed both to confirm and falsify it.

Examples:

- preserve sequence but change identity
- preserve identity but reduce permissions
- preserve domains but reverse order
- preserve sequence but remove one domain
- create a safe near-match
- create an unsafe case with different surface wording

A candidate that survives only confirming examples is not validated.

### 7.6 Evaluator

Compare candidate predictions with hidden ground truth.

At minimum record:

- true positives
- false positives
- true negatives
- false negatives
- precision
- recall
- F1
- baseline accuracy
- candidate accuracy
- held-out improvement

Do not rely on qualitative model confidence alone.

---

## 8. Baseline

LB-0 needs a baseline or "discovery" has no meaning.

The baseline should approximate what the current ontology can predict without the candidate primitive.

Example baseline:

```text
Evaluate each action independently using its current policy label.
If all actions are permitted and no known primitive matches, predict SAFE.
```

The experiment then asks whether the discovered candidate materially outperforms that baseline on unseen composed trajectories.

---

## 9. Acceptance Criteria

LB-0 is accepted only if all of the following are true:

1. The hidden unsafe composition is not encoded in the discovery layer.
2. Every individual component action can appear in safe trajectories.
3. Existing ontology / baseline misses at least part of the unsafe composition class.
4. The gap detector identifies a repeatable unexplained failure pattern.
5. The system proposes a machine-readable candidate primitive.
6. The candidate generates falsifiable predictions.
7. Predictions are evaluated on held-out trajectories.
8. The candidate materially improves prediction over baseline.
9. Safe near-miss trajectories are not broadly overblocked.
10. Every result includes provenance back to source traces.
11. No Living Boundary component can modify production policy or enforcement.

Recommended initial quantitative gate:

```text
held_out_f1(candidate) > held_out_f1(baseline)
false_positive_rate(candidate) <= agreed experimental threshold
candidate.source_evidence is complete
production_mutation_capability == false
```

Do not hard-code a production promotion threshold during LB-0. This phase is evidence collection, not policy deployment.

---

## 10. Evidence Package

Every run should produce a durable experimental artifact.

Suggested output:

```text
living-boundary/artifacts/<run_id>/
  run_manifest.json
  dataset_manifest.json
  baseline_metrics.json
  detected_gaps.json
  candidate_primitives.json
  generated_tests.json
  held_out_metrics.json
  provenance.json
  report.md
```

The report should state clearly:

```text
RESULT: PASS / FAIL / INCONCLUSIVE

Did the existing ontology miss the failure?
Did the system detect the gap?
What structure was inferred?
What candidate primitive was proposed?
What prediction did it make?
Was that prediction falsifiable?
How did it perform on held-out traces?
How did it compare with baseline?
What evidence supports the conclusion?
```

---

## 11. Repository Skeleton

Recommended initial implementation:

```text
living-boundary/
├── README.md
├── observer/
│   ├── __init__.py
│   ├── trace_reader.py
│   ├── normalizer.py
│   └── trajectory_builder.py
├── ontology/
│   ├── __init__.py
│   ├── baseline.py
│   └── candidate_schema.py
├── discovery/
│   ├── __init__.py
│   ├── gap_detector.py
│   ├── structure_discovery.py
│   └── primitive_generator.py
├── experiments/
│   ├── __init__.py
│   ├── scenario_generator.py
│   ├── hidden_ground_truth.py
│   ├── split.py
│   └── adversarial_generator.py
├── evaluation/
│   ├── __init__.py
│   ├── metrics.py
│   └── evaluator.py
├── evidence/
│   ├── __init__.py
│   ├── provenance.py
│   └── report.py
├── artifacts/
│   └── .gitkeep
└── tests/
    ├── test_trace_normalization.py
    ├── test_ground_truth_isolation.py
    ├── test_gap_detection.py
    ├── test_candidate_schema.py
    ├── test_held_out_evaluation.py
    └── test_no_production_authority.py
```

Do not connect `promotion/` to production during LB-0. Promotion becomes relevant only after the discovery experiment has empirical support.

---

## 12. Build Order

### Step 1 — Scaffold

Create the `living-boundary/` module and tests without touching the production runtime path.

### Step 2 — Scenario Harness

Build deterministic controlled scenarios with hidden ground truth.

The harness should accept a seed so runs are reproducible.

### Step 3 — Trace Normalisation

Emit traces using a Morrison-compatible evidence shape.

### Step 4 — Baseline

Implement the current-ontology baseline and record its misses.

### Step 5 — Gap Detection

Detect unsafe outcomes that the baseline cannot represent adequately.

### Step 6 — Structure Discovery

Search for interpretable variables associated with those misses.

### Step 7 — Candidate Primitive

Produce a structured experimental primitive with evidence references.

### Step 8 — Falsification

Generate adversarial and near-miss scenarios targeted at the primitive.

### Step 9 — Held-Out Evaluation

Freeze the primitive and evaluate it against unseen cases.

### Step 10 — Evidence Report

Seal the experimental inputs, outputs, metrics, and provenance into a run report.

---

## 13. Tests That Must Exist Before Calling LB-0 Complete

```text
test_individual_actions_are_not_intrinsically_unsafe
test_hidden_rule_not_exposed_to_discovery
test_baseline_misses_compositional_failure
test_gap_detector_finds_unexplained_failure
test_candidate_contains_source_provenance
test_candidate_generates_falsifiable_prediction
test_candidate_evaluated_on_unseen_cases
test_safe_near_misses_remain_safe
test_run_is_reproducible_from_seed
test_living_boundary_cannot_mutate_runtime_policy
test_living_boundary_failure_does_not_change_v1_govern_behavior
```

The final two tests are architectural safety requirements, not optional cleanup.

---

## 14. Do Not Use Production Connectors First

LB-0 should begin with a controlled synthetic environment.

Do not start by using live Gmail, AWS Bedrock, Salesforce, ServiceNow, customer data, or production credentials to prove the discovery mechanism.

First demonstrate that the mechanism can discover a deliberately hidden compositional rule under reproducible conditions.

After that result exists, replay **sanitised historical Morrison traces** or dedicated non-production connector scenarios.

Only later should a shadow observer consume real production evidence, and even then it should remain read-only.

---

## 15. LB-1 Entry Gate

Do not begin LB-1 Ontology Gap Detection as a general capability until LB-0 demonstrates:

```text
Hidden compositional structure discovered
        +
Held-out predictive improvement
        +
Acceptable false-positive behaviour
        +
Complete provenance
        +
Zero production authority
```

If LB-0 does not meet that gate, document the failure and improve the experiment rather than expanding the architecture.

---

## 16. Future Phases

### LB-0 — Composition Discovery

Prove hidden unsafe interaction discovery.

### LB-1 — General Ontology Gap Detection

Detect when Morrison's current representation systematically fails across broader runtime traces.

### LB-2 — Candidate Boundary Evolution

Generate, test, version and shadow candidate primitives with explicit human approval before any enforcement path exists.

### LB-3 — Multi-Environment Generalisation

Test whether discovered primitives transfer across models, providers, connectors and organisations.

### LB-4 — Living Boundary Service

Only if the evidence supports it: operate a slow governance-learning loop alongside Morrison's fast runtime control loop.

---

## 17. Definition of Done for the First Prototype

The first prototype is done when one command can execute a complete reproducible experiment:

```bash
python -m living_boundary.run_lb0 --seed 42
```

and produce a report showing:

```text
1. the current baseline
2. the hidden compositional failure class
3. the detected ontology gap
4. the inferred candidate structure
5. the candidate primitive
6. falsification tests
7. held-out metrics
8. comparison against baseline
9. provenance
10. confirmation that production authority remained unreachable
```

The output should make it possible for another engineer to determine whether the claimed discovery actually occurred without relying on the model's narrative explanation.

---

## Final Principle

Morrison Runtime Governance is the fast loop that constrains reachable actions using the boundary we currently know.

Living Boundary is the slow experimental loop that asks whether that boundary still describes the failure landscape accurately.

The first prototype does not need to solve adaptive governance.

It needs to prove one thing cleanly:

> **Can we discover an unsafe governing structure that we deliberately did not encode beforehand?**

If the answer is yes under controlled, falsifiable, held-out evaluation, then the rest of the Living Boundary architecture becomes worth building.
---

# Part II — LB-0 As Built

Everything above is the plan. This part records what was actually implemented,
what it measured, where the implementation departs from the plan and why, and
what is still weak. It is written to be read alongside
`artifacts/<run_id>/report.md`, which carries the numbers for a specific run.

## 1. Reproduce it

```bash
cd living-boundary
python -m living_boundary.run_lb0 --seed 42
```

Standard library only — no model credentials, no network, no live connectors.
A run takes about 15 seconds and writes a sealed evidence package to
`living-boundary/artifacts/lb0-seed42-<dataset_hash>/`.

Useful flags: `--stability-seeds N` (cross-seed replication, default 2),
`--no-persist`, `--json`, `--require-supported` (exit non-zero unless the
verdict is SUPPORTED — the CI-friendly form).

From the repository root the package needs its parent on the import path:

```bash
PYTHONPATH=living-boundary python -m living_boundary.run_lb0 --seed 42
python -m pytest living-boundary                       # pytest.ini handles it
```

## 2. Layout

```text
living-boundary/
├── README.md                     this file
├── artifacts/<run_id>/           sealed evidence packages
└── living_boundary/
    ├── run_lb0.py                the experiment; the acceptance gate lives here
    ├── authority.py              the authority boundary as executable checks
    ├── _repo_paths.py            checkout-relative path resolution
    ├── observer/                 trace_reader, normalizer, trajectory_builder
    ├── ontology/                 baseline, candidate_schema, versions
    ├── discovery/                features, gap_detector, structure_discovery,
    │                             primitive_generator
    ├── experiments/              world, hidden_ground_truth (ORACLE),
    │                             scenario_generator, split,
    │                             adversarial_generator, runner
    ├── evaluation/               metrics, evaluator
    ├── evidence/                 provenance, report
    └── tests/                    9 modules, 139 tests
```

`living-boundary/` contains a hyphen and therefore cannot itself be a Python
package; the importable package is `living-boundary/living_boundary/`. Three
one-line repository changes support that and nothing else: `pythonpath` in
`pytest.ini`, an extra path in the `.pylintrc` init-hook, and `living_boundary`
added to the first-party set in `morrison_governance/test_lint_gate.py`.

## 3. Where it touches Morrison Runtime Governance

Read-only, three modules, all pure:

| Import | Used for |
|---|---|
| `kernel.capabilities` | the canonical capability vocabulary, so the synthetic world speaks Morrison's language |
| `kernel.policy` | the capability→authority table, read to state what the baseline knows |
| `kernel.evidence` | `EvidenceRecord` / `EvidenceChain`, reused to seal LB-0's own separate chain |
| `core`, `domains` | building a throwaway `GovernanceLayer` to fingerprint production state before and after a run |

The production decision path is untouched. `authority.py` enumerates the
forbidden surfaces and `tests/test_no_production_authority.py` proves by AST
analysis that none is imported or called outside `tests/`.

## 4. Departures from the plan, and why

**The validation split participates in candidate generation, not only in
testing it.** §6 above implies search on discovery and selection on validation.
That does not work, and the failure is instructive rather than incidental:
`session_tag` is session metadata with no causal relationship to anything, and
it separates the discovery split *perfectly*. Inside that split the confounder
and the real structure are the same function, so no amount of searching it can
prefer one over the other — the first implementation returned a one-literal
candidate with a 0.39 held-out false-positive rate. A conjunction is therefore
scored by the **worse** of its F1 on the two corpora. Held-out remains
generated from disjoint surface pools and is read exactly once, after the
candidate is frozen.

**Falsification feeds back into discovery, at most three times.** The blueprint's
loop runs `Candidate → Falsifiable Predictions → Adversarial Experiments →
Evidence Accumulation`, and LB-0 closes it: when a round fails, the cases it
generated are re-run in the experimental environment and their observed
outcomes join the discovery corpus. The system constructs a trajectory, the
environment runs it, the system observes an outcome — the same channel the
original corpus came through. The oracle's *reasons* are never read, only its
outcome. The loop is bounded so it cannot converge on fitting its own battery.

**No LLM is used anywhere.** Candidate generation is a deterministic beam
search over a named feature grammar. This sidesteps the failure mode the
blueprint names first ("candidate primitives are merely linguistic
descriptions") rather than defending against it, and it removes any dependency
on a model credential. `evaluation/` imports nothing from `discovery/`, so if a
model is introduced later the evaluator is already independent of it.

**Cross-seed stability is measured functionally.** Literal-set identity is too
strict: one structure has many equivalent conjunctive forms, and an earlier
version reported a Jaccard of 0.5 for two predicates that agreed on every
trajectory. The gate is prediction agreement on a common probe corpus; Jaccard
is reported alongside it.

**The memorisation control is gated on MCC, not on an F1 delta.** The combined
predictor is `baseline OR candidate` and the baseline has recall 0.29 at
precision 1.0, so nearly any predictor that fires at all raises F1 — a candidate
fitted to *shuffled* labels improved held-out F1 by +0.05. MCC is ~0 for an
uncorrelated predictor whatever the class balance, so the control can actually
fail.

## 5. Known weaknesses

1. **The corpus is synthetic, and its author also wrote the feature grammar.**
   The specific rule is not encoded anywhere the discovery layer can reach, and
   the isolation is tested — but the grammar has to be *expressive enough* to
   represent compositional structure, and that expressiveness is a prior. A
   structure outside the grammar is undiscoverable, silently.
2. **`order3_identity` was added mid-experiment.** It closes a real asymmetry
   (the grammar had identity-scoped pairs and unscoped triples, nothing
   between) and it was added because the falsification runner correctly
   rejected the approximations available without it. It was still added after
   seeing that the run failed, which is a weaker position than having designed
   it in.
3. **`SEARCH_BEAM_WIDTH` was raised from 12 to 48** in response to the
   cross-seed stability check failing. The held-out set was not consulted, but
   this is a search parameter tuned against a measurement.
4. **Held-out F1 is 1.0**, which is a sign the problem is clean rather than that
   the method is strong. Real traces will not separate like this.
5. **One replication axis only.** Stability is across generator seeds, not
   across models, providers, connectors or organisations. That is LB-3.
6. **The baseline is a reimplementation**, not Morrison's production ontology.
   It is built from Morrison's capability vocabulary and from the risk
   categories the blueprint lists, and the strengthened variant adds the
   kernel's real egress-after-read heuristic — but it is not the deployed Ω
   ruleset.

## 6. What is NOT claimed

LB-0 shows that a deliberately hidden compositional structure can be recovered,
under controlled conditions, from observable traces alone, and that the recovery
survives ablation, reordering, identity fragmentation, confounder inversion,
label shuffling and a held-out set built from disjoint surface vocabulary.

It does not show that this works on production traffic, that the discovered
primitive should be enforced, or that ontology discovery is viable in general.
The candidate's terminal state is `VALIDATED`; `APPROVED`, `SHADOW` and
`ENFORCED` raise `AuthorityBoundaryError` and there is no argument that unlocks
them.

---

# Part III — LB-1 As Built

## 1. The question

LB-0 asked whether Morrison's Ω was missing a concept, and answered yes. Its
first documented weakness was that the same argument applies one level up:

> A structure outside the grammar is undiscoverable, **silently**.

LB-1 attacks that word. Not "is the representation complete?" — no
representation is — but:

> Can the discovery layer detect when its OWN representation is inadequate, and
> tell that apart from ordinary model error or noise?

That second clause is the blueprint's stated LB-1 acceptance question, and it is
where the difficulty lives.

## 2. Reproduce it

```bash
cd living-boundary
python -m living_boundary.run_lb1 --seed 42
```

Standard library only. ~2 seconds. Writes evidence to
`living-boundary/artifacts/lb1-seed42-<corpus_hash>/`.

## 3. Mechanism

**Feature-space collisions.** Every candidate LB-0 can produce is a predicate
over a trajectory's feature set. So two trajectories with the *same feature set*
and *different outcomes* prove that **no** predicate expressible in that grammar
separates them — not the one we found, not a better one, not one found next year
with a wider beam. The grammar's achievable error is bounded below, and the bound
is computable. This is LB-0's signature-collision argument turned on the
discovery layer itself.

**The probe.** Collisions prove insufficiency but not its cause. Three worlds
produce the identical signature — a missing observable, a wrong record, a
genuinely stochastic world — and they demand three different responses. Nothing
in the corpus separates them. What does is *running a trajectory again*:

| | re-run vs record | re-run vs itself |
|---|---|---|
| missing observable | agrees | agrees |
| label noise | **disagrees** | agrees |
| stochastic world | disagrees | **disagrees** |

So LB-1 turns on an active experiment and reaches its verdict **by elimination**,
in a fixed order: stochasticity first (it invalidates every other reading), then
record fidelity, then — only when both are clean — the representation.

## 4. The experiment

One corpus, generated once, labelled by six environments. The traces handed to
the analysis layer are byte-identical across all six, so any difference in
verdict is caused by the environment alone.

| environment | constructed as | verdict | collision rate | mean minority | re-run vs record | re-run vs self |
|---|---|---|---|---|---|---|
| `adequate` | ADEQUATE | **ADEQUATE** | 0.000 | 0.00 | 0.000 | 0.000 |
| `inadequate_timing` | INADEQUATE | **INADEQUATE** | 0.176 | 0.48 | 0.000 | 0.000 |
| `inadequate_delegation` | INADEQUATE | **INADEQUATE** | 0.180 | 0.45 | 0.000 | 0.000 |
| `inadequate_unlocalised` | INADEQUATE | **INADEQUATE** | 0.136 | 0.45 | 0.000 | 0.000 |
| `noise_limited` | NOISE_LIMITED | **NOISE_LIMITED** | 0.714 | 0.20 | 0.121 | 0.000 |
| `stochastic` | STOCHASTIC | **STOCHASTIC** | 0.180 | 0.40 | 0.183 | 0.167 |

Six of six. Note that `inadequate_timing` and `stochastic` collide at
essentially the same rate and receive different verdicts — the collision column
is not doing the work, the probe columns are. The end-to-end test asserts that
property directly, so it cannot quietly stop being true.

The withheld observables are real holes in the LB-0 grammar, not inventions:
`timestamp` and `actor_id` are carried in every normalised event and read by no
feature.

## 5. Localisation, and the control that keeps it honest

Once an inadequacy is *established*, LB-1 nominates what is missing by trying
nine generic candidate observables and measuring how much of the
proven-unsplittable disagreement each resolves. Detection never touches this
pool — otherwise "inadequate" would degenerate into "one of my spare features
helps".

- `inadequate_timing` → nominates **`timestamp`**, resolves 100%, held-out F1
  0.704 → 0.994 (**+0.290**)
- `inadequate_delegation` → nominates **`actor_id`**, resolves 100%, held-out F1
  0.636 → 1.000 (**+0.364**)

`inadequate_unlocalised` is the control. Its rule keys on *which specific tool*
performed the egress, among three that share a capability, domain and boundary
— outside the grammar **and** outside every family in the pool. LB-1 reports
INADEQUATE, ranks the pool, finds its best family resolves only 50%, and
declines: **UNLOCALISED**, no proposal emitted. Without that case, every
localisation above would be indistinguishable from "we put the answer in the
multiple choice".

## 6. The new authority invariant

LB-0's invariants all still hold, verified on every LB-1 run by the same
`authority.py` scan. LB-1 adds one:

> **LB-1 may propose a representation extension. It may not adopt one.**

`FEATURE_FAMILIES` is a source constant, asserted byte-identical before and
after a full run, and `RepresentationProposal.advance(ADOPTED)` raises. The
reasoning is in `representation/proposal.py`: a discovery layer that rewrites
its own hypothesis space in response to data is one whose future findings are
conditioned on its past ones with no external record of when the space changed.
The cost of the restriction is one review step; the cost of removing it is that
no later finding can be audited against a fixed representation.

## 7. Known weaknesses

1. **The pool contains the answer for two of the three inadequacies.** Mitigated
   by `inadequate_unlocalised`, not eliminated. Localisation is only ever as good
   as the observables someone thought to offer, and LB-1 cannot tell you what it
   has never heard of.
2. **Two families tie at 100% on the delegation corpus** (`actor_count` and
   `actor_divergence`); the winner is chosen alphabetically. Both name the same
   observable, so the reported answer is right, but the tie-break is arbitrary.
3. **The base rule is defined as LB-0 literals.** That makes "the grammar is
   adequate here" provable rather than hopeful, but it also means the adequate
   control is adequate *by construction* rather than by luck.
4. **The probe assumes trajectories can be re-run.** Real governance traces
   often cannot be replayed against the real world, which is precisely the
   mechanism LB-1 depends on. In production this becomes a shadow-execution
   problem, and it is the hardest thing standing between LB-1 and LB-3.
5. **Thresholds are sharp.** A world that is *slightly* stochastic (say 1%)
   would pass the reproducibility margin and be reported INADEQUATE. The
   residual-beyond-noise figure is reported in every verdict to make that
   visible, but the verdict itself is a hard classification.
6. **Six environments, one corpus, two seeds checked.** Not a general result.

## 8. What is NOT claimed

That LB-1 finds all representational gaps, that the extension pool is anything
like exhaustive, or that a proposal should be adopted. The strongest honest
statement is the negative one: **an inadequacy that would previously have been
silent is now reported, with a computable bound on what it costs, and separated
from noise by an experiment rather than by assertion.**

## 9. Why replayability is the blocker, and what it costs

LB-1's verdict rests entirely on one operation: **run the trajectory again,
twice**. Every discrimination it makes comes from that probe, not from the
collision statistics — `inadequate_timing` and `stochastic` collide at
essentially the same rate and are separated only by what re-running reveals.

That operation is unavailable for most real governance evidence, and not for
engineering reasons. The trajectories a governance system most needs to learn
from are exactly the ones that must never be repeated:

- an email that has already been sent
- a payment that has already been initiated
- a healthcare record that has already been accessed
- a cloud resource that has already been mutated
- a permission state that has since changed underneath the trace

Re-running any of those to test an ontology hypothesis would cause the harm a
second time in order to study it. No experimental value justifies that, so the
probe cannot simply be pointed at production evidence.

**What is lost with it is specific, and worth naming before attempting a
replacement.** Replay is what lets LB-1 separate *the world is random* from
*something real drove this and we did not record it*. Both produce identical
observational signatures: trajectories that agree on every field the telemetry
carries and disagree in outcome. Only re-execution distinguishes them, because
only re-execution can ask the world the same question twice.

LB-2 therefore removes the probe and asks whether defensible evidence of
representational inadequacy can still be assembled from **sealed, irreversible,
observational** traces alone — and reports honestly which of LB-1's
discriminations survive the loss and which do not.
