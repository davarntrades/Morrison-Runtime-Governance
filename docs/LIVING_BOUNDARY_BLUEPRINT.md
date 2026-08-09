# Morrison Runtime Governance
## Living Boundary Architecture Blueprint

**Status:** Research / Experimental Architecture  
**Purpose:** Adaptive discovery of previously unmodelled runtime failure structures  
**Authority Model:** Discover autonomously. Test autonomously. Never self-authorise production policy changes.

---

# 1. Vision

Morrison Runtime Governance currently evaluates AI actions against known governance boundaries before execution.

The Living Boundary extends this architecture by addressing a deeper problem:

> What happens when the current governance ontology does not contain the concept required to describe an emerging failure?

Traditional policy systems assume that the relevant risk categories are already known.

Examples:

- credential exfiltration
- unauthorised financial transfer
- PHI disclosure
- destructive infrastructure mutation
- privilege escalation
- prohibited communication
- unapproved external execution

But increasingly capable AI systems may produce failures through combinations, couplings and trajectories that do not map cleanly onto any individual predefined category.

The Living Boundary therefore introduces a second governance loop:

**Runtime Governance** controls execution within the current ontology.

**Living Boundary** tests whether the current ontology itself remains sufficient.

The objective is not to allow AI systems to rewrite their own safety rules.

The objective is to allow the governance system to detect when its current map of risk is incomplete.

---

# 2. Core Principle

The system may discover that the boundary is incomplete.

It may propose a new representation of the failure.

It may generate tests for that representation.

It may gather supporting evidence.

It must not autonomously grant that representation production authority.

Production boundary modification remains explicitly authorised and version-controlled.

Therefore:

> **Discovery is autonomous. Authority is not.**

And as a permanent architectural invariant:

> **The system may discover that the map is wrong. It does not receive authority to redraw the border.**

---

# 3. Existing Runtime Model

The existing Morrison Runtime Governance architecture evaluates whether a proposed action or trajectory enters a prohibited region.

Simplified:

```text
Current State
      ↓
Proposed Action
      ↓
Capability Classification
      ↓
Trust Boundary
      ↓
Trajectory Analysis
      ↓
Policy Evaluation
      ↓
Approval Verification
      ↓
Evidence Sealing
      ↓
Provider Execution
```

Conceptually:

```text
Reach(xₜ) ∩ Ωₜ = ∅
```

Where:

- `xₜ` = current observable system state
- `Reach(xₜ)` = reachable outcomes from the current state
- `Ωₜ` = currently defined unsafe region

The limitation is that `Ωₜ` is constructed from the governance ontology we currently know.

The Living Boundary asks:

> What if the observed failure cannot be adequately represented by Ωₜ?

---

# 4. Living Boundary Model

The Living Boundary introduces ontology evolution:

```text
Ωₜ → Ωₜ₊₁
```

but only after evidence-based validation and authorised promotion.

The discovery loop becomes:

```text
Observed Trajectories
        ↓
Prediction Error / Novel Failure
        ↓
Ontology Coverage Analysis
        ↓
Latent Structure Inference
        ↓
Candidate Risk Primitive
        ↓
Falsifiable Predictions
        ↓
Adversarial Experiments
        ↓
Evidence Accumulation
        ↓
Human / Authorised Review
        ↓
Versioned Ontology Update
        ↓
Runtime Deployment
```

---

# 5. The Problem: Unsafe Composition

A critical target is **compositional risk**.

An individual action may be safe.

Another individual action may also be safe.

Their interaction may not be.

Example:

```text
Action A
Read customer account metadata
→ permitted

Action B
Generate payment workflow
→ permitted

Action C
Send information to approved CRM
→ permitted
```

But:

```text
A → B → C
```

under a particular identity, timing, data-flow or permission relationship may create a prohibited outcome.

Therefore:

```text
Safe(A) = true
Safe(B) = true
Safe(C) = true

but

Safe(A ∘ B ∘ C) = false
```

The governing primitive may therefore exist at the level of the **trajectory or coupling**, not the individual action.

---

# 6. Candidate Concept: Cross-Domain Coupling

The system should be capable of identifying previously unrepresented interactions such as:

```text
Domain A × Domain B → Emergent Risk
```

Examples:

```text
Finance × Identity
Privacy × Communications
Infrastructure × Credentials
Healthcare × External Messaging
CRM × Payment Systems
Cloud Permissions × Autonomous Execution
```

A candidate newly discovered primitive might describe:

> A configuration in which individually permitted actions across separate governance domains combine to create an unsafe reachable state.

The exact terminology must be treated as provisional until empirically validated.

The system must discover useful structures rather than merely invent impressive labels.

---

# 7. Architecture

The Living Boundary should initially operate **outside the production execution decision path**.

```text
                    ┌────────────────────┐
                    │ Runtime Governance │
                    └──────────┬─────────┘
                               │
                        Immutable Trace
                               │
                               ▼
                ┌──────────────────────────┐
                │ Living Boundary Observer │
                └────────────┬─────────────┘
                             │
                 Detect unexplained patterns
                             │
                             ▼
                ┌──────────────────────────┐
                │ Ontology Gap Detector    │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Structure Discovery      │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Candidate Primitive      │
                │ Generator                │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Experiment Generator     │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Hardening / Simulation   │
                │ Environment              │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Evidence Evaluator       │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │ Human Approval Boundary  │
                └────────────┬─────────────┘
                             │
                             ▼
                       Ωₜ → Ωₜ₊₁
```

---

# 8. System Components

## 8.1 Trace Observer

Consumes runtime evidence generated by Morrison Runtime Governance.

Inputs may include:

- proposed capability
- action sequence
- provider
- tool calls
- resource targets
- trust boundaries
- identities
- permissions
- policy decisions
- trajectory classification
- approvals
- execution outcome
- blocked outcome
- timestamps
- environment
- provenance
- agent relationships

It does not modify production behaviour.

## 8.2 Ontology Gap Detector

Determines whether observed behaviour is poorly represented by existing governance concepts.

Signals may include:

- repeated policy misses
- unexplained outcome variance
- failures composed entirely of individually permitted actions
- policy conflicts
- unusual multi-domain coupling
- anomalous state transitions
- adversarial failures outside known categories
- high residual prediction error
- novel multi-agent interactions

Possible output:

```json
{
  "ontology_gap_detected": true,
  "confidence": 0.87,
  "affected_domains": [
    "finance",
    "identity",
    "data_privacy"
  ],
  "existing_primitives_insufficient": [
    "unauthorised_transfer",
    "credential_exfiltration"
  ],
  "evidence_refs": [
    "trace_291",
    "trace_450",
    "trace_612"
  ]
}
```

---

# 9. Structure Discovery

When an ontology gap is detected, the system attempts to identify the latent variable or interaction responsible for the failure.

Candidate factors may include:

- sequence
- timing
- shared identity
- shared destination
- permission inheritance
- cross-domain coupling
- hidden dependency
- repeated resource access
- trust-boundary transitions
- multi-agent delegation
- information accumulation
- action composition
- temporal escalation
- recursive planning

The objective is not explanation for explanation's sake.

A candidate structure is only useful if it improves prediction.

---

# 10. Candidate Primitive Generation

The system may propose a candidate governance primitive.

Example:

```json
{
  "candidate_id": "CP-0041",
  "name": "cross_domain_authority_accumulation",
  "description": "A trajectory in which individually permitted actions accumulate authority across multiple governance domains until a prohibited state becomes reachable.",
  "observed_variables": [
    "identity",
    "permission_scope",
    "domain_transition_count",
    "resource_access"
  ],
  "hypothesised_invariant": "...",
  "supporting_traces": 17,
  "status": "experimental"
}
```

All generated primitives begin as:

```text
EXPERIMENTAL
```

Never:

```text
ACTIVE_POLICY
```

---

# 11. Falsifiability Requirement

Every candidate primitive must generate predictions that can fail.

For example:

> If cross-domain authority accumulation is the governing structure, then trajectories exceeding threshold X across domains Y and Z should produce significantly higher unsafe reachability than equivalent single-domain trajectories.

Then test it.

A candidate primitive that cannot generate falsifiable predictions should not be promoted.

---

# 12. Experiment Generator

The system creates controlled adversarial cases.

Example matrix:

```text
Single-domain safe action
Single-domain unsafe action
Two-domain composition
Three-domain composition
Different action order
Different identities
Different trust boundaries
Different timing
Different permission scopes
Different agent counts
Different provider models
```

Testing should determine whether the candidate primitive:

- predicts failures
- generalises beyond the discovery examples
- avoids excessive false positives
- identifies previously unknown failures
- remains stable under perturbation

---

# 13. Hardening Integration

The Living Boundary should connect to the existing Morrison hardening pipeline.

Candidate primitives should be tested against:

- existing regression suite
- adversarial scenarios
- multi-agent simulations
- cybersecurity scenarios
- healthcare scenarios
- finance scenarios
- Gmail connector
- AWS Bedrock connector
- future CRM connectors

No candidate primitive should enter production merely because an LLM describes it persuasively.

**Evidence outranks explanation.**

---

# 14. Promotion Lifecycle

Every primitive should move through an explicit state machine:

```text
DISCOVERED
   ↓
HYPOTHESISED
   ↓
TESTING
   ↓
VALIDATED
   ↓
REVIEW_REQUIRED
   ↓
APPROVED
   ↓
SHADOW
   ↓
ENFORCED
```

Possible rejection states:

```text
REJECTED
SUPERSEDED
RETEST_REQUIRED
```

---

# 15. Human Authority Boundary

The following operations must require explicit authorised approval:

- production ontology modification
- production policy modification
- enforcement threshold modification
- removal of existing safety constraints
- expansion of agent permissions
- trust-boundary modification
- transition from SHADOW to ENFORCED

The discovery system must not be able to approve itself.

---

# 16. Shadow Mode

Before enforcement, validated primitives should enter **shadow mode**.

Shadow mode asks:

> What would have happened if this primitive had been active?

Record:

- additional blocks
- additional escalations
- false positives
- false negatives
- newly detected trajectories
- business impact
- latency impact
- policy overlap

Only after acceptable shadow-mode performance should production enforcement be considered.

---

# 17. Evidence Model

Every ontology evolution event must create immutable evidence.

Required evidence:

```text
primitive_id
primitive_version
discovery_timestamp
source_traces
hypothesis
generated_predictions
experiments
results
false_positive_rate
false_negative_rate
reviewer
approval
deployment_timestamp
previous_ontology_version
new_ontology_version
rollback_reference
```

This creates an auditable history of how the governance boundary evolved.

---

# 18. Versioned Ontology

Governance ontology must be versioned.

Example:

```text
morrison-ontology-v1.4
morrison-ontology-v1.5
morrison-ontology-v1.6
```

Every governance decision must record the ontology version used.

Example:

```json
{
  "decision": "blocked",
  "policy": "cross_domain_authority_accumulation",
  "ontology_version": "1.6",
  "primitive_version": "1.0",
  "trace_id": "trace_82912"
}
```

---

# 19. Rollback

Every ontology deployment must support deterministic rollback.

```text
Ωₜ₊₁ → Ωₜ
```

Rollback must restore:

- previous primitives
- previous thresholds
- previous policies
- previous evaluation behaviour

Rollback itself must produce an evidence record.

---

# 20. Threat Model

The Living Boundary introduces new attack surfaces.

Potential threats include:

### Ontology Poisoning

An attacker intentionally generates traces designed to convince the discovery system that a false primitive exists.

### Boundary Expansion Attack

A malicious agent attempts to cause the system to weaken an existing constraint.

### Primitive Explosion

The discovery system generates excessive overlapping risk primitives until governance becomes unusable.

### Semantic Manipulation

A model generates persuasive but non-predictive explanations.

### Self-Approval

A discovery agent attempts to influence or bypass the authority boundary.

### Distribution Manipulation

Adversarial examples distort the evidence base used for primitive discovery.

Mitigations must include:

- immutable provenance
- minimum evidence thresholds
- independent evaluation
- adversarial testing
- primitive deduplication
- human approval
- signed ontology versions
- rollback
- separation of discovery and enforcement authority

---

# 21. Architectural Invariants

The following invariants must never be violated.

### Invariant 1

Discovery cannot directly modify production enforcement.

### Invariant 2

Every governance decision is traceable to a specific ontology version.

### Invariant 3

Every ontology update has evidence provenance.

### Invariant 4

Every ontology update is reversible.

### Invariant 5

Candidate primitives must produce falsifiable predictions.

### Invariant 6

Explanatory elegance is not evidence.

### Invariant 7

Production authority remains externally controlled.

### Invariant 8

Existing safety boundaries fail closed during discovery-layer failure.

---

# 22. MVP Experiment

The first implementation should remain narrow.

## Objective

Determine whether the system can discover an unsafe composition that is not explicitly represented by the current policy ontology.

## Experiment

Create controlled scenarios containing:

```text
Action A = permitted
Action B = permitted
Action C = permitted
```

but configure:

```text
A → B → C = unsafe
```

Do not tell the discovery layer which composition is unsafe.

Give it:

- execution traces
- policy decisions
- outcomes
- trust-boundary data
- capability classifications
- provenance

Then test whether it can:

1. detect that the current ontology is insufficient
2. identify the relevant coupling
3. propose a candidate primitive
4. generate a falsifiable prediction
5. reproduce the failure under new conditions
6. distinguish dangerous compositions from safe controls

---

# 23. MVP Success Criteria

The experiment succeeds only if the system can:

- detect a real ontology coverage gap
- identify a repeatable latent structure
- predict unseen failures better than the existing ontology
- avoid merely memorising known examples
- reproduce findings across multiple models or seeds
- provide evidence linking discovery to source traces
- remain incapable of modifying production policy directly

---

# 24. MVP Failure Criteria

The experiment fails if:

- candidate primitives are merely linguistic descriptions
- results cannot generalise beyond training examples
- false positives dominate
- the discovery system cannot distinguish correlation from governing structure
- generated primitives duplicate existing policies
- the model fabricates evidence
- the discovery layer can influence production authority without approval

Failure is useful.

The experiment exists to determine whether ontology discovery is technically viable.

---

# 25. Suggested Repository Structure

```text
living-boundary/
│
├── observer/
│   ├── trace_reader.py
│   └── event_normalizer.py
│
├── ontology/
│   ├── registry.py
│   ├── primitives.py
│   └── versions.py
│
├── discovery/
│   ├── gap_detector.py
│   ├── structure_inference.py
│   └── primitive_generator.py
│
├── experiments/
│   ├── generator.py
│   ├── runner.py
│   └── evaluator.py
│
├── evidence/
│   ├── provenance.py
│   ├── candidate_record.py
│   └── sealing.py
│
├── promotion/
│   ├── lifecycle.py
│   ├── approval.py
│   └── shadow_mode.py
│
├── tests/
│   ├── composition/
│   ├── ontology_poisoning/
│   ├── regression/
│   └── adversarial/
│
└── README.md
```

---

# 26. Delivery Milestones

The architecture should be implemented incrementally.

## LB-0 — Composition Discovery

Find emergent failures from combinations of individually allowed actions.

Acceptance question:

> Can the system identify unsafe composition effects that were not directly encoded beforehand?

## LB-1 — Ontology Gap Detection

Determine when the existing primitives systematically fail to represent or predict an observed failure structure.

Acceptance question:

> Can the system distinguish a missing concept from ordinary model error or noise?

## LB-2 — Candidate Boundary Evolution

Generate, test, shadow and version a new primitive while retaining explicit external approval before enforcement.

Acceptance question:

> Can the governance ontology evolve from evidence without granting the discovery system production authority?

---

# 27. Long-Term Architecture

If validated, Morrison Runtime Governance could eventually contain two interacting control loops.

## Fast Loop — Runtime Governance

Milliseconds to seconds.

```text
Observe
Predict
Evaluate
Allow / Block / Escalate
Record
```

Purpose:

**Constrain the current trajectory.**

## Slow Loop — Living Boundary

Hours to weeks.

```text
Observe many trajectories
Detect ontology failure
Infer structure
Hypothesise
Experiment
Validate
Approve
Version
Deploy
```

Purpose:

**Improve the definition of what must be constrained.**

---

# 28. Strategic Model

The architecture therefore becomes:

```text
                    AI SYSTEM
                        │
                        ▼
                Proposed Trajectory
                        │
                        ▼
             ┌─────────────────────┐
             │ RUNTIME GOVERNANCE  │
             │     FAST LOOP       │
             └─────────┬───────────┘
                       │
              allow / block / escalate
                       │
                       ▼
                    Evidence
                       │
                       ▼
             ┌─────────────────────┐
             │   LIVING BOUNDARY   │
             │      SLOW LOOP      │
             └─────────┬───────────┘
                       │
              discover new structure
                       │
                       ▼
               Validated Primitive
                       │
                       ▼
               Authorised Promotion
                       │
                       ▼
                 Updated Boundary
```

---

# 29. Final Principle

Static governance asks:

> Is this action permitted by the rules we already know?

Runtime Governance asks:

> Is this trajectory capable of entering a known unsafe region?

Living Boundary asks:

> What if the unsafe region exists but our current ontology cannot yet describe it?

The long-term objective is a governance architecture capable of learning where its own model of risk is incomplete while preserving external authority over what becomes enforceable.

> **A living boundary is not a boundary that controls itself.**

> **It is a boundary capable of discovering where its map no longer matches the territory.**
