# Living Boundary — Ontology Uncertainty & Meta-Observability

**Status:** Experimental / Research Extension  
**Applies to:** LB-0 through LB-4  
**Production Authority:** None  
**Purpose:** Prevent Living Boundary from assuming that its own representation of safety gaps is complete.

---

## 1. The Hard Question

Living Boundary exists because Morrison's current governance ontology may fail to represent an emerging unsafe structure.

But Living Boundary itself necessarily has an ontology.

Its gap detector uses concepts such as:

- unsafe outcome
- repeated unsafe outcomes
- materially different outcomes among superficially similar trajectories
- residual error
- coupling
- permission accumulation
- trust-boundary transition
- candidate primitive

Those concepts are also compressions.

Therefore Living Boundary must explicitly account for the possibility that:

> **The discovery layer's own representation can become insufficient.**

This creates a recursive epistemic risk:

```text
Runtime Governance
    ↓
Living Boundary detects gaps in Runtime Governance
    ↓
But what detects gaps in Living Boundary itself?
```

The architecture must not solve this with unbounded recursive self-modification.

Instead, Living Boundary should be treated as **epistemically bounded**.

---

## 2. Core Principle

Living Boundary must never claim:

> "No unknown failure mode exists."

It may only claim:

> **"No ontology failure is observable under the current measurement grammar, evidence, representation and tests."**

This distinction is an architectural invariant.

---

## 3. Ontology Uncertainty

Introduce a first-class experimental concept:

```text
ONTOLOGY_UNCERTAINTY
```

Ontology uncertainty represents evidence that Living Boundary's current representation is losing predictive sufficiency even when it cannot yet name the missing primitive.

Let:

```text
φₜ : X → Z
```

where:

- `X` = underlying system / trajectory state
- `Z` = Living Boundary's current representational space
- `φₜ` = the current coarse-graining / feature representation

A critical warning condition occurs when:

```text
φₜ(x₁) ≈ φₜ(x₂)
```

while:

```text
Outcome(x₁) ≠ Outcome(x₂)
```

In plain language:

> Living Boundary considers two trajectories materially equivalent, yet reality repeatedly produces materially different outcomes.

That is evidence that the current representation may be collapsing a hidden variable or coupling.

The system does not need to know the missing concept yet.

It only needs to detect:

> **"My current representation is losing predictive sufficiency."**

---

## 4. Meta-Observability Layer

Add a read-only experimental meta-observability component above the normal ontology-gap detector.

```text
Runtime / Experimental Traces
          ↓
Standard Living Boundary Representation φₜ
          ↓
Gap Detection / Candidate Discovery
          ↓
Prediction + Evaluation
          ↓
Residual & Representation Diagnostics
          ↓
Meta-Observability
          ↓
ONTOLOGY_UNCERTAINTY signal
          ↓
Human / Authorised Review
```

The meta-observability layer does **not** create production policy.

It measures whether the discovery system's own representation is still adequate to separate trajectories with materially different outcomes.

---

## 5. Prototype Signals

The prototype should compute ontology-uncertainty signals such as:

### 5.1 Representation Collision

Two or more trajectories map to the same or near-identical Living Boundary feature representation but produce different outcomes.

```text
representation_collision_rate
```

### 5.2 Residual Structure

Prediction errors are not random; they cluster around an unrepresented variable, interaction, sequence, domain crossing, identity pattern, permission pattern, timing pattern or other latent structure.

```text
structured_residual_score
```

### 5.3 Calibration Degradation

The system reports high confidence while prediction error rises.

```text
calibration_error
```

### 5.4 Unexplained Outcome Divergence

Superficially equivalent trajectories diverge repeatedly in outcome.

```text
outcome_divergence_rate
```

### 5.5 Candidate Instability

Different seeds, partitions or perturbations produce incompatible candidate primitives from the same underlying failure class.

```text
candidate_stability_score
```

### 5.6 Unknown-Unknown Trigger

If no candidate primitive explains the residual structure better than baseline, the correct result is not forced interpretation.

The result should be:

```text
ONTOLOGY_UNCERTAINTY = HIGH
candidate_status = INCONCLUSIVE
human_review_required = true
```

---

## 6. New Evidence Contract

Extend Living Boundary experimental evidence with:

```json
{
  "ontology_uncertainty": {
    "status": "low | medium | high",
    "representation_collision_rate": 0.0,
    "structured_residual_score": 0.0,
    "calibration_error": 0.0,
    "outcome_divergence_rate": 0.0,
    "candidate_stability_score": 1.0,
    "unexplained_trace_ids": [],
    "measurement_grammar_version": "lb-measurement-v0.1",
    "representation_version": "lb-representation-v0.1",
    "human_review_required": false
  }
}
```

Exact thresholds remain experimental during LB-0/LB-1 and must not be represented as production safety guarantees.

---

## 7. Measurement Grammar Versioning

Living Boundary must version not only the governance ontology but also the representation used to discover ontology failures.

Record:

```text
measurement_grammar_version
representation_version
feature_schema_version
gap_detector_version
candidate_generator_version
evaluator_version
```

This allows a result to be reconstructed under the exact discovery vocabulary that existed at the time.

A candidate primitive without the discovery representation version is incomplete evidence.

---

## 8. The Scientific Loop vs Constitutional Loop

Living Boundary should separate two authority domains.

### Scientific Loop

The machine may autonomously:

```text
observe anomaly
    ↓
measure residual structure
    ↓
detect ontology uncertainty
    ↓
propose hypothesis
    ↓
propose candidate primitive
    ↓
generate falsification tests
    ↓
validate on held-out evidence
    ↓
produce evidence package
```

### Constitutional Loop

Only authorised external governance may:

```text
review
    ↓
approve / reject
    ↓
version
    ↓
shadow
    ↓
promote
    ↓
enforce
    ↓
rollback
```

The scientific loop may discover that humans lack a useful concept.

It must not receive unilateral authority to decide that the concept becomes law.

---

## 9. Human Review as an Architectural Invariant

Human review is not merely a temporary limitation until the discovery layer becomes more capable.

For the Living Boundary architecture, authorised review should remain the final observer for production ontology changes.

The system may eventually produce an evidence package like:

> The current governance ontology predicts these trajectories should be equivalent. They are not. Residual structure is associated with authority accumulated across otherwise independently safe domains. I have generated the candidate primitive `cross_domain_authority_accumulation`. Here are the falsification tests, counterexamples, held-out metrics and provenance. Human authorisation is required before this primitive can enter enforcement.

That is acceptable.

This is not:

> "I discovered a better ontology and deployed it myself."

That remains prohibited.

---

## 10. Prototype Tests

Add tests equivalent to:

```text
test_representation_collision_detected_when_same_features_have_different_outcomes
test_random_residual_noise_does_not_force_new_primitive
test_structured_residuals_raise_ontology_uncertainty
test_high_confidence_wrong_predictions_raise_calibration_warning
test_candidate_instability_is_recorded_across_seeds
test_inconclusive_result_is_allowed
test_ontology_uncertainty_cannot_modify_runtime_policy
test_measurement_grammar_version_is_recorded_in_evidence
test_human_review_required_for_any_boundary_promotion
test_meta_observability_failure_does_not_change_v1_govern_behavior
```

A successful system must be capable of saying:

```text
I DO NOT CURRENTLY HAVE A SUFFICIENT REPRESENTATION TO EXPLAIN THIS FAILURE.
```

That is a valid scientific result.

---

## 11. LB-0 Extension

LB-0 should retain its original narrow objective: discover a hidden compositional failure.

Add one secondary experiment:

1. Generate trajectories where the public Living Boundary feature representation intentionally aliases two different hidden structures.
2. Ensure some aliased trajectories are safe and others unsafe.
3. Do **not** expose the hidden distinguishing variable.
4. Verify the standard gap detector cannot cleanly explain the divergence.
5. Verify the meta-observability layer detects loss of predictive sufficiency.
6. Require the result to be `ONTOLOGY_UNCERTAINTY` or `INCONCLUSIVE` rather than a fabricated candidate primitive.

This tests whether the prototype can recognise when its own vocabulary is inadequate.

---

## 12. Future Phase Implication

The Living Boundary roadmap should be interpreted as:

```text
LB-0 — Composition Discovery
LB-1 — General Ontology Gap Detection
LB-2 — Candidate Boundary Evolution
LB-3 — Multi-Environment Generalisation
LB-4 — Living Boundary Service
```

with **meta-observability and ontology uncertainty operating across all phases**, not as an infinite LB-5 / LB-6 recursion.

The architecture should resist "turtles all the way down."

The response to recursive uncertainty is:

- explicit epistemic bounds
- representation diagnostics
- versioned measurement grammar
- falsification
- evidence
- authorised human review

not autonomous recursive policy rewriting.

---

## 13. Permanent Invariants

1. Living Boundary may discover that Runtime Governance's ontology is incomplete.
2. Living Boundary may also discover evidence that its **own** representation is incomplete.
3. Absence of detected ontology failure is not proof that no unknown failure exists.
4. An unexplained residual may remain unresolved.
5. The system must be allowed to return `INCONCLUSIVE`.
6. Candidate primitives require falsifiable predictions.
7. Discovery representation and measurement grammar must be versioned.
8. Scientific discovery does not confer production authority.
9. Human / authorised review remains required for production boundary evolution.
10. Failure of the discovery or meta-observability layer must never weaken existing Runtime Governance.

---

## 14. Final Principle

Runtime Governance asks:

> **Given the current boundary, is this trajectory admissible?**

Living Boundary asks:

> **Is the current boundary representation still sufficient?**

Meta-observability asks:

> **Is Living Boundary itself still capable of distinguishing the structures that matter?**

The answer is not infinite recursion.

It is an architecture capable of saying:

> **"My current map may be inadequate. Here is the evidence of that inadequacy. I do not have authority to redraw the border."**
