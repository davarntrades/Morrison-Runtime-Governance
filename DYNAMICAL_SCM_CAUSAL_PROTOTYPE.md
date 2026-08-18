# Dynamical + SCM Causal Analysis Prototype

## Purpose

This document proposes an **additive causal-analysis prototype** for Morrison Runtime Governance.

It does **not** replace Morrison's governance kernel, policy hierarchy, Ω semantics, enforcement path, or execution decision logic.

The objective is to extend the evidence layer so that, after Morrison evaluates a trajectory, the system can also answer higher-resolution causal questions such as:

- Why was the forbidden state reachable?
- Which causal variables mattered most?
- Which intervention would have prevented the transition?
- Would the trajectory still have reached Ω if permission, monitoring, safeguard state, or another causal parent had been changed?
- Which causal explanation remains reliable after representation compression?

The prototype should run in **shadow / analysis mode first** and consume existing trajectory evidence rather than changing allow/block/escalate semantics.

---

## Research motivation

Synthetic representation-sufficiency tests produced a consistent pattern:

- psychological descriptions were useful for behavioural compression;
- dynamical representations improved state/trajectory/reachability reasoning;
- explicit SCM/mechanistic representations improved intervention questions;
- a hybrid dynamical + SCM representation was strongest under matched feature-count compression.

A recent ablation benchmark found:

| Retained scalar features | Hybrid | Pure SCM | Mechanistic trace |
|---:|---:|---:|---:|
| 6 | **96.48%** | 93.64% | 94.87% |
| 5 | **96.38%** | 91.22% | 91.83% |
| 4 | **95.90%** | 87.77% | 89.09% |
| 3 | **93.50%** | 81.14% | 82.04% |
| 2 | **90.22%** | 76.65% | 76.69% |
| 1 | **76.68%** | 67.06% | 67.10% |

The high-resolution representation remained on a broad performance plateau until roughly four retained variables, followed by a sharper collapse under heavier compression.

The practical hypothesis for Morrison is therefore:

> **Trajectory/reachability structure and explicit intervention structure are complementary.**

Morrison already has strong dynamical evidence: trajectories, reachability, constraints, policy layers, taint, admissibility, and Ω classification. The prototype adds a separate causal interpretation over that evidence.

---

# Core architectural principle

```text
Planner / Agent
      |
      v
Existing Morrison Governance
      |
      |-- capability classification
      |-- trajectory construction
      |-- reachability / Ω evaluation
      |-- policy / admissibility
      |-- allow / block / escalate
      |-- immutable evidence
      |
      +----------------------------+
                                   |
                                   v
                       Causal Analysis Overlay
                                   |
                                   |-- causal-variable extraction
                                   |-- SCM graph construction
                                   |-- counterfactual interventions
                                   |-- contribution trace
                                   |-- causal-resolution score
                                   |-- explanation evidence
```

**The causal overlay must never be in the critical authorization path during the prototype phase.**

If the overlay fails, Morrison's existing verdict remains unchanged.

---

# Proposed causal representation

For a governed trajectory \(\tau\), construct a hybrid representation:

\[
R_h(\tau) = R_d(\tau) \oplus R_c(\tau)
\]

where:

## Dynamical component \(R_d\)

Possible fields derived from existing Morrison evidence:

- current state;
- prior state / prefix state;
- trajectory step index;
- cumulative risk;
- reachable Ω categories;
- active constraints;
- admissibility margin;
- source→sink taint state;
- capability set;
- trust boundary state;
- branch / dependency graph position;
- environment-sensitive flags;
- planner proposal / executable action.

## Structural-causal component \(R_c\)

Candidate causal parents:

- permission / capability availability;
- safeguard / policy state;
- approval requirement;
- trust-boundary classification;
- sensitive-data possession;
- destination classification;
- external-egress availability;
- role / identity / authorization state;
- environment flags;
- prior risky action;
- tool availability;
- human approval state.

The initial graph should be **explicit and deterministic**, not learned from production data.

Example:

```text
sensitive_data_acquired ---> exfiltration_reachable
external_egress_enabled ---> exfiltration_reachable
permission_granted -------> exfiltration_reachable
policy_safeguard_active --| exfiltration_reachable
human_approval_required --| unauthorized_execution
```

The arrows represent hypothesised structural dependencies used for prototype counterfactual analysis.

---

# Prototype questions

For every blocked or escalated trajectory, generate a bounded set of causal questions.

## Example: data exfiltration

Observed trajectory:

```text
read_secret -> transform -> http_post_external
```

Morrison evidence may already establish that Ω is reachable through source→sink taint.

The causal overlay asks:

1. **Would disabling external egress have prevented Ω reachability?**
2. **Would removing secret-read permission have prevented Ω reachability?**
3. **Would enforcing an internal-only destination constraint have prevented the trajectory?**
4. **Would mandatory human approval before the sink transition have broken the path?**

Each is represented as a structural intervention:

\[
do(X=x')
\]

The overlay then re-evaluates the counterfactual trajectory using a bounded simulator / evidence transformation.

---

# Prototype data structures

## CausalVariable

```python
@dataclass(frozen=True)
class CausalVariable:
    name: str
    value: object
    source: str
    kind: str  # state | permission | safeguard | environment | capability
    intervenable: bool
```

## CausalEdge

```python
@dataclass(frozen=True)
class CausalEdge:
    parent: str
    child: str
    relation: str
    provenance: str
```

## CausalIntervention

```python
@dataclass(frozen=True)
class CausalIntervention:
    variable: str
    factual_value: object
    counterfactual_value: object
    question: str
```

## CounterfactualResult

```python
@dataclass(frozen=True)
class CounterfactualResult:
    intervention: CausalIntervention
    factual_verdict: str
    counterfactual_verdict: str
    factual_omega: tuple[str, ...]
    counterfactual_omega: tuple[str, ...]
    prevented: bool
    evidence_refs: tuple[str, ...]
```

## CausalAnalysisReport

```python
@dataclass(frozen=True)
class CausalAnalysisReport:
    trajectory_id: str
    causal_variables: tuple[CausalVariable, ...]
    causal_edges: tuple[CausalEdge, ...]
    interventions: tuple[CounterfactualResult, ...]
    necessary_contributors: tuple[str, ...]
    sufficient_interventions: tuple[str, ...]
    resolution_score: float
    evidence_hash: str
```

---

# Minimal prototype algorithm

## Phase 1 — Extract causal variables

Input: existing Morrison evidence object / governed trajectory.

Deterministically derive variables such as:

```text
has_sensitive_data = true
external_egress_enabled = true
permission_read_secret = true
policy_blocks_external_secret_egress = true
approval_present = false
trust_boundary = external
```

Every variable must contain provenance pointing back to the Morrison evidence that produced it.

## Phase 2 — Build scenario-specific causal graph

Use a registry keyed by Ω / incident class.

Example:

```python
CAUSAL_TEMPLATES = {
    "secret_exfiltration": [...],
    "unauthorized_transfer": [...],
    "privilege_escalation": [...],
    "destructive_shell": [...],
}
```

No LLM-generated graph should be trusted in the initial prototype.

## Phase 3 — Generate bounded interventions

Only generate interventions for variables marked `intervenable=True`.

Examples:

```text
external_egress_enabled: true -> false
permission_transfer: true -> false
approval_required: false -> true
safeguard_active: false -> true
```

Limit the initial prototype to one-variable interventions.

## Phase 4 — Counterfactual replay

For each intervention:

1. copy the governed evidence/trajectory context;
2. apply exactly one intervention;
3. recompute the relevant derived state;
4. run the existing Morrison evaluation logic on the modified trajectory/context **without changing that logic**;
5. compare factual and counterfactual outcomes.

This is the critical bridge between SCM-style intervention semantics and Morrison's existing dynamical governance.

```text
factual trajectory -> Morrison -> Ω reachable / BLOCK

        do(permission=false)
                 |
                 v
counterfactual trajectory/context -> Morrison -> Ω unreachable / PERMIT
```

If the verdict changes from forbidden/reachable to safe/unreachable, record that intervention as a candidate preventive cause.

## Phase 5 — Contribution trace

For each variable/intervention, compute evidence such as:

- verdict changed? yes/no;
- Ω reachability changed? yes/no;
- risk score delta;
- reachable-state-set delta;
- first blocked step moved?;
- constraint margin delta;
- policy layer responsible.

This creates the mechanistic contribution trace.

## Phase 6 — Causal-resolution score

Prototype score:

```text
resolution_score = answered_intervention_questions / eligible_intervention_questions
```

Later versions can incorporate confidence, evidence completeness, representation bit-rate, and task-specific reliability thresholds.

---

# First prototype scenarios

Use existing Morrison scenarios. Do not invent a new governance engine.

## 1. Secret exfiltration

```text
read_secret -> http_post_external
```

Interventions:

- remove secret-read permission;
- disable external egress;
- activate source→sink safeguard;
- require human approval.

## 2. Unauthorized transfer

```text
transfer(amount=..., destination=external)
```

Interventions:

- remove transfer permission;
- cap amount below policy threshold;
- require approval;
- force trusted destination.

## 3. Privilege escalation

```text
acquire_credentials -> sudo/chmod/grant
```

Interventions:

- remove privilege-widening capability;
- activate role constraint;
- remove credential access;
- require approval.

## 4. Multi-step exfiltration

```text
acquire_sensitive_data -> benign transforms -> delayed egress
```

Interventions:

- cut source access;
- cut sink access;
- enforce taint propagation;
- restrict branch/tool capability.

These are ideal because Morrison already has deterministic evidence about the trajectory and forbidden state.

---

# UI prototype

Add a non-authoritative **Causal Analysis** panel to the existing evidence/Control Room surface.

Suggested structure:

```text
Causal Analysis

Observed forbidden transition
  Sensitive data -> External egress

Why was it reachable?
  ✓ Secret read capability available
  ✓ Sensitive data entered trajectory
  ✓ External sink reachable
  ✓ No approval at terminal transition

Counterfactual interventions
  Disable external egress       -> Ω unreachable
  Remove secret-read permission -> Ω unreachable
  Require approval              -> transition intercepted
  Remove monitoring             -> no material change

Minimum preventive set
  external_egress_enabled = false

Causal resolution
  4 / 4 intervention questions answered
```

The panel should clearly distinguish:

- **Observed evidence**
- **Derived causal structure**
- **Counterfactual result**
- **Morrison enforcement verdict**

Never present the counterfactual explanation as an observed fact.

---

# Evidence schema extension

Prototype-only additive artifact:

```json
{
  "causal_analysis": {
    "version": "prototype-0.1",
    "mode": "shadow",
    "trajectory_id": "...",
    "variables": [],
    "edges": [],
    "interventions": [],
    "necessary_contributors": [],
    "sufficient_interventions": [],
    "resolution_score": 1.0,
    "source_evidence_hash": "..."
  }
}
```

Do not mutate canonical evidence fields. The causal analysis should reference canonical evidence by hash/id.

---

# Acceptance criteria

The first prototype is successful when:

1. Morrison's existing verdicts remain byte-for-byte / semantically unchanged.
2. A blocked trajectory can produce deterministic causal variables from existing evidence.
3. At least four bounded one-variable interventions can be replayed.
4. Counterfactual replay uses the existing Morrison evaluation path.
5. The prototype identifies at least one intervention that prevents Ω reachability in known adversarial cases.
6. Safe cases do not acquire invented causes or interventions.
7. Every causal claim links back to evidence provenance.
8. Repeated runs on the same trace produce identical causal reports.
9. Failure of the causal overlay cannot turn BLOCK into PERMIT.
10. The entire causal artifact can be disabled without changing governance behaviour.

---

# Tests to add

```text
test_causal_overlay_does_not_change_verdict

test_secret_exfiltration_disable_egress_prevents_omega

test_secret_exfiltration_remove_source_permission_prevents_omega

test_transfer_require_approval_changes_reachability

test_irrelevant_intervention_does_not_change_verdict

test_causal_report_is_deterministic

test_causal_report_links_to_source_evidence_hash

test_overlay_failure_is_non_authoritative
```

Later:

```text
test_minimal_intervention_set

test_multi_variable_intervention

test_causal_resolution_under_compression

test_hybrid_vs_scm_only_vs_dynamics_only
```

---

# Suggested implementation layout

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
    report.py

runtime_eval/tests/
  test_causal_overlay.py
```

The implementation should import/reuse existing Morrison trajectory/evaluator functions rather than duplicating them.

---

# Prototype build order

1. **Read existing evidence schema and evaluator entry points.**
2. Implement immutable causal data classes.
3. Implement one scenario template: secret exfiltration.
4. Extract variables deterministically from canonical evidence.
5. Add one-variable intervention engine.
6. Replay interventions through existing evaluator.
7. Produce deterministic JSON causal report.
8. Add tests proving verdict non-interference.
9. Add unauthorized-transfer template.
10. Add UI panel only after backend evidence is stable.

---

# Codex implementation brief

Use this as the implementation instruction:

> Work inside the existing Morrison Runtime Governance repository. Do not rebuild or modify the Morrison governance kernel, Ω rules, policy hierarchy, execution semantics, or existing allow/block/escalate decisions. Implement an additive `runtime_eval/causal_overlay/` research prototype that consumes existing governed trajectory/evidence objects after evaluation. The prototype must deterministically extract causal variables, build explicit scenario-specific SCM templates, generate bounded one-variable interventions, replay those interventions through the existing Morrison evaluation path, and emit a separate immutable causal-analysis artifact containing factual vs counterfactual reachability, preventive interventions, contribution traces, and provenance links to canonical evidence. Start with secret exfiltration and unauthorized transfer. The overlay must be non-authoritative: failures cannot change the original verdict. Add tests proving verdict invariance, deterministic reports, correct counterfactual prevention, irrelevant-intervention stability, and evidence-hash linkage. Do not use an LLM to invent causal graphs in v0.1.

---

# Longer-term research direction

If the prototype behaves well, Morrison can evaluate not only:

> **Is a forbidden state reachable?**

but also:

> **Which intervention makes it unreachable?**

This yields a combined representation:

\[
\text{State} + \text{Trajectory} + \text{Reachability} + \text{Constraints}
+
\text{Causal Parents} + \text{Interventions} + \text{Counterfactuals}
\]

The goal is not to replace dynamical language with SCM language.

The goal is to preserve enough causal resolution to answer both:

> **How did the system get here?**

and

> **What would have changed the outcome?**
