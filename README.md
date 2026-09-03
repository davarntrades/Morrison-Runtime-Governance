<div align="center">

# Morrison Runtime Governance™

![Safety Envelope](https://img.shields.io/badge/Local_Safety_Envelope-Environment--Bounded-5b6cff?style=flat-square)
![Safety](https://img.shields.io/badge/Safety-ℛ(t)_∩_Ω_=_∅-0075ca?style=flat-square)
![Evaluations](https://img.shields.io/badge/Evaluations-129%2C857-0075ca?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-1%2C092_Passing-2ea44f?style=flat-square)
![Patent](https://img.shields.io/badge/UK_Patent-GB2600765.8-0075ca?style=flat-square)

**Local Safety Envelopes for autonomous AI — established, tested, and enforced before execution.**

**Morrison shows what locally safe operation actually looks like inside a real environment, under its tools, permissions, policies, workflows, and reachable states.**

</div>

---

## Try Morrison now

Choose the path that matches how deeply you want to inspect the system.

### 1. Browser — no install, account, agent, or API key

- **[Live trajectory console](https://www.resurrection-tech.com/live-demo)** — paste your own tool-call sequence and receive the real pre-execution verdict, layer, reason, and downloadable audit trail.
- **[Test without your own agent](https://www.resurrection-tech.com/test-without-agent)** — run prepared agent scenarios or type a task and inspect the proposed trajectory before Morrison evaluates it.

The public console inspects proposed actions only. It does not execute the submitted workflow or expose a production credential in the browser.

### 2. Two-minute local Quick Start — no model key required

```bash
git clone https://github.com/davarntrades/Morrison-Runtime-Governance.git
cd Morrison-Runtime-Governance
python3 quickstart.py
```

The Quick Start now runs the current stack end to end:

1. pre-execution `PERMIT` / `BLOCK` trajectory decisions;
2. enforcement-layer attribution;
3. deterministic replay;
4. the non-authoritative causal overlay and bounded counterfactual interventions;
5. construction and evaluation of a provenance-linked local Safety Envelope;
6. exhaustive control-versus-governed state-space comparison in a finite model.

For a paced screen-recording version:

```bash
python3 quickstart.py --cinematic
```

### 3. Test the evidence surfaces directly

Run a deterministic Frontier Containment experiment. The planner may propose prohibited actions, but only Morrison-permitted calls can reach the inert simulator:

```bash
python -m runtime_eval.frontier.cli \
  --provider deterministic \
  --scenario all
```

Exhaustively enumerate a finite secret-exfiltration environment in control and governed modes, export the graph, and inspect which transitions Morrison removed:

```bash
python -m morrison_governance.global_verification \
  --scenario secret_exfiltration \
  --compare-control \
  --export-json verification-result.json \
  --export-dot verification-graph.dot
```

Run the bounded perturbation matrix and composition experiment:

```bash
python -m morrison_governance.global_verification --perturbations
python -m morrison_governance.global_verification --composition-experiment
```

Verify the Safety Envelope and causal overlay regression suites directly:

```bash
python -m pytest \
  runtime_eval/tests/test_safety_envelope.py \
  runtime_eval/tests/test_safety_envelope_evidence.py \
  runtime_eval/tests/test_causal_overlay.py \
  -q
```

Technical guides:

- [Global Safety Verification Harness](GLOBAL_SAFETY_VERIFICATION.md)
- [Runtime evaluation, causal overlay, and Safety Envelope](runtime_eval/README.md)
- [Hosted Frontier Containment Harness](runtime_eval/frontier/README.md)
- [Deployment integrations](morrison_governance/DEPLOYMENT.md)

These paths test different claims. The browser and Frontier harness provide empirical trajectory evidence. The Safety Envelope produces a deployment-bounded assurance artifact. Global verification exhaustively enumerates only the declared finite model; it does not establish universal real-world AI safety.

---

## The core claim

Morrison is not positioned as a universal claim that an AI model is “safe.”

Its strongest enterprise result is narrower, testable, and deployment-specific:

> **Morrison has established and validated a local Safety Envelope for this specific autonomous workflow, in this specific environment, under these tools, permissions, policies, and reachable states.**

That statement is intentionally bounded to the evaluated deployment configuration. It is supported by trajectory evidence, reachable-state analysis, governance decisions, environment context, and the documented limits of the evaluation.

---

## What is a local Safety Envelope?

Safety-critical engineering does not normally ask whether a complex system is simply “safe” in the abstract. It defines an operating region and the boundaries that must not be crossed.

The principle is familiar in:

- **Aviation** — flight envelopes define combinations of speed, load, altitude, and operating condition within which an aircraft is designed to operate.
- **Nuclear engineering** — facilities operate inside tightly controlled limits around temperature, pressure, cooling, power, and system state.
- **Industrial robotics & process control** — operating envelopes constrain motion, force, speed, pressure, temperature, and other process variables.

Morrison applies the same engineering idea to autonomous AI.

> **A local Safety Envelope is the environment-bounded region within which an autonomous system has been evaluated as locally admissible under the tools, permissions, policies, workflows, state, and reachable consequences present in that deployment.**

Ω remains the configured forbidden region. The Safety Envelope is broader: it describes the region in which operation is locally admissible, where the boundary sits, and what must happen when a proposed trajectory leaves it.

---

## Why this matters now

Autonomous agents are no longer just generating text. They can move money, read secrets, write files, call APIs, modify repositories, operate security tooling, and coordinate across multi-agent workflows.

Prompts, permissions, and policies do not enforce themselves at the moment an AI system acts.

A sequence can become unsafe even when every individual step looks acceptable in isolation:

- authorised data access → aggregation → prohibited exfiltration
- permitted finance actions → unsafe transfer sequence
- valid healthcare access → PHI exposure or unsafe downstream action
- normal shell operations → privilege escalation or destructive execution
- separately safe multi-agent actions → jointly unsafe outcome

The problem is therefore not only:

> *Is this individual action allowed?*

It is:

> **Does this proposed trajectory remain inside the locally validated operating envelope of this deployment?**

---

## What Morrison does

Morrison sits between an AI planner and the real execution surface.

For each proposed trajectory, it evaluates whether the next state remains locally admissible under the deployment's defined constraints and reachable-state model.

It returns:

**ALLOW · ESCALATE · BLOCK**

before side effects occur.

```mermaid
flowchart LR
    A[Autonomous AI / Agent] --> T[Proposed trajectory]
    T --> M[Morrison Runtime Governance]
    M --> E[Local Safety Envelope evaluation]
    E -->|ALLOW| X[Execute]
    E -->|ESCALATE| H[Human / Policy Review]
    E -->|BLOCK| B[Prevent + Evidence]
```

The planner can change. The model can change. The governance invariant remains external to the model.

---

## Safety geometry

```text
Locally admissible trajectory ⇔ ℛ(t) remains inside the validated Safety Envelope
Forbidden reachability ⇔ ℛ(t) ∩ Ω ≠ ∅
```

Where:

- **ℛ(t)** is the set of reachable states from the current trajectory and environment.
- **Ω** is the configured forbidden region.
- the **local Safety Envelope** is the bounded operating region in which the evaluated deployment remains locally admissible.

This makes the claim operational rather than rhetorical: safe operation is tied to a specific environment and a specific reachable-state boundary.

---

## What makes the approach different

### Environment-specific
The claim is tied to the actual deployment: its tools, permissions, policies, workflows, state, and reachable consequences.

### Trajectory-level
Morrison evaluates the path through the system, not only the latest prompt, output, or individual tool call.

### Pre-execution
The governance decision occurs before the proposed action reaches the real execution surface.

### Bounded evidence
Morrison records what was evaluated, which envelope and constraints applied, what was allowed, escalated, or blocked, and the limits of the local safety claim.

### Model-agnostic
The governance layer sits outside the model and does not require model retraining or access to model weights.

---

## Current technical evidence

| Metric | Current state |
|---|---:|
| Governance evaluations | **129,857** |
| Repository test suite | **1,092 passing · 7 environment-dependent skips** |
| Runtime posture | **Fail-closed** |
| Governance level | **Pre-execution** |
| Model dependence | **Model-agnostic middleware** |
| Patent | **GB2600765.8** |

Validation work spans finance, cybersecurity, healthcare, data privacy, enterprise systems, multi-step trajectories, delayed intent, chained-tool behaviour, adversarial cases, and multi-agent paths.

These are bounded evaluation results, not a universal claim that every model or deployment is globally safe.

---

## Enforcement stack

```text
A_safe ⊂ V₂ ⊂ V₃ ⊂ V₄ ⊂ V₄⁺ ⊂ V₅ ⊂ V₅⁺
```

| Layer | Core question |
|---|---|
| **A_safe** | Is the current step directly forbidden? |
| **V₂** | Is the trajectory drifting toward the Safety Envelope boundary? |
| **V₃** | Is the trajectory forecast to leave the envelope or reach Ω? |
| **V₄ / V₄⁺** | Does a locally admissible state or trajectory remain constructible? |
| **V₅ / V₅⁺** | Does the local safety property survive perturbation and adversarial assumption attack? |

---

## What a deployment should be able to show

A useful enterprise result should not end with a generic “safe / unsafe” label.

It should expose the scope of the claim:

- **Autonomous workflow** evaluated
- **Model / agent configuration**
- **Connected tools and APIs**
- **Permissions and trust boundaries**
- **Policies and constraints**
- **Reachability horizon / state model**
- **Ω definition**
- **Inside-envelope trajectories**
- **Boundary violations**
- **ALLOW / ESCALATE / BLOCK evidence**
- **Known limitations and untested conditions**

A deployment-level conclusion can then be stated clearly:

> **Morrison has established and validated a local Safety Envelope for this specific autonomous workflow, in this specific environment, under these tools, permissions, policies, and reachable states.**

That is the assurance artifact Morrison is designed to produce and enforce.

---

## Integration surface

Morrison is designed to sit at the action boundary across agent frameworks and enterprise workflows, including:

- OpenAI tool/function calling
- Anthropic / Claude tool use
- LangChain / LangGraph-style orchestration
- AutoGen
- MCP
- browser agents
- shell / subprocess execution
- custom enterprise workflows

```mermaid
flowchart LR
    P[Planner / Agent] --> G[Morrison Runtime Governance]
    G -->|Inside envelope| T[Tools / APIs / Infrastructure]
    G -->|Boundary uncertain| H[Escalation]
    G -->|Outside envelope| B[Block + Evidence]
```

---

## Causal analysis overlay

Morrison's canonical runtime decision remains separate from the additive Structural Causal Model (SCM)-based causal-analysis overlay.

The runtime layer asks:

> **What became reachable, and may this trajectory execute?**

The causal overlay asks:

- Why was the Safety Envelope boundary reachable?
- Which variables materially contributed to that reachability?
- What intervention would have broken the trajectory?
- Would Ω still have been reachable if permission, safeguard state, approval, or another causal parent had changed?

> **Dynamics asks how the system moved and what became reachable.**  
> **Structural causal modelling asks what would have changed the outcome.**

The overlay is non-authoritative with respect to Morrison's canonical **ALLOW / ESCALATE / BLOCK** decision.

---

## Enterprise evaluation path

The commercial entry point is no longer only “find catastrophic actions.”

It is to establish the deployment's local operating boundary and prove where autonomous operation remains admissible.

### Safety Envelope Assessment
A bounded assessment of the deployment's architecture, tools, permissions, policies, reachable states, and constraints.

### Shadow Mode / Limited Pilot
Observe live or sandboxed trajectories without enforcing, and show which remain inside the envelope, approach the boundary, or would leave it.

### Guarded / Enforced Pilot
Apply **ALLOW / ESCALATE / BLOCK** before execution and preserve evidence of every governed decision.

### Enterprise Integration
Continuously revalidate the Safety Envelope as models, tools, permissions, workflows, and policies change.

The target proof is explicit:

> **Morrison has established and validated a local Safety Envelope for this specific autonomous workflow, in this specific environment, under these tools, permissions, policies, and reachable states.**

---

## Bounded claim discipline

Morrison does **not** claim:

- that an underlying model is globally safe;
- that untested environments inherit the same envelope;
- that a past validation remains valid after material changes to tools, permissions, policies, model behaviour, or workflow structure;
- that local safety evidence eliminates all residual risk.

Instead, Morrison makes a narrower claim that can be tested, enforced, and audited:

> **For this evaluated deployment, under this specified environment and constraint set, these trajectories were established as locally admissible, these boundary violations were identified, and runtime governance enforced the resulting Safety Envelope before execution.**

---

## Enterprise risk coverage

The current evaluation surface includes classes such as:

- unauthorised financial execution
- credential / secret exfiltration
- shell injection / RCE
- privilege escalation
- path traversal / sandbox escape
- PII / PHI leakage
- chained and delayed multi-step attacks
- multi-agent collusion and cross-agent delayed intent
- malformed or semantically disguised tool calls
- encoded payloads and nested delegation
- long-horizon agent drift
- environment-sensitive safety under perturbation
- replay and evidence ambiguity
- schema-malformation bypass
- cross-domain Ω reachability
- stochastic planner divergence

Detailed implementation and evaluation artefacts live throughout this repository.

---

## The positioning in one sentence

> **See the Safety Envelope your AI can actually operate within — in your environment, before actions execute.**

---

<div align="center">

### Resurrection Tech Ltd

**Local Safety Envelopes for autonomous AI · Runtime governance before execution · Evidence after every decision**

[Website](https://resurrection-tech.com) · [GitHub](https://github.com/davarntrades) · [LinkedIn](https://www.linkedin.com/in/davarn-morrison-14b93b263) · [Email](mailto:davarn@resurrection-tech.com)

</div>

## Technical Presentation Website

A Gamma-style single-page technical presentation site is available in [`presentation-site/`](presentation-site/).

```bash
cd presentation-site
npm install
npm run dev
```

For export/screenshot instructions and environment-specific validation notes (including restricted-registry install failure context), see [`presentation-site/README.md`](presentation-site/README.md).
