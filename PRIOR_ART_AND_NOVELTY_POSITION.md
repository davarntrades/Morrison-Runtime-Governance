# Prior Art & Novelty Position — Morrison Runtime Governance

**Date:** 24 August 2026  
**Status:** Internal technical-positioning audit — not a legal patentability opinion, not an exhaustive literature review  
**Question:** *How much of Morrison is unique versus known runtime-policy, control, formal-method, and agent-guardrail techniques assembled in a new way?*

---

## Executive answer

Morrison should **not** claim novelty for the individual ingredients of runtime enforcement, policy decision points, safe sets, reachability, shielding, runtime monitoring, tool-call validation, taint/information-flow ideas, or audit logging. Those all have substantial prior art.

The strongest defensible novelty position is narrower:

> **Morrison is an integrated runtime-assurance architecture for tool-using autonomous systems that combines trajectory-level pre-execution governance, bounded Admissible Operating Envelope claims over declared deployment conditions, explicit non-inheritance of assurance outside the tested envelope, provider-normalised execution mediation, and evidence/provenance around each canonical decision.**

That is best described today as a **distinct operational synthesis and assurance architecture** with potentially novel claim structure — not as proof that every underlying mathematical or enforcement primitive is new.

The most promising candidate for genuinely distinctive intellectual contribution is not “runtime blocking” by itself. It is the combination of:

1. **trajectory/reachability-based action governance at the agent-tool boundary**;
2. a **declared Admissible Operating Envelope** parameterised by real deployment configuration;
3. **OBSERVED LOCAL SAFETY vs UNVALIDATED** as an explicit epistemic state;
4. **no assurance inheritance** after material configuration change;
5. canonical runtime decisions kept separate from downstream causal/regulatory interpretation;
6. tamper-evident evidence supporting the bounded claim.

A full novelty determination would require deeper literature, product, patent, and code review by independent specialists. This document deliberately stops short of “first,” “unprecedented,” or formal patentability claims.

---

## 1. Comparison frame

Morrison sits near several mature traditions that must be acknowledged rather than collapsed into “ordinary AI guardrails”:

- runtime verification
- security automata / enforceable security policies
- reference-monitor / policy-decision-point architectures
- policy-as-code engines
- information-flow / taint tracking
- shielding / runtime enforcement
- reachability analysis
- invariant safe sets / control barrier functions
- AI-agent tool guardrails
- agent orchestration / approvals
- audit and decision logging

The question is therefore not whether Morrison has antecedents. It clearly does.

The useful question is:

> **What object is Morrison constructing that is not already supplied by any one of these neighbouring approaches?**

---

## 2. Prior-art family: runtime verification

### Established idea

Runtime verification is a mature field concerned with checking execution traces against specified properties while a system runs. The classic survey by Leucker & Schallhart distinguishes runtime verification from model checking and testing and discusses contract enforcement.

Reference:
- Martin Leucker & Christian Schallhart, **“A Brief Account of Runtime Verification”** (2009): https://doi.org/10.1016/j.jlap.2008.08.004

### Overlap with Morrison

- observes / evaluates runtime traces
- properties can be checked on execution prefixes
- can support enforcement or contract-like behaviour
- naturally produces trace-level evidence

### Difference / possible Morrison contribution

Morrison's stronger current positioning is not merely “monitor a property at runtime.” It attaches runtime decisions to a **deployment-scoped Admissible Operating Envelope** over tools, permissions, policies, planners, trust boundaries, horizon, and reachable states, with explicit status when that envelope no longer applies.

**Conclusion:** runtime verification is important prior art; “runtime monitoring” is not novel.

---

## 3. Prior-art family: enforceable security policies / security automata

### Established idea

The security-monitor literature asks which properties can be enforced by observing execution and aborting or otherwise mediating it. Schneider's security-automata work is foundational to this area, and later surveys explicitly describe traces as sequences of atomic actions and runtime monitors as enforcement mechanisms.

Reference:
- Survey: **“Which security policies are enforceable by runtime monitors?”** https://doi.org/10.1016/j.entcs.2012.01.014

### Overlap with Morrison

- execution mediation
- action sequence / trace as a first-class object
- stop/block capability
- policy external to the governed program/model

### Difference / possible Morrison contribution

Morrison applies that general enforcement logic to **agent-generated tool trajectories** with an explicit state/reachability representation and a bounded assurance envelope rather than only a policy language over traces.

**Conclusion:** “external monitor that can block execution” has strong prior art.

---

## 4. Prior-art family: policy engines / policy-as-code

### Established idea

Open Policy Agent (OPA) is a general-purpose policy engine that separates policy decision-making from enforcement. Applications submit structured data; OPA returns policy decisions. OPA also supports decision logs for auditing.

References:
- OPA documentation: https://www.openpolicyagent.org/docs
- OPA deployment / PDP-PEP model: https://www.openpolicyagent.org/docs/deploy
- OPA decision logs: https://www.openpolicyagent.org/docs/management-decision-logs

### Overlap with Morrison

- external policy decision point
- structured input
- policy separated from application/model
- low-latency runtime decision
- audit/decision logging
- can be deployed near enforcement points

### Difference / possible Morrison contribution

OPA is domain-general policy evaluation. It does not by itself define Morrison's specific machinery of:

- agent trajectory prefix evaluation,
- reachable forbidden regions Ω,
- declared Admissible Operating Envelope validity,
- assurance non-inheritance after configuration change,
- canonical agent execution evidence package.

Those could theoretically be implemented *using* a policy engine, which is why Morrison should not claim that externalised policy evaluation itself is novel.

**Conclusion:** policy-decision architecture is prior art; Morrison's claim must live above that layer.

---

## 5. Prior-art family: shield synthesis / runtime enforcement

### Established idea

Shield synthesis attaches a component to a system that monitors behaviour and corrects unsafe outputs at runtime so specified safety properties remain satisfied. Bloem et al. introduced shield synthesis for reactive systems; later work formalised variants and extensions.

References:
- R. Bloem et al., **“Shield Synthesis: Runtime Enforcement for Reactive Systems”**: https://arxiv.org/abs/1501.02573
- Extended open-access treatment: https://link.springer.com/article/10.1007/s10703-017-0276-9

### Overlap with Morrison

- external safety layer
- runtime intervention
- specified safety properties
- aim to prevent unsafe system output from becoming effective behaviour
- can be model-independent relative to the protected component

### Difference / possible Morrison contribution

Morrison currently does not synthesise a formally verified shield from a complete reactive-system specification. Its reachability and Admissible Operating Envelope are empirical/structural and deployment-scoped.

Where Morrison differs operationally is the application to **LLM/agent tool-use trajectories**, provider normalisation, enterprise execution surfaces, explicit tested-envelope status, and evidence/audit semantics.

**Conclusion:** “runtime shield” is not a new concept. Morrison should explicitly position itself as adjacent to, but less formally complete than, verified shield synthesis — while potentially more directly operationalised for heterogeneous agent-tool stacks.

---

## 6. Prior-art family: safe sets, invariance, control barrier functions

### Established idea

Control theory has long represented safety through state-space sets and invariance. Control Barrier Functions (CBFs) provide conditions under which a safe set remains forward invariant under control inputs.

Reference:
- A. D. Ames, X. Xu, J. W. Grizzle, P. Tabuada, **“Control Barrier Function Based Quadratic Programs for Safety Critical Systems”**: https://doi.org/10.1109/TAC.2016.2638961

The core established idea is:

```text
start inside a safe set
+ satisfy the required control condition
=> remain inside the safe set
```

### Overlap with Morrison

- safety represented geometrically / as a set
- unsafe/forbidden region
- state transitions and trajectories
- admissible control/action constraints
- boundary crossing as a meaningful safety event

### Difference / possible Morrison contribution

Morrison's Admissible Operating Envelope is not currently a CBF proof or a continuous-time invariant set. It is an **environment-bounded empirical assurance region** for an agentic deployment whose dimensions include software/organisational variables such as tools, permissions, planner, policy, trust boundary, and horizon.

**Conclusion:** safe-set/invariance geometry is established mathematics. Morrison's possible contribution is the translation and operationalisation of bounded admissible-operating-envelope semantics into agentic runtime governance, not invention of safe sets.

---

## 7. Prior-art family: reachability analysis

### Established idea

Reachability analysis asks which states a dynamical system can reach under its dynamics and constraints; Hamilton-Jacobi methods are a well-developed example used for safety and reach-avoid problems.

Recent work continues to use backward reachable sets/tubes and safety filters in autonomous systems, including real-time and learned variants.

Examples:
- Hamilton-Jacobi reachability for contingency planning: https://arxiv.org/abs/2603.26995
- Data-driven safe-set construction / reachability: https://arxiv.org/abs/2504.03233

### Overlap with Morrison

- reachable-state sets
- forbidden region Ω
- safety question framed as whether unsafe states are reachable
- horizon and environmental assumptions matter

### Difference / possible Morrison contribution

Morrison's reachability machinery is not equivalent to exhaustive HJ reachability over a known physical dynamics model. It uses a software/action-state abstraction over tool trajectories and organisational execution context.

**Conclusion:** reachability itself is not novel. The candidate novelty lies in the *agentic action-state representation, runtime insertion point, bounded assurance semantics, and evidence layer*.

---

## 8. Prior-art family: current AI-agent guardrails

### OpenAI Agents SDK

Current OpenAI Agents SDK documentation includes **tool input guardrails** that can run immediately before custom function-tool execution and reject or raise an exception. It also includes human approval, sessions, tracing, and multi-agent orchestration.

References:
- Guardrails: https://openai.github.io/openai-agents-python/guardrails/
- Agents SDK: https://openai.github.io/openai-agents-python/

Important overlap:

- pre-tool-execution checks
- block/reject semantics
- per-tool validation
- accumulated run data / tracing
- approval workflows

Important limitation relative to Morrison's stated scope:

The OpenAI tool-guardrail pipeline is SDK/tool-specific and documentation focuses on validation around custom function-tool calls. It does not itself present Morrison's declared Admissible Operating Envelope / reachability / non-inheritance assurance model.

### NVIDIA NeMo Guardrails

NeMo Guardrails has execution rails controlling tool/action invocations, and current IORails functionality can validate model-emitted tool calls before they reach the application. Its tool-call rails can fail closed on invalid names/arguments.

References:
- Tool calling: https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog/tool-calling
- Rail types / execution rails: https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/rail-types

Important overlap:

- execution rails around actions/tools
- input/output validation
- fail-closed tool-call validation
- external guardrail layer around LLM applications

Important difference:

NeMo's documented tool-call validation focuses heavily on declared tool/schema correctness and configurable rails. Morrison's stronger differentiated claim must therefore be **trajectory/reachability and assurance-envelope semantics**, not merely “we govern tool calls before execution.”

**Conclusion:** by 2026, pre-execution tool guardrails are clearly not unique. Any Morrison novelty claim that reduces to “blocks unsafe tool calls before they execute” is too broad.

---

## 9. Feature-by-feature novelty matrix

Legend:
- **Known** = substantial prior art exists
- **Differentiated** = known ingredients, but Morrison's particular operational combination is meaningfully distinct
- **Candidate novelty** = warrants deeper literature/patent review; do not call “first” yet

| Morrison element | Status | Reason |
|---|---|---|
| External pre-execution enforcement | **Known** | Security monitors, reference monitors, shields, policy engines |
| ALLOW / BLOCK decision | **Known** | Standard policy/runtime enforcement pattern |
| ESCALATE / human review | **Known** | Approval / HITL systems |
| Structured tool-call mediation | **Known** | Agent SDKs, NeMo, policy middleware |
| Fail-closed execution gate | **Known** | Standard safety/security design |
| Runtime trace evaluation | **Known** | Runtime verification |
| Audit / decision logging | **Known** | OPA and many governance systems |
| Hash-linked evidence | **Known primitive** | Hash chains / tamper-evident logs long established |
| Taint across action sequences | **Known family** | Information-flow / taint tracking |
| Reachability of forbidden states | **Known mathematics** | Reachability / safety verification |
| Safe / admissible state region | **Known mathematics** | Invariance / viability / barrier-function traditions |
| Provider-normalised governance boundary | **Differentiated** | Common adapter pattern, but directly applied to heterogeneous agent-tool governance |
| Full agent trajectory prefix as governance object | **Differentiated** | Stronger than isolated tool validation; adjacent to trace/runtime verification |
| Admissible Operating Envelope parameterised by tools + permissions + planner + trust boundaries + horizon | **Candidate novelty** | Specific assurance object may be distinctive; needs exhaustive review |
| OBSERVED LOCAL SAFETY vs UNVALIDATED | **Candidate novelty** | Explicit epistemic distinction around tested deployment envelope |
| No safety-claim inheritance outside declared envelope | **Candidate novelty** | Particularly strong assurance semantics; needs prior-art search |
| Canonical verdict separated from causal/regulatory overlays | **Differentiated** | Strong architecture/evidence discipline; individual pieces known |
| Runtime evidence package binding trajectory + decision + envelope context | **Differentiated / candidate novelty** | Integration may be distinctive even though logging is not |
| Shadow → Guarded Pilot → Enforced operational progression | **Known pattern / differentiated packaging** | Shadow/enforce deployment modes exist elsewhere |
| Causal Information Sufficiency programme | **Separate research programme** | Not established by runtime-governance prior art; requires its own literature audit |

---

## 10. The strongest candidate novelty: assurance non-inheritance

One of Morrison's most defensible differentiators is the refusal to let a safety claim silently transfer when the configuration changes.

A useful abstract formulation is:

```text
Let E = declared validated envelope
Let C = current deployment configuration
Let V(E, C) = whether C is inside validated conditions

if V(E, C) == true:
    bounded safety evidence may apply
else:
    status = UNVALIDATED
    no safety claim is inherited from E
```

This is stronger than a normal runtime rule saying “call allowed” or “call blocked.” It is a statement about the **validity domain of the assurance claim itself**.

That distinction should be formalised further because it may be more original than the low-level enforcement mechanism.

Potential research/legal-review phrase:

> **configuration-indexed runtime assurance with explicit non-inheritance across unsupported state-space / deployment-envelope changes**

Do not treat this phrase as a patent claim without professional review.

---

## 11. The second strong candidate: trajectory + envelope + evidence as one assurance object

Morrison can be framed as constructing an assurance object:

```text
A = (
    trajectory,
    environment/configuration,
    reachable-set estimate,
    forbidden region Ω,
    canonical decision,
    execution outcome,
    Admissible Operating Envelope status,
    provenance/evidence
)
```

The claim is then not:

```text
"model safe"
```

but something closer to:

```text
"under configuration C and evaluated horizon H,
trajectory τ was governed against Ω,
its execution outcome was controlled,
and the resulting local-safety claim is valid only inside E."
```

This integration of *what happened*, *what could be reached*, *what was allowed to execute*, and *where the claim remains valid* is the part worth testing against the literature most aggressively.

---

## 12. What Morrison should stop claiming or avoid claiming

Avoid unqualified statements such as:

- “Morrison invented runtime AI safety.”
- “Morrison invented operating envelopes.”
- “Morrison invented reachability-based safety.”
- “Morrison is the first pre-execution guardrail.”
- “No other system blocks tool calls before execution.”
- “Morrison formally proves autonomous systems safe.”
- “Morrison is a verified shield.”

Those claims are either false, too broad, or currently unsupported.

---

## 13. What Morrison can defensibly say now

A strong current positioning is:

> **Morrison Runtime Governance operationalises bounded runtime assurance for tool-using autonomous systems by governing normalised action trajectories before execution, evaluating reachable forbidden states under a declared deployment configuration, explicitly refusing to inherit safety claims outside the tested Admissible Operating Envelope, and preserving evidence around the canonical execution decision.**

Shorter version:

> **Morrison combines trajectory-level runtime control with configuration-bounded assurance: safe here under these tested conditions; unvalidated outside them.**

This acknowledges prior art while preserving the genuinely interesting contribution.

---

## 14. What would upgrade “distinct synthesis” to a stronger novelty claim?

### A. Exhaustive scholarly prior-art review

Search systematically across:

- runtime assurance
- Simplex architectures
- runtime verification
- shield synthesis
- predictive safety filters
- reachability-based safety
- AI control
- agent tool governance
- policy-as-code
- information-flow security
- safety cases / dynamic assurance cases
- autonomous-agent governance
- runtime monitors for LLM agents
- configuration-aware certification / assurance envelopes

### B. Patent landscape

Search granted/pending patents for:

- pre-execution AI-agent tool governance
- trajectory-level policy enforcement
- runtime reachability over agent actions
- admissible-operating-envelope validity over AI deployment configuration
- revalidation on tool/permission/planner changes
- evidence-bound runtime safety claims

### C. Formalise the claim boundary

Define mathematically:

- envelope dimensions,
- envelope membership,
- configuration equivalence,
- when assurance inheritance is permitted,
- when status must become UNVALIDATED,
- what evidence is necessary/sufficient for a local claim.

### D. Independent reproduction

A third party should implement the envelope semantics from the specification without using Morrison's implementation and compare outputs.

### E. Head-to-head benchmark

Compare Morrison against:

- isolated per-tool guardrails,
- a general policy engine,
- NeMo execution rails,
- an OpenAI Agents SDK tool-guardrail implementation,
- a trace/runtime-verification baseline.

Use trajectories where **every individual call is locally acceptable but the composition becomes unsafe**. This is where Morrison's trajectory thesis should either earn its differentiation or fail.

---

## 15. Recommended benchmark for the novelty claim

Create a held-out corpus with four classes:

### Class A — isolated forbidden calls

Any competent tool guardrail should catch these.

Expected result: Morrison should not claim differentiation here.

### Class B — schema/argument violations

Tool-schema validators should perform strongly.

Expected result: Morrison should not claim differentiation here either.

### Class C — safe individual calls, unsafe trajectory composition

Examples:

```text
read approved data
→ transform/store
→ external egress
```

or:

```text
read financial state
→ obtain/accumulate authority
→ excessive transfer
```

This is a key Morrison differentiation test.

### Class D — configuration change outside validated envelope

Change one of:

- tool set,
- permission set,
- planner,
- trust boundary,
- horizon,
- policy version.

Then ask whether each system continues to emit an assurance claim or explicitly withdraws it.

This is the key test for **assurance non-inheritance**.

---

## 16. Current novelty verdict

### Not novel by itself

- runtime enforcement
- policy mediation
- blocking tool calls
- safe sets
- reachability
- shielding
- audit logs
- fail-closed design

### Meaningfully differentiated

- provider-normalised trajectory governance for heterogeneous agent stacks
- whole-trajectory / prefix-aware policy evaluation at the execution boundary
- integration of reachability-style reasoning with enterprise agent-tool mediation
- canonical decision separated from analytical overlays
- evidence tied to the runtime governance event

### Strongest candidate novelty requiring deeper review

> **A configuration-indexed Admissible Operating Envelope for autonomous-agent runtime governance, with explicit assurance validity/non-inheritance semantics and evidence-bound pre-execution decisions.**

### Overall grade

**ENGINEERING SYNTHESIS: STRONG**  
**OPERATIONAL DIFFERENTIATION: STRONG**  
**THEORETICAL NOVELTY: NOT YET ESTABLISHED**  
**SPECIFIC ASSURANCE-SEMANTICS NOVELTY: PLAUSIBLE / REQUIRES EXHAUSTIVE REVIEW**  
**“FIRST IN THE WORLD” CLAIM: NOT SUPPORTED AT THIS STAGE**

---

## 17. Sources reviewed for this audit

### Morrison repository

- `README.md`
- `CRITICAL_EVALUATION.md`
- `morrison_governance/integrations.py`
- `runtime_eval/frontier/ARCHITECTURE.md`
- `runtime_eval/frontier/provider_registry.py`
- `runtime_eval/frontier/README.md`
- `runtime_eval/tests/test_frontier_containment.py`
- `living-boundary/README.md`

### External references

- Leucker & Schallhart, Runtime Verification: https://doi.org/10.1016/j.jlap.2008.08.004
- Runtime-monitor enforceability survey: https://doi.org/10.1016/j.entcs.2012.01.014
- Open Policy Agent: https://www.openpolicyagent.org/docs
- OPA deployment architecture: https://www.openpolicyagent.org/docs/deploy
- OPA decision logs: https://www.openpolicyagent.org/docs/management-decision-logs
- Bloem et al., Shield Synthesis: https://arxiv.org/abs/1501.02573
- Shield synthesis extended treatment: https://link.springer.com/article/10.1007/s10703-017-0276-9
- Ames et al., Control Barrier Functions: https://doi.org/10.1109/TAC.2016.2638961
- OpenAI Agents SDK guardrails: https://openai.github.io/openai-agents-python/guardrails/
- NVIDIA NeMo Guardrails tool calling: https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog/tool-calling
- NVIDIA NeMo execution rails: https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/rail-types

---

**Interpretation rule:** Morrison's credibility increases, not decreases, when known prior art is named precisely. The strongest claim is the one that survives comparison.
