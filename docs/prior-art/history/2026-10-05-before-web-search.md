# Prior Art & Novelty Position — Morrison Runtime Governance

**Updated:** 5 October 2026  
**Status:** Internal technical-positioning analysis for counsel and independent falsification. Not legal advice or a patentability opinion.  
**Primary analysis:** *Adversarial Prior-Art Analysis — Local–Global Admissible Operating Envelope Enforcement* (2 October 2026), covering patents, academic literature, standards, open-source systems and deployed architectures from 1972–2026.

---

## Executive position

Morrison should not claim novelty for runtime enforcement, policy engines, reference monitors, safe sets, reachability, shielding, runtime monitoring, tool-call validation, information-flow controls, pre-execution blocking, or audit logging individually. Each has substantial prior art.

The current search supports a narrower and more technically important position:

> **We have not identified prior work demonstrating local and global admissibility combined with unavoidable execution authority in a general-purpose AI-agent environment.**

This is a result of the search, **not a universal claim**. A single qualifying reference could overturn it.

The strongest Morrison position is therefore **local + global safety for autonomous systems**, implemented as a bounded runtime-governance architecture in which:

1. a bounded **Admissible Operating Envelope (AOE)** is defined;
2. local admissibility is evaluated at the individual action / transition boundary;
3. global admissibility is evaluated separately over composed state / trajectory;
4. a sequence of individually admissible transitions is prevented from reaching a globally inadmissible state through the governed path;
5. governance is separated from the model or agent;
6. authority is exercised before execution through **PERMIT / ESCALATE / BLOCK** (or equivalent ALLOW / ESCALATE / BLOCK semantics);
7. evidence binds the decision to action identity, ruleset and trajectory state.

The novelty question is not whether these seven ideas each existed. They did. The question is whether the **claimed combination, authority placement and evidence semantics** were disclosed together before the relevant priority date.

---

## 1. The claim tested

| # | Claimed element |
|---|---|
| 1 | Defines a bounded Admissible Operating Envelope (AOE) for an AI/agent system |
| 2 | Evaluates and enforces local admissibility at individual execution boundaries, actions, agents, components or transitions |
| 3 | Separately evaluates and enforces global admissibility of the composed system state or execution trajectory |
| 4 | Prevents a sequence of individually admissible transitions from reaching a globally inadmissible state through the governed path |
| 5 | Places enforcement at an independent runtime authority, not solely in the model or agent |
| 6 | Exercises authority before execution, with veto/block or escalation |
| 7 | Produces evidence showing whether local and global execution stayed within the AOE |

**Element 4 is central:** individually admissible transitions must not compose into a globally inadmissible state.

---

## 2. Authority classes

The prior-art analysis separates systems by architecture rather than marketing terminology.

### K — Kernel / reference monitor
Sits on the execution path and controls the only credential, OS/network route or executor. The governed action cannot occur through that path without authorization, and the agent cannot override the verdict.

### H — Hybrid
Makes and applies a decision inside the agent process, framework or proxy. It has kernel authority only when deployment guarantees complete mediation.

### G — Guardrail
Filters, classifies, monitors, advises or returns a policy verdict. Another component ultimately decides whether execution occurs.

This distinction matters. A component being described as able to “block” or “enforce” does not establish execution authority. **Representation of authority is not authority.**

---

## 3. Prior-art result

### No single pre-priority reference identified with all seven elements

The search found no single pre-priority reference disclosing all seven claimed elements together.

However, the individual elements and many combinations are old and well established. Strong references include:

- Schneider (2000) and Ligatti, Bauer & Walker (2005): step-by-step pre-execution enforcement of trace/security properties.
- NCSC TNI (1987) + TCSEC audit: global policy partitioned into component reference monitors with mandatory mediation/audit.
- Simplex / ASTM F3269: runtime assurance and switching before leaving a safety envelope.
- ModelPlex: per-step monitoring connected to trajectory safety.
- Alshiekh et al. (2018): preemptive shielding.
- ElSayed-Aly et al. (2021): local/factored and centralized/global multi-agent shields.
- Mehmood et al. (2020/21): per-agent runtime assurance composing to global multi-agent safety.
- CaMeL and Invariant Guardrails (2025): agent/tool-call and cross-call/flow controls, but with deployment-dependent authority.

Therefore, broad claims such as “invented runtime safety,” “invented pre-execution blocking,” or “invented local/global safety” are not defensible.

---

## 4. Strong obviousness pressure

No anticipation was identified in the search, but a **strong obviousness combination exists**.

A particularly strong combination is:

- an established reference monitor / runtime enforcement mechanism;
- local + global or history-aware policy;
- reservation/pending-state treatment;
- decision logging and tamper-evident evidence.

Payment-card authorization is especially damaging to broad claims because systems documented from the 1990s already combine per-transaction checks with cumulative/velocity checks, count pending holds, can count declined attempts, and log authorization decisions.

The remaining distinction must therefore be framed around **semantic autonomous-agent trajectories, reachability, authority placement and evidence binding**, not generic “local + global checks.”

---

## 5. Residue after adversarial attack

The October analysis attacked the apparent residue rather than stopping after the first novelty-positive search.

The most defensible remaining features are:

1. **Denied actions as semantic trajectory state** — a refused action can alter later admissibility, rather than merely incrementing a rate counter.
2. **Reservation-aware global checks over general autonomous-agent actions** — pending/reserved transitions participate in a reachability-style global decision before execution.
3. **Two verdicts in one authority** — a local check and a separate global reachability/environment-state check, with the strictest applicable verdict controlling execution.
4. **Evidence bound to the decision** — action identity, ruleset version and trajectory state are bound into the decision/evidence object.
5. **Exhaustive environment-state verification** in a declared finite bounded environment, rather than only sampled benchmark trajectories.

The report found no single pre-2026 document combining the targeted local/global decision, reservation/denial-aware semantic trajectory and bound evidence in one general-agent decision path. But this residue is **thin and application-specific**, and obviousness remains a serious issue.

---

## 6. General-purpose AI-agent comparison

Public systems reviewed include CaMeL, FIDES, Agent-C, FORGE, ContrAgent, AgentLTL, CaMeLoT, Pro2Guard, AgentSpec, Progent, Invariant Guardrails, ShieldAgent and QuadSentinel.

Several demonstrate trajectory-level decision logic for bounded property classes:

- information flow;
- temporal ordering;
- history-dependent multi-agent rules;
- cross-call flows.

The important remaining authority distinction is:

> Systems reviewed that reason over trajectories generally run inside the agent process/framework or depend on proxy routing; systems with unavoidable execution authority generally enforce capabilities or per-call requests rather than a separate local + global semantic trajectory decision.

The search therefore did **not** support “nobody else has local/global safety logic.” It supported the narrower finding that the reviewed work did not combine that logic with unavoidable execution authority in a general-purpose AI-agent environment.

---

## 7. Closest authority-side systems

The closest systems with strong execution authority include:

- **aiAuthZ (2026):** credential broker keeps API secrets away from the agent; per-call authorization, but no identified trajectory/AOE semantics.
- **AWS AgentCore Gateway + Policy (2025–26):** intercepts agent-to-tool requests outside agent code and can hold backend credentials; per-call Cedar policy, no identified trajectory check.
- **ActPlane (2026):** OS/eBPF enforcement with history-dependent information flow; not semantic reachability over Ω.
- **Simplex / ASTM F3269:** authority over actuator selection and system-state envelope, but not general tool-using agents.
- **seL4 / reference-monitor architectures:** strong mediation and capability authority, but capability-level rather than Morrison's semantic transition model.

This is why the key Morrison question is not “can software block an action?” It is:

> **Can an independent runtime authority enforce both local and global admissibility over semantic autonomous-system trajectories before execution, with the relevant path completely mediated and the decision evidenced?**

---

## 8. Morrison's current authority status

Morrison must not overstate this.

The library's PDP + execution path is **hybrid unless the deployment satisfies complete mediation**. Resource-side lease verification is the route toward kernel-class authority, but Morrison's own analysis treats complete mediation as an open deployment assumption until it is independently tested.

A credible containment claim requires all three of the following to survive falsification:

### 1. AOE completeness
Did the bounded model include every relevant state and transition?

Failure: a relevant harmful state/transition exists outside the model or Ω.

### 2. Decision soundness
For transitions that reach Morrison, does it decide correctly against the AOE?

Failure: a transition that should be refused is permitted.

### 3. Mediation completeness
Can any relevant transition occur without Morrison-issued authority?

Failure: any bypass path exists through credentials, raw network access, another SDK/executor, or a compromised connector.

No amount of kernel decision testing establishes mediation completeness. It is a deployment property and must be tested in each environment.

---

## 9. What Morrison can defensibly say

### Primary technical positioning

> **Morrison Runtime Governance is designed to provide local and global safety for autonomous systems by separating proposal from execution authority and evaluating proposed transitions against both local and global admissibility conditions before execution.**

### Prior-art positioning

> **Our adversarial prior-art search did not identify prior work demonstrating local and global admissibility combined with unavoidable execution authority in a general-purpose AI-agent environment. This is a search result, not a universal claim, and we are actively seeking independent falsification.**

### Validation positioning

> **The next objective is independent stress testing of AOE completeness, decision soundness and mediation completeness in a bounded external deployment.**

---

## 10. What Morrison should not claim

Do not claim:

- Morrison invented runtime enforcement.
- Morrison invented safety envelopes / admissible regions.
- Morrison invented reachability.
- Morrison invented reference monitors.
- Morrison invented local/global safety as a general concept.
- Morrison is the first system to block tool calls before execution.
- Morrison already proves universal safety.
- Morrison currently has unavoidable authority in every deployment.
- No other company or research system has relevant prior art.

The stronger position is narrower and falsifiable.

---

## 11. 2026 references and priority-date sensitivity

The analysis identified several close 2026 publications:

- Open Agent Passport — deterministic pre-action authorization, fail-closed behavior and signed decision records.
- CAVA — canonical action hashes, approval binding and receipts.
- Proof of Execution — authorization/path/no-effect/history guarantees and attestation.
- Ray, *What Can Be Enforced?* — enforceability of multi-step policies by deterministic gates.
- ChainCaps / *One Gate Is Not Enough* — composition of locally acceptable calls into unsafe behavior.

Whether any of these are prior art depends on the confirmed priority date of the relevant Morrison filing. Their existence also demonstrates rapid convergence of the field and increases obviousness pressure.

---

## 12. Independent falsification target

The strongest external test is not “does Morrison look novel?” It is whether its claimed properties survive attempts to break them.

A bounded independent evaluation should test:

1. **AOE completeness** — search for unmodelled dimensions, states and transitions.
2. **Decision soundness** — adversarially search for false permits and incorrect escalation/block behavior.
3. **Local/global composition** — construct sequences where each transition is locally admissible but the composition reaches a globally inadmissible state.
4. **Reservation and denial semantics** — test whether pending and refused transitions correctly affect later admissibility.
5. **Mediation completeness** — attempt to reach protected resources without a valid Morrison-issued authorization.
6. **Evidence integrity** — verify that verdict, action identity, ruleset and trajectory state can be independently reconstructed and checked.
7. **Environment-state verification** — where the environment is finite, enumerate governed versus ungoverned reachable states.

A failed claim is useful evidence. The purpose of the programme is falsification, not confirmation.

---

## 13. Current novelty verdict

**Individual primitives:** established prior art.  
**Local + global safety logic:** established antecedents exist in runtime assurance, multi-agent shielding, workflow/security and control systems.  
**General-purpose AI-agent demonstrations:** trajectory-level bounded decision logic exists, generally with hybrid/deployment-dependent authority.  
**Unavoidable execution authority for AI agents:** deployed examples exist for capabilities and per-call authorization.  
**Combination not identified in this search:** local + global admissibility + semantic trajectory/reachability + unavoidable execution authority + bound evidence in a general-purpose AI-agent environment.  
**Obviousness risk:** strong.  
**Most defensible residue:** denial/reservation-aware semantic trajectories, separate local/global reachability verdicts in one pre-execution authority, exhaustive bounded environment-state verification, and decision-bound trajectory evidence.  
**Independent validation:** still required.

---

## 14. Recommended next steps

1. Confirm the priority date and claim allocation for each Morrison filing.
2. Obtain and review full text for the closest academic and patent references.
3. Commission professional full-text patent searches in the relevant classifications.
4. Continue attacking the remaining residue, especially payment authorization, Kubernetes admission/audit, information-flow taint and workflow reference monitors.
5. Centre any future claim work on the narrow residue rather than broad runtime-governance primitives.
6. Run a complete-mediation test in a real bounded deployment with resource-side authorization verification and default-deny bypass controls.
7. Commission an independent red team to attack AOE completeness and decision soundness.
8. Publish the falsification protocol separately from commercial positioning so external evaluators can reproduce the claimed properties.

---

## Interpretation rule

Morrison's credibility increases when the strongest prior art is stated precisely.

**The goal is not to claim that every ingredient is new. The goal is to identify exactly what combination remains unlocated, define it narrowly, and invite independent attempts to falsify it.**
