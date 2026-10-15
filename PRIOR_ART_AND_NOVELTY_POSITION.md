# Prior Art & Novelty Position — Morrison Runtime Governance

**Updated:** 6 October 2026  
**Status:** Internal technical-positioning analysis for counsel and independent falsification. Not legal advice or a patentability opinion.  
**Primary analysis:** *Adversarial Prior-Art Analysis — Local–Global Admissible Operating Envelope Enforcement* (2 October 2026), covering patents, academic literature, standards, open-source systems and deployed architectures from 1972–2026.

---

**Scope correction (6 October 2026):** The Consumable Credentials “complete technical match” conclusion is **withdrawn for the autonomous-agent target**. The earlier review substituted generic clients, resource bounds and credential history for elements that required an actual architectural disclosure. See the [element-by-element correction](docs/prior-art/2026-10-06-consumable-credentials-correction.md). The [preceding main document](docs/prior-art/history/2026-10-06-before-agent-scope-correction.md), [second-pass review](docs/prior-art/2026-10-05-adversarial-review.md), [first supplement](docs/prior-art/2026-10-05-search-supplement.md) and earlier snapshots preserve the search history. The independent [Morrison reproduction](docs/prior-art/reproduce_adversarial_2026_10_05.py) and [results](docs/prior-art/2026-10-05-adversarial-results.json) are unaffected.

## Executive position

Morrison should not claim novelty for runtime enforcement, policy engines, reference monitors, safe sets, reachability, shielding, runtime monitoring, tool-call validation, information-flow controls, pre-execution blocking, or audit logging individually. Each has substantial prior art.

The current bounded search result is:

> **No single reference has yet been verified as disclosing the complete narrow autonomous-agent combination. The overall earlier-disclosure question remains unresolved. Consumable Credentials is component prior art and combination pressure, not a verified complete match.**

This is a bounded verification status, not an exhaustive negative finding. The earlier terminology-neutral ratings, including conditional complete-match claims for other references, cannot establish the exact autonomous-agent target without a fresh claim-specific mapping. Missing experiments do not negate disclosure; architectural intent does not establish demonstration.

The target being compared is **local + global safety for autonomous systems**, expressed as a bounded runtime-governance architecture in which:

1. a bounded **Admissible Operating Envelope (AOE)** is defined;
2. local admissibility is evaluated at the individual action / transition boundary;
3. global admissibility is evaluated separately over composed state / trajectory;
4. a sequence of individually admissible transitions is prevented from reaching a globally inadmissible state through the governed path;
5. governance is separated from the model or agent;
6. authority is exercised before execution through **PERMIT / ESCALATE / BLOCK** (or equivalent ALLOW / ESCALATE / BLOCK semantics);
7. decision-bound evidence is associated with the action, governing rules/state and relevant trajectory;
8. an autonomous decision-making component produces the proposed actions. A generic requester is not automatically such a component.

The novelty question is not whether these individual ideas each existed. They did. The question is whether the **claimed combination, authority placement and evidence semantics** were disclosed together before the relevant priority date.

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
| 7 | Produces decision-bound evidence associated with action, governing rules/state and relevant trajectory |
| 8 | Includes an autonomous decision-making component producing proposed actions |

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

This distinction matters. A component being described as able to “block” or “enforce” does not establish execution authority. **Representation of authority is not authority.** Classify the actual deployment boundary, not its packaging: a protected proxy or framework executor can be mandatory on a declared path, while calling software a kernel does not establish complete mediation. History-aware policy is compatible with any placement; authority and expressiveness are separate axes.

---

## 3. Prior-art result

### Disclosure question and current verification status

**The 2006 complete-match finding is withdrawn.** Its disclosed mechanisms remain relevant, but adaptation is not disclosure of the autonomous-agent combination. The 2007 successor cannot fill gaps in the 2006 reference or backdate later additions. Other complete-match assertions in the second pass are not adopted for the exact target until assessed against the corrected scope. Morrison's claim-specific priority and historical public availability remain separate questions.

Four questions must be answered independently:

1. **Prior-art/disclosure:** Does an earlier qualifying reference disclose the complete claimed combination?
2. **Demonstration:** Has a system actually demonstrated the complete property under its stated assumptions?
3. **Morrison demonstration:** What does this implementation establish, including counterexamples and deployment assumptions?
4. **Combination pressure:** What small set of earlier mechanisms could produce the target, and what integration remains?

A missing deployment experiment is not evidence of missing disclosure. Conversely, specifying an enforcement architecture does not establish that its complete property was demonstrated. The original search's stronger wording is retained in the historical snapshot, not adopted as a current legal conclusion.

However, the individual elements and many combinations are old and well established. Strong references include:

- Schneider (2000) and Ligatti, Bauer & Walker (2005): step-by-step pre-execution enforcement of trace/security properties.
- NCSC TNI (1987) + TCSEC audit: global policy partitioned into component reference monitors with mandatory mediation/audit.
- Simplex / ASTM F3269: runtime assurance and switching before leaving a safety envelope.
- ModelPlex: per-step monitoring connected to trajectory safety.
- Alshiekh et al. (2018): preemptive shielding.
- ElSayed-Aly et al. (2021): factored and centralized multi-agent shields; these alternatives do not alone establish separate local/global adjudication.
- Mehmood et al. (2020/21): per-agent runtime assurance composing to global multi-agent safety.
- CaMeL and Invariant Guardrails (2025): agent/tool-call and cross-call/flow controls, but with deployment-dependent authority.

Therefore, broad claims such as “invented runtime safety,” “invented pre-execution blocking,” or “invented local/global safety” are not defensible.

---

## 4. Combination pressure: candidate synthesis, not an established inventive-step case

**Correction dated 6 October 2026:** the earlier “particularly strong combination” and subsequent assertion that autonomous-agent shields plus proof-gated authorization leave a short, motivated consistency bridge overstated the inspected evidence. The [combination evidence audit](docs/prior-art/2026-10-06-combination-evidence-audit.md) is controlling. The [preceding position](docs/prior-art/history/2026-10-06-before-combination-audit.md) and earlier review remain preserved.

The smallest concrete candidate examined here is **Safe Multi-Agent Reinforcement Learning via Shielding (2021) + Consumable Credentials in Logic-Based Access Control (2006)**. The 2017 single-agent shield is its documented antecedent, not an additional necessary ingredient. This is a proposed synthesis, not an architecture disclosed in combination by those references.

The shield actually supplies autonomous proposals, a finite model, temporal/joint-state safety enforcement and a mandatory shield-output path in its stated mathematical architecture. Consumable Credentials actually supplies distributed consumption accounting and proof-bound authorization for resource access. Substituting that authorization protocol for the shield-to-environment interface requires adaptation. Separate local/global predicates for the same agent action, execution-side validation of the exact adjudicated transition, policy/history evidence binding and delay/concurrency/recovery consistency remain unestablished for the combined target.

Neither qualifying pre-priority status relative to Morrison's unverified claim-specific priority nor contemporaneous motivation to combine this pair has been established. The sources motivate their own mechanisms; that does not prove motivation for this synthesis. The remaining steps have not been shown to be either routine assembly or inventive contributions. Older monitors, escrow, payment authorization and policy composition remain component leads; the prior categorical payment-card claim is not carried forward as a verified agent-architecture comparison.

This correction does not establish non-obviousness. It withdraws an unsupported strength assessment and identifies the evidence needed to test the candidate.

---

## 5. Residue after adversarial attack

The October analysis attacked the apparent residue rather than stopping after the first novelty-positive search.

The narrower implementation features requiring continued comparison are:

1. **Denied actions as semantic trajectory state** — a refused action alters later admissibility. A counter qualifies if its value changes authorization; a count used only for logging does not.
2. **Reservation-aware global checks over general autonomous-agent actions** — pending/reserved transitions participate in a reachability-style global decision before execution.
3. **Two verdicts in one authority** — a local check and a separate global reachability/environment-state check, with the strictest applicable verdict controlling execution.
4. **Evidence bound to the decision** — action identity, ruleset version and trajectory state are bound into the decision/evidence object.
5. **Exhaustive environment-state verification** in a declared finite bounded environment, rather than only sampled benchmark trajectories.

The original report recorded that it had not located a single pre-2026 document combining these features. That is preserved as history, not adopted here. The new charts assess each narrower feature independently. For this review, action/rules-state/trajectory evidence belongs to the expressly stated target. Analogy cannot substitute for autonomous-agent architectural disclosure; this corrects the second pass rather than adding a device to exclude an inconvenient reference.

---

## 6. General-purpose AI-agent comparison

Public systems reviewed include CaMeL, FIDES, Agent-C, FORGE, ContrAgent, AgentLTL, CaMeLoT, Pro2Guard, AgentSpec, Progent, Invariant Guardrails, ShieldAgent and QuadSentinel.

Several demonstrate trajectory-level decision logic for bounded property classes:

- information flow;
- temporal ordering;
- history-dependent multi-agent rules;
- cross-call flows.

**Correction from the 5 October web search:** history-aware enforcement and OS-level authority can coexist. CamQuery performs provenance-based checks inside Linux security hooks before actions; ActPlane enforces cross-event information-flow and temporal rules at the OS boundary. Evaluating at each call does not imply evaluating only that call's arguments.

Authority placement and policy expressiveness must therefore be evaluated independently. Neither trajectory awareness nor framework/proxy packaging determines whether a protected deployment path is unavoidable.

The expanded comparison includes **PACE, Provenact/MasuGate, L-DREA, Controlled Agentic AI Systems, ActPlane, CamQuery and KedgeFlow**, plus **US20260127298A1 and US20260142827A1**. The [second-pass charts](docs/prior-art/2026-10-05-adversarial-review.md) retain useful mechanism comparisons, but their complete-target ratings are qualified by the [scope correction](docs/prior-art/2026-10-06-consumable-credentials-correction.md). Older references were traced backwards rather than excluded for lacking AI branding.

---

## 7. Closest authority-side systems

Relevant authority-side references include both implemented controls and specified architectures; their demonstration status must be checked separately:

- **aiAuthZ (2026):** credential broker keeps API secrets away from the agent; per-call authorization, but no identified trajectory/AOE semantics.
- **AWS AgentCore Gateway + Policy (2025–26):** intercepts agent-to-tool requests outside agent code and can hold backend credentials; per-call Cedar policy, no identified trajectory check.
- **ActPlane (2026):** OS/eBPF enforcement with history-dependent information flow and temporal gates. The exact separate local/global semantic-reachability and evidence combination is **not established from the inspected material**.
- **CamQuery (2018):** in-kernel whole-system provenance analysis before protected actions. Its userspace/distributed mode has a different prevention boundary; see the supplement.
- **PACE, Provenact/MasuGate, L-DREA and KedgeFlow:** additional authority-side architectural disclosures, with implementation and deployment qualifications assessed separately in the supplement.
- **Simplex / ASTM F3269:** authority over actuator selection and system-state envelope, but not general tool-using agents.
- **seL4 / reference-monitor architectures:** foundational mediation and capability authority. These categories do not impose a stateless-policy limit; the exact Morrison combination is not established from the previously inspected examples.

This is why the key Morrison question is not “can software block an action?” It is:

> **Can an independent runtime authority enforce both local and global admissibility over semantic autonomous-system trajectories before execution, with the relevant path completely mediated and the decision evidenced?**

---

## 8. Morrison's current authority status

Morrison must not overstate this.

The library's PDP + execution path is **hybrid unless the deployment satisfies complete mediation**. Resource-side lease verification is the route toward kernel-class authority, but Morrison's own analysis treats complete mediation as an open deployment assumption until it is independently tested.

**New implementation qualification:** authorization → lease minting → successful reservation release → resource-side redemption leaves the read absent from kernel history. The [recorded offline trace](docs/prior-art/2026-10-05-adversarial-results.json) then permits and mock-executes the external send that the control blocks. This is an execution-boundary/reservation-lifecycle gap, not just an omitted harm specification. Deployments must establish whether this public-API sequence is reachable. No runtime fix is included in this documentation commit.

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

> **No single reference has yet been verified as disclosing the complete narrow autonomous-agent combination. Earlier-disclosure status remains unresolved; this does not establish novelty or non-obviousness.**

### Demonstration positioning

> **External complete-property demonstration was not verified. Morrison's selected tests and finite models were rerun, including unsafe characterizations; an additional offline lease-path failure was reproduced. None establishes complete deployed safety.**

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

The supplement adds the requested nine reference entries and separates publication, filing and priority information. Relevance depends on the confirmed priority date and claim allocation of the relevant Morrison filing. Publication dates, filing dates, continuation-family dates and the dates of later documentation are not interchangeable.

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

## 13. Current search verdict

| Question | Current conclusion |
|---|---|
| Prior art | **Unresolved.** C06 complete match withdrawn; complete earlier autonomous-agent disclosure not verified by this correction. |
| Combination/obviousness pressure | MARL shielding (2021) plus Consumable Credentials (2006) is a concrete candidate synthesis requiring adaptation. Qualifying timeline, contemporaneous motivation, integrated local/global predicates, mediation and evidence/consistency protocol remain unestablished; see the combination evidence audit. |
| External demonstration | Complete property **not verified** here. Formal specification, prototype, simulation, production and independent reproduction remain separate. |
| Morrison demonstration | 134 selected tests passed; seven all-PERMIT unsafe finite-model counterexamples and a new lease-release composition failure reproduced. Complete deployed property not established. |

Primary citations, all element ratings, version/date qualifications, assumptions and reproduction commands are in the [adversarial review](docs/prior-art/2026-10-05-adversarial-review.md). Earlier evidence and conclusions remain in the historical snapshots, unchanged first supplement, original PDF and git history. The 6 October correction governs current interpretation.


---

## 14. Recommended next steps

1. Confirm the priority date and claim allocation for each Morrison filing.
2. Resolve the explicit claim-construction and historical-publication questions for the candidate references; follow the remaining full-text leads in the new review.
3. Commission professional full-text patent searches in the relevant classifications.
4. Continue attacking the remaining residue, especially payment authorization, Kubernetes admission/audit, information-flow taint and workflow reference monitors.
5. Assess any proposed residue against the updated charts; do not assume it survives.
6. Reproduce the lease-release failure across a real isolated gateway, then test all reservation, redemption, cancellation and recovery interleavings.
7. Commission an independent red team to attack AOE completeness and decision soundness.
8. Publish the falsification protocol separately from commercial positioning so external evaluators can reproduce the claimed properties.

---

## Interpretation rule

Morrison's credibility increases when the strongest prior art is stated precisely.

**The goal is to determine which claims survive evidence and which fail, without treating an unlocated reference or an intended architecture as proof.**
