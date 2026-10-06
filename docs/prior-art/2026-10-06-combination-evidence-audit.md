# Combination evidence audit — 6 October 2026

**Examined repository:** `297e23c30949e7e6e15b3d7fb7376468f6a89d58`. Technical assessment, not a legal opinion. This audit corrects the strength of the combination argument without changing runtime code or silently removing previous analysis. PDF work is paused pending the user's review.

## 1. Correction and timeline gate

The statement that the stronger combination is autonomous-agent shielding plus proof-gated authorization, with only a concrete consistency bridge remaining, is **unsupported as an established pre-priority inventive-step case**. It describes a candidate synthesis. It does not establish a short bridge, historical motivation, predictable success or complete disclosure.

Morrison's claim-specific priority date and priority-supporting disclosure have not been verified. Consequently none of the following is labelled unconditionally qualifying pre-priority art. A dated paper also does not by itself establish every jurisdiction's qualification requirements.

| Reference | Verified date and version | Timeline qualification |
|---|---|---|
| Alshiekh, Bloem, Ehlers, Könighofer, Niekum, Topcu, *Safe Reinforcement Learning via Shielding* | arXiv v1 submitted 29 August 2017; v2 3 September 2017; subsequent AAAI 2018 paper cited by MARL | v1 passages inspected; conditional on relevant Morrison priority being later and applicable availability requirements. Do not backdate subsequent revisions. |
| ElSayed-Aly, Bharadwaj, Amato, Ehlers, Topcu, Feng, *Safe Multi-Agent Reinforcement Learning via Shielding* | arXiv v1 submitted 27 January 2021; v2 2 February 2021; v1 identifies AAMAS conference 3–7 May 2021 | v1 passages inspected; conditional on relevant priority later than its public submission. Conference dates are not substituted for precise proceedings release. |
| Bauer, Bowers, Pfenning, Reiter, *Consumable Credentials in Logic-Based Access Control*, CMU-CyLab-06-002 | cover dated 10 February 2006 | Report date verified. Independent contemporaneous public-release evidence not established in this audit; Morrison priority also unresolved. The 2007 successor cannot fill or backdate gaps. |

No patent filing or patent priority dates attach to these paper dates. Current source accessibility and download date are not historical publication dates.

## 2. Primary passage register

Page locators for shield papers refer to the inspected arXiv v1 PDF pages, not the later proceedings pagination. C06 locators are printed pages; add one for PDF viewer numbering.

### RL2017: real autonomous-agent antecedent

Sections 4 (PDF pp. 6–8) and 5.2 (PDF p. 11, Fig. 7) describe an RL learner proposing an action, a separate post-posed shield forwarding or substituting it, and the environment executing the shield output. The safety-game construction considers future forced unsafe states, not merely action arguments. Assumption 1 (PDF p. 9) requires an MDP, an environment abstraction and learner access to combined state.

**Mapping:** E1 explicitly disclosed; finite safety-game/abstraction component of E2 explicitly disclosed; stateful temporal safety machinery relevant to E4 explicitly disclosed, but a *separate local/global pair* is not established. E6 logical component separation and E7 mediation in the specified loop explicitly disclosed; security-isolated authority and complete real effect mediation are not established. Shield-output dependence is explicit and can supply E8 in the stated loop if the shield output is the authorization. A separate proof/permit check at a resource boundary requires adaptation; cryptography is not an added requirement of E8. No E9/E10 complete decision evidence established. An enabled action in an MDP is not thereby a separately adjudicated local ALLOW.

### MARL2021: proposed main autonomous reference

Section 3 (PDF pp. 2–3) defines agents, finite joint state and transition model, LTL safety automata and safety games. Section 4 (PDF pp. 3–4), Fig. 1 and Algorithm 1 specify agents selecting a joint action, the shield correcting unsafe proposals, and the environment receiving its output. The shield combines an environment-abstraction DFA and a specification DFA and restricts outputs to the safety game's winning region.

**Mapping:** E1 and E2 explicitly disclosed. Joint/temporal safety logic is explicit; the separate E3/E4 adjudication pair and E5 local-ALLOW/global-BLOCK witness are not established by these passages. Membership in an action set, or simultaneous individual choices, cannot substitute for a separate local admissibility decision. Section 5's factored shields are not automatically local checks followed by an independent global check: central and factored architectures are presented as approaches. E6 logical separation and E7 specified-loop mediation explicit; isolated independent authority and unavoidable external effects not established. E8 shield-output dependence is explicit in the specified loop; proof/permit dependence at a separate resource boundary requires adaptation, and E8 does not itself require a signed permit. E9/E10 not established. Section 6 supplies author-reported benchmark experiments, not a reproduction of the complete combined target.

### C06: authorization and consumption components

Section 3.1 (printed p. 5) represents actions with parameters and nonce. Section 3.3 (pp. 7–9) distinguishes linear proof checking from global credential-consumption coordination, defines Bounded Use and boxes ratified proofs. This is real local/global resource machinery, not generic logging. Its bounded consumption condition is not a disclosed bounded autonomous-agent environment.

Section 4 (pp. 10–12) binds consent to credential statement F, proof M and goal G; the client sends the boxed proof and the resource monitor grants access after verification. Section 5 (pp. 12–14) refines atomic ratification to avoid consumption when access fails. These are substantive protocol contributions, not merely suggested future work.

**Mapping:** generic authorization independent of a client, proof gating, local/global consumption and proof-bound consent explicitly disclosed. Their use for the specified autonomous-agent architecture is **ANALOGOUS BUT REQUIRES ADAPTATION**, as the earlier correction records. E1 and complete E10 are **NOT ESTABLISHED**. Full semantic trajectory, current ruleset/state version and executed transition are not established as one binding. The report's atomic ratification must not be equated with atomic execution of an arbitrary governed external effect.

No element is classified NECESSARILY INHERENT just because a proposed integration could supply it.

## 3. Smallest concrete candidate and remaining elements

The candidate is MARL2021 + C06. RL2017 explains MARL's actual lineage. It is not needed as a third ingredient. Adding Schneider, escrow or logging without an evidenced architecture does not complete this candidate by accumulation.

| Target element | After juxtaposing the references | What still must be supplied |
|---|---|---|
| E1 autonomous proposals | EXPLICITLY DISCLOSED by MARL | Adapt its output to a proof-authorized resource request. |
| E2 bounded agent environment | EXPLICITLY DISCLOSED by MARL's finite model | Show the authorized action's effects stay within that same model. |
| E3 local check | ANALOGOUS BUT REQUIRES ADAPTATION from C06 proof checking | Define local admissibility for the identical proposed agent transition. |
| E4 separate global/trajectory check | ANALOGOUS BUT REQUIRES ADAPTATION for integrated pair | Couple temporal game state to the same local decision; do not substitute resource use counts for semantic trajectory. |
| E5 local ALLOW/global BLOCK | NOT ESTABLISHED for combined target | Exhibit an action passing the defined local predicate and blocked by the distinct global predicate. |
| E6 independent authority | ANALOGOUS BUT REQUIRES ADAPTATION for combined authority | Give shield/monitor exclusive effect authority; logical separation alone does not establish isolation or custody. |
| E7 unavoidable pre-execution mediation | ANALOGOUS BUT REQUIRES ADAPTATION across combined boundary | Ensure all governed effects use the monitor and cannot bypass the shield. |
| E8 valid-authorization execution dependence | ANALOGOUS BUT REQUIRES ADAPTATION | Resource accepts only authorization for the exact shield-adjudicated action and relevant state. |
| E9 decision-bound evidence | ANALOGOUS BUT REQUIRES ADAPTATION | Bind shield verdict to authorization proof, not merely attach a later audit event. |
| E10 action + rules/state + trajectory evidence | NOT ESTABLISHED | Specify and validate one binding over these items and the executed transition. |

The adaptations are proposed by this review; neither paper discloses that integrated architecture. Additional reserved/denied semantic-state updates and strictest-verdict semantics are not supplied automatically by credential consumption, punishment rewards or factored shields.

## 4. Motivation: positive evidence and evidentiary limit

MARL introduction and Section 2 motivate shielding by unsafe exploration, emergent joint-agent safety and insufficient reward-only enforcement. Its actual citations link RL2018 and shield synthesis to multi-agent safety. That is contemporaneous evidence of motivation for **RL + reactive safety synthesis**; it is not evidence for **shield + proof-carrying authorization**.

C06 introduction (printed pp. 1–2) motivates combining job safety proofs with payment commitment and enforcing globally consumable credentials despite copying, failure and misbehavior. Sections 3.3 and 5 directly motivate global accounting and atomicity. This is evidence for proof-based distributed resource authorization. It does not identify autonomous learners or the shield integration proposed here.

The inspected papers' citation lists and targeted searches for shield/consumable-credential and shield/proof-carrying-authorization links did not establish a contemporaneous proposal for this pair. Search included both available search engines on 6 October 2026; later convergence and secondary summaries were excluded as motivation evidence. This is a search limitation, not proof that no such teaching exists.

A shared desire for safety is too general to establish this bridge. A qualifying security-critical autonomous deployment needing both consumption-limited distributed authority and temporal shielding, together with a documented technical reason to connect them, would materially strengthen the case. No such dated source has been verified here.

## 5. Assembly versus missing protocol

Ordinary-looking interface work includes serializing an action, transporting a proof, forwarding shield output and handling a failed request. Calling those steps ordinary is an engineering assessment, not a dated obviousness finding.

The load-bearing obligations are: (a) define two predicates on the same transition, (b) soundly map tool effects into the bounded model, (c) validate current policy and history when authority is redeemed, (d) serialize or safely compose concurrent reservations, (e) prevent released/expired authority from causing unaccounted effects, (f) recover durable safety state consistently with resource effects, and (g) bind evidence to all relevant decision inputs. They remain unestablished for this combination. The inspected sources do not prove these obligations need invention, nor that they are routine integration. C06 already contributes consumption coordination and atomic ratification; credit those mechanisms without expanding their scope.

The phrase “remaining bridge is concrete” can mean these are identifiable design obligations. It cannot mean a historical protocol, predictable success or a short motivated assembly has been demonstrated.

## 6. Three separate conclusions

**Single-reference anticipation:** No single reference has yet been verified as disclosing the complete narrow combination. Qualifying earlier disclosure remains unresolved. C06's withdrawn complete-match finding remains withdrawn.

**Combination/inventive-step pressure:** Autonomous shields plus proof-bound consumable authorization are a concrete component combination candidate requiring adaptation. The currently inspected record does not establish qualifying pre-priority status, motivation to combine, complete integrated mapping or that the residue is routine. It also does not establish non-obviousness.

**Later 2026 specification convergence:** PACE, Provenact/MasuGate, L-DREA, Controlled Agentic AI Systems, ActPlane, KedgeFlow and the identified 2026 patent publications remain separately dated candidates. They cannot retrospectively supply earlier motivation or fill earlier references' gaps. Their priority/filing/publication and disclosure-versus-demonstration questions remain separate; this audit makes no new complete-match finding for them.

Morrison's lease/reservation trace and seven finite models with all-PERMIT unsafe paths are unaffected. They test Morrison's implementation, not historical motivation. No PDF rebuilding or runtime modification was performed in this audit.

## Primary sources

- [RL2017 v1](https://arxiv.org/pdf/1708.08611v1), [version dates](https://arxiv.org/abs/1708.08611).
- [MARL2021 v1](https://arxiv.org/pdf/2101.11196v1), [version dates](https://arxiv.org/abs/2101.11196); [author-hosted paper](https://www.cs.virginia.edu/~lufeng/papers/aamas2021.pdf) inspected as corroboration, not used to backdate revisions.
- [C06 original report](https://www.cs.cmu.edu/~fp/papers/CMU-CYLAB-06-002.pdf).
- [Previous C06 correction](2026-10-06-consumable-credentials-correction.md); [previous main position](history/2026-10-06-before-combination-audit.md); [historical adversarial review](2026-10-05-adversarial-review.md).
