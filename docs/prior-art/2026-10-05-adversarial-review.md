# Adversarial disclosure and demonstration review — 5 October 2026

> **Combination assessment qualification, 6 October 2026:** subsequent evidence audit withdraws an established strong/short motivated combination characterization. Component mechanisms remain relevant; qualifying timeline, contemporaneous motivation and integrated target remain unestablished. See [controlling combination audit](2026-10-06-combination-evidence-audit.md). Earlier text is preserved as search history.

> **Correction dated 6 October 2026 — historical analysis below:** The C06/C07 “complete technical match” and one-reference sufficiency findings are withdrawn for the autonomous-agent target. Generic clients and consumable-resource history were substituted for required architectural elements. The [correction](2026-10-06-consumable-credentials-correction.md) supplies the controlling element classifications. Other full-target assertions below (including KedgeFlow and conditional recent specifications) are not established for the corrected target by these charts alone. Mechanism evidence, dates and the separate Morrison reproduction remain available; the original text is preserved below to make the error and its correction traceable.


**Reviewed Morrison revision:** `bde1dcc35fdd63a4ac7dd572a28648d16a1105a9`.  
**Method:** seek counterexamples, not support for the previous conclusion. Technical assessment, not a determination of patent validity or priority entitlement.  
**History:** the [preceding supplement](2026-10-05-search-supplement.md) remains unchanged; the [preceding main document](history/2026-10-05-before-adversarial-search.md) is preserved verbatim. Those conclusions are historical, not the conclusions of this pass.  
**Reproduction:** [offline script](reproduce_adversarial_2026_10_05.py) and [recorded results](2026-10-05-adversarial-results.json).

## 1. Four conclusions

1. **Prior art: qualifying earlier disclosure UNRESOLVED; complete technical mechanism disclosure FOUND.** The 2006 consumable-credentials report, corroborated by its 2007 successor, matches the stated target under a terminology-neutral reading of software agents, bounded resources and history-dependent global admissibility. The previous statement, “No single reference has yet been verified as disclosing the complete narrow combination,” is withdrawn for that reading. A confirmed Morrison priority date, actual claims and supported claim construction are still needed to decide legal qualification. If “agent” requires a particular AI-specific mechanism, that requirement must be identified in the claim; it cannot be added merely to exclude this reference. KedgeFlow also supplies a complete conditional specification for its Level A shared-invariant profile. These are disclosure findings, not deployment findings.
2. **Combination/obviousness pressure: substantial.** The smallest set for the core technical target is already one reference on the above reading. If that reading is rejected, Schneider's composable security automata plus the consumable-credentials mechanism provide a two-reference route to broader trajectory policies, independent authorization and proof-bound decisions. O'Neil's escrow supplies explicit pending-capacity treatment; Polymer supplies restrictive verdict composition and policy-state updates. The remaining work is concrete semantic modeling, trusted effect translation, distributed consistency and evidence/deployment integration—not an established conceptual gap or a legal finding of obviousness.
3. **External demonstration: complete property NOT VERIFIED by this review.** There are implemented and evaluated components, bounded prototypes, simulations and formal results. They must not be collapsed into one end-to-end demonstration. No external system was independently reproduced here. MasuGate's checked source explicitly records no accepted independent reproduction of its reference fixture; its experimental history provider is outside its reference-release claim boundary. Lack of independent reproduction does not invalidate an author's reported experiment and does not negate disclosure.
4. **Morrison demonstration: bounded results and concrete failures reproduced.** 134 selected existing tests passed, including characterization tests that expect unsafe states. Seven existing finite models still have all-`PERMIT` counterexamples. A new offline public-API experiment exposes reservation release after lease minting: the resource accepts the released read lease, and the kernel then permits the send that the control blocks. No forged credential or real external effect was involved. Complete global prevention is not established, even assuming requests use these governed APIs. The strongest next experiment is to repeat this exact trace across an isolated real gateway and kernel service, then race release, redemption, reconciliation, expiry and restart against a resource-side effect ledger.

## 2. Fixed interpretation and assessment rules

Target: **Separate local and global admissibility checks over a bounded agent environment, preventing locally acceptable actions from composing into a globally prohibited state, enforced by independent pre-execution authority, with decision-bound evidence.**

“Global” includes cumulative resource state, shared invariants, causal provenance and history-dependent restrictions. It need not mean a whole future plan or universal real-world safety. “Separate” means distinguishable checks; it does not demand separate machines, separately named verdict objects or Morrison terminology. “Bounded” means a declared protected state/action/resource scope; exhaustive finite-state enumeration is assessed separately. A software client can propose actions without being an LLM. These interpretations are material to the matching result and are explicit rather than silently assumed.

Decision-bound evidence must participate in, or causally identify, the authorization and action. An unrelated after-the-fact log is insufficient. The stronger requirement to bind the full relevant action/policy/history basis is a separate column. Neither cryptographic signing nor all four narrower implementation features are silently added to the core target.

**YES** means affirmative disclosure within the identified scope, not demonstrated universal enforcement. **PARTIAL** means a stated subset or qualified mapping. **NOT ESTABLISHED** means the inspected material did not establish the element; it never means absent. **NO** is used only for an explicit contrary mechanism. All prevention/authority entries inherit the reference's trusted-component and mediation assumptions. No different papers are mosaicked into a single-reference match.

## 3. Source and date register

All sources were inspected on 2026-10-05. For non-patent works, filing/priority are **not applicable to the inspected publication**, not a statement that no associated patent exists. Exact days not established are left at month/year precision. A repository commit timestamp does not prove the date its contents became publicly accessible. **Every date-qualified comparison remains conditional on Morrison's confirmed claim-specific priority.**

| ID | Primary source / inspected version | Publication or document date | Filing date | Priority / version qualification |
|---|---|---|---|---|
| C06 | [Bauer, Bowers, Pfenning, Reiter, CMU-CyLab-06-002](https://www.cs.cmu.edu/~fp/papers/CMU-CYLAB-06-002.pdf), §§3–7, appendices | Report dated **2006-02-10** | N/A | Verify historical public availability if legally disputed; not dated from crawler metadata |
| C07 | [Bowers et al., Consumable Credentials in Logic-Based Access-Control Systems](https://users.ece.cmu.edu/~reiter/papers/2007/NDSS2.pdf), §§3.2–7, Appendix B | NDSS **2007-02**, day not established | N/A | Separate revised paper; does not backdate additions to C06 |
| PACE | [PACE v1](https://arxiv.org/html/2610.01349v1), §§4, C.3–C.6, D | **2026-10-01** | N/A | PACE-c specification distinguished from evaluated PACE-p |
| PRO | [Provenact v1](https://arxiv.org/html/2608.02764v1), §§3–6 | **2026-08-03** | N/A | v2 dated 2026-08-10 is a separate revision |
| MAS | [MasuGate source](https://github.com/masugate/masugate/tree/10f097ced9480ca86c138a9c3d8c92bebdadcefa) | Inspected commit **2026-08-26T21:43:02Z** | N/A | Commit `10f097c…`; [release article](https://masugate.github.io/blog/masugate-public-source-release/) published 2026-08-16, updated 2026-08-25. Do not backdate this tree to either article date |
| LD | [L-DREA author paper](https://www.researchgate.net/publication/411276938_Deterministic_Runtime_Enforcement_The_Execution_Authority_for_Autonomous_AI_Agents), DOI [10.1109/ACCESS.2026.3719838](https://doi.org/10.1109/ACCESS.2026.3719838) | Header publication **2026-08-04**; current version **2026-08-11** | N/A | Received 2026-07-12, accepted 2026-07-30; host's “January” metadata is not used |
| CAIS | [Controlled Agentic AI Systems v1](https://www.preprints.org/manuscript/202603.1904), §§2–5 | Posted **2026-03-24** | N/A | Submitted 2026-03-21; later journal version not backdated |
| ACT | [ActPlane v2](https://arxiv.org/html/2606.25189v2), §§3–6; [current rule specification](https://eunomia.dev/actplane/rule-language/) | v1 **2026-06-23**, v2 **2026-06-30** | N/A | Mutable documentation as inspected 2026-10-05; feature-introduction commit not established |
| CAM | [CamQuery](https://arxiv.org/pdf/1808.06049), §§3–8 | arXiv **2018-08-18**; CCS **2018-10-15** | N/A | In-kernel and userspace modes differ |
| KED | [KedgeFlow v0.9](https://www.openkedge.io/paper/kedgeflow), §§3.4, 4, 7–10, A–B | Stated **2026-10-05** | N/A | Current proposed specification; earlier snippet dates cannot date v0.9 content |
| P1 | [US20260127298A1](https://patents.google.com/patent/US20260127298A1/en), description and claims | **2026-05-07** | **2025-11-10** | Record priority **2025-11-10**; claim support/entitlement not independently adjudicated |
| P2 | [US20260142827A1](https://patents.google.com/patent/US20260142827A1/en), description and claims | **2026-05-21** | **2026-01-16** | Record prior-art date 2026-01-16; CIP ancestry reaches **2024-10-19**, not automatic support for every later feature |
| P0 | [US20260111292A1](https://patents.google.com/patent/US20260111292A1/en), P2's parent | **2026-04-23** | **2025-12-09** | Claimed ancestry: 2025-11-10, 2025-08-02, 2025-05-04, 2024-10-19; new governed-compute matter explicitly identified |
| LPM | [Bates et al., Trustworthy Whole-System Provenance](https://adambates.org/documents/Bates_Security15a.pdf), §§3–5, Algorithms 2–3; [proceedings](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/bates) | USENIX Security **2015-08** | N/A | Author index dates presentation 2015-08-13; do not infer earliest public availability from presentation |
| SCH | [Schneider, Enforceable Security Policies](https://www.cs.cornell.edu/fbs/publications/EnfSecPols.pdf), security automata and conjunction | Journal **2000-02** | N/A | [1998-01 report](https://ecommons.cornell.edu/entities/publication/5a936aa1-8a4f-41df-bc17-f2db479cf33e) identifies substantial later revision; journal detail not backdated |
| ESC | [O'Neil, The Escrow Transactional Method](https://www.cs.umb.edu/~poneil/EscrowTM.pdf), §§1–2 | **1986-12** | N/A | Author lists 1985 workshop antecedent; that text not inspected |
| POL | [Bauer, Ligatti, Walker, Polymer](https://users.ece.cmu.edu/~lbauer/papers/2005/pldi2005-polymer.pdf), §§3–5 | PLDI **2005-06** | N/A | Earlier 2004 report listed by authors, not used to date this text |
| PCA | [A Proof-Carrying Authorization System](https://users.ece.cmu.edu/~lbauer/papers/pcaprototr.pdf), protocol and prototype | Report **2001-04-30** | N/A | Earlier Appel–Felten 1999 citation followed; full earlier text not retrieved |
| HIST | [Abadi–Fournet, Access Control Based on Execution History](https://www.cs.columbia.edu/~locasto/projects/candidacy/papers/abadi2003ac.pdf), history-based checks | NDSS **2003-02** | N/A | Day not established from inspected paper |
| WALL | [Brewer–Nash, Chinese Wall Security Policy](https://people.csail.mit.edu/alinush/6.858-fall-2014/papers/chinese-wall-sec-pol.pdf) | IEEE S&P **1989** | N/A | Exact publication day not established |
| COORD | [Komenda et al., Coordination Control Revisited](https://arxiv.org/pdf/1307.4332); [version record](https://arxiv.org/abs/1307.4332) | v1 **2013-07-16** | N/A | Unversioned PDF is later revision; detailed claims below apply to inspected PDF, not necessarily v1 |
| SHIELD | [Bloem et al., Shield Synthesis](https://arxiv.org/pdf/1501.02573) | arXiv v1 **2015-01-12**; TACAS 2015 | N/A | Unversioned PDF inspected; later changes not separately dated |
| INV | [Bailis et al., Coordination Avoidance v1](https://arxiv.org/pdf/1402.2237v1) | **2014-02-10** | N/A | Version-specific, not later VLDB text |

## 4. Core element chart

B = bounded operating environment; L = local/per-transition admissibility; G = separate global/trajectory admissibility; C = prevents locally acceptable composition; I = independent pre-execution authority; X = execution structurally requires authorization; E = decision-bound evidence. Ratings concern disclosure, except the explicitly labeled Morrison implementation row. The source notes below delimit each YES.

| Reference / profile | B | L | G | C | I | X | E |
|---|---|---|---|---|---|---|---|
| C06, bounded credential/resource instances | YES | YES | YES | YES | YES | YES | YES |
| C07, same scoped mechanism | YES | YES | YES | YES | YES | YES | YES |
| PACE-c + specified C.3 protocol | YES | YES | YES | YES | YES | YES | YES |
| PACE-p evaluated combiner | YES | YES | YES | NO | PARTIAL | PARTIAL | PARTIAL |
| Provenact v1, conforming provider boundary | YES | YES | YES | YES | YES | YES | YES |
| MasuGate pinned service/provider specification | YES | YES | YES | YES | YES | YES | YES |
| MasuGate experimental event-history provider, same protected service | YES | YES | YES | YES | YES | YES | YES |
| L-DREA | YES | YES | YES | PARTIAL | YES | YES | YES |
| CAIS | YES | YES | YES | PARTIAL | PARTIAL | PARTIAL | YES |
| ActPlane | YES | YES | YES | YES | YES | YES | PARTIAL |
| CamQuery, in-kernel mode | YES | YES | YES | YES | YES | YES | PARTIAL |
| KedgeFlow Level A, fully coordinated invariant | YES | YES | YES | YES | YES | YES | YES |
| US20260127298A1 | YES | YES | PARTIAL | NOT ESTABLISHED | YES | YES | YES |
| US20260142827A1 | YES | YES | PARTIAL | NOT ESTABLISHED | YES | YES | YES |
| US20260111292A1 parent | YES | YES | PARTIAL | NOT ESTABLISHED | YES | YES | YES |
| LPM / PB-DLP | YES | YES | YES | YES | YES | YES | PARTIAL |
| Schneider security automata | YES | YES | YES | YES | YES | YES | NOT ESTABLISHED |
| O'Neil escrow | YES | YES | YES | YES | PARTIAL | YES | YES |
| Polymer | YES | YES | YES | YES | YES | YES | PARTIAL |
| PCA 2001 | YES | YES | NOT ESTABLISHED | NOT ESTABLISHED | YES | YES | YES |
| Abadi–Fournet history control | YES | YES | YES | YES | PARTIAL | YES | NOT ESTABLISHED |
| Chinese Wall | YES | YES | YES | YES | PARTIAL | PARTIAL | NOT ESTABLISHED |
| Coordination control | YES | YES | YES | YES | PARTIAL | YES | NOT ESTABLISHED |
| Shield synthesis | YES | YES | YES | YES | YES | YES | NOT ESTABLISHED |
| Invariant confluence | YES | YES | YES | YES | NOT ESTABLISHED | PARTIAL | NOT ESTABLISHED |
| Morrison current implementation, all exported paths | YES | YES | PARTIAL | NO | PARTIAL | PARTIAL | YES |

PACE's NO is specifically the certified path-confinement guarantee for the evaluated combiner, not every property PACE enforces. Morrison's NO is the unrestricted prevention claim across the reviewed public paths, not every configured bounded scenario. Formal reference-monitor YES ratings do not certify a deployed trust boundary. Information-flow rows concern declared causal flows, not arbitrary semantic harms.

### Narrower features

R = reservations affect adjudication; D = relevant denied attempts affect later adjudication; V = strictest-verdict composition (binary conjunction counts); H = evidence binding action, policy/ruleset state and relevant trajectory/history. Counting denials **does** count when the count changes authorization; merely logging/counting without a decision dependency does not.

| Reference / profile | R | D | V | H |
|---|---|---|---|---|
| C06 | PARTIAL | NOT ESTABLISHED | YES | PARTIAL |
| C07 | PARTIAL | PARTIAL | YES | PARTIAL |
| PACE-c + C.3 | YES | NOT ESTABLISHED | YES | YES |
| PACE-p | NOT ESTABLISHED | NOT ESTABLISHED | NO | PARTIAL |
| Provenact v1 | YES | NOT ESTABLISHED | PARTIAL | YES |
| MasuGate pinned reference profile | YES | NOT ESTABLISHED | YES | YES |
| MasuGate experimental event-history provider | YES | YES | YES | PARTIAL |
| L-DREA | NOT ESTABLISHED | PARTIAL | YES | PARTIAL |
| CAIS | NOT ESTABLISHED | NOT ESTABLISHED | PARTIAL | YES |
| ActPlane | NOT ESTABLISHED | NOT ESTABLISHED | YES | PARTIAL |
| CamQuery | NOT ESTABLISHED | NOT ESTABLISHED | YES | PARTIAL |
| KedgeFlow Level A | YES | PARTIAL | YES | YES |
| US20260127298A1 | NOT ESTABLISHED | PARTIAL | YES | PARTIAL |
| US20260142827A1 | NOT ESTABLISHED | NOT ESTABLISHED | YES | PARTIAL |
| US20260111292A1 parent | NOT ESTABLISHED | NOT ESTABLISHED | YES | PARTIAL |
| LPM / PB-DLP | NOT ESTABLISHED | NOT ESTABLISHED | YES | PARTIAL |
| Schneider | NOT ESTABLISHED | NOT ESTABLISHED | YES | NOT ESTABLISHED |
| O'Neil escrow | YES | NOT ESTABLISHED | YES | PARTIAL |
| Polymer | NOT ESTABLISHED | PARTIAL | PARTIAL | PARTIAL |
| PCA 2001 | NOT ESTABLISHED | NOT ESTABLISHED | PARTIAL | PARTIAL |
| Abadi–Fournet | NOT ESTABLISHED | NOT ESTABLISHED | PARTIAL | NOT ESTABLISHED |
| Chinese Wall | NOT ESTABLISHED | NOT ESTABLISHED | YES | NOT ESTABLISHED |
| Coordination control | NOT ESTABLISHED | NOT ESTABLISHED | YES | NOT ESTABLISHED |
| Shield synthesis | NOT ESTABLISHED | PARTIAL | YES | NOT ESTABLISHED |
| Invariant confluence | NOT ESTABLISHED | NOT ESTABLISHED | PARTIAL | NOT ESTABLISHED |
| Morrison kernel / exported leases | PARTIAL | YES | YES | PARTIAL |

## 5. Strongest counterexample and source-specific findings

### C06: why the old conclusion does not survive

| Target | Mechanism disclosed in C06 |
|---|---|
| B | Declared resources, credentials and bounded permitted uses |
| L | Proof validity and linear use within each request, §3 |
| G | Distinct ratification against cross-request consumption, §§3.2–4 |
| C | Global bounded-use condition; local proof checking alone is insufficient |
| I | Ratifiers and resource monitor separate from requesting prover, §5 |
| X | Resource released only after verified ratified proof, §4 |
| E | Signed consent binds credential, proof and action goal, §4 |

This is a mechanism match, not lexical similarity. It does not establish a complete retained history snapshot or Morrison's particular denied-read semantics. Consumption before resource access is reservation-like but not identical to a cancellable pending lease. §7 reports a prototype; it does not establish independently reproduced end-to-end containment. The report date is not Morrison's priority date.

### C07: corroboration and limits

§§3.2–4 expressly separate local proof validity from global consumption. §4.2 and Appendix B bind signatures to proof/action/nonces; §5 treats a ratified proof as evidence. Refusal after completed ratification can leave authority consumed pending compensation: a limited denied-outcome state effect, not a general denied-attempt policy. §7 evaluates ratification on separate computers; Grey deployment was in progress. Neither a full-history evidence digest nor adversarial end-to-end enforcement of every example is established by those measurements.

### Requested recent references

- **PACE:** PACE-c specifies separate capability and provenance-path checks, with the stronger C.3 atomic freshness/reservation/evidence protocol. That is disclosure even though outside the evaluated artifact. PACE-p can restore a provenance-blocked call and dispatch repairs without final recertification; its results cannot demonstrate the certified episode invariant. Blocked/cancelled proposals in the evidence graph do not establish their participation in the active causal graph. Coverage, correct schemas, labels, hooks and trusted state remain premises.
- **Provenact:** §§3–4 distinguish request predicates from certified shared-state views and protect their decision/effect interval through provider coordination. Durable governance records identify request, policy/rule, reads, decision and effect. For that declared provider scope, the core mechanism is disclosed; requiring a separate “trajectory engine” would impose an extra restriction. Its PostgreSQL procurement prototype is narrower than external-effect deployment. Policy-state serializability alone does not prove that the chosen policy excludes every prohibited state. V is partial: policy and coordination must both succeed; the later implementation's cross-policy precedence is not backdated to v1.
- **MasuGate:** inspected `policy.py` implements separate policies with deny-overrides; `coordinator.py` records protected admission and authorization before finishing the operation. The pinned [correction record](https://github.com/masugate/masugate/blob/10f097ced9480ca86c138a9c3d8c92bebdadcefa/docs/pss-v0.1.1-correction.md) rejects the old PSS checker: write-skew could pass and harmless shared reads could fail. Earlier results require corrected replay. The [event-history provider](https://github.com/masugate/masugate/blob/10f097ced9480ca86c138a9c3d8c92bebdadcefa/docs/event-history-provider.md) commits normal denied attempts into policy-readable history; subsequent attempt/receiver guards use it. That contradicts treating denied attempts as merely logs. Its [threat model](https://github.com/masugate/masugate/blob/10f097ced9480ca86c138a9c3d8c92bebdadcefa/docs/event-history-threat-model.md) leaves production PSS export integration incomplete. These experimental features must not be attributed to paper v1 or the reference fixture. Receipt hashing is not independent signed attestation.
- **L-DREA:** §§V–VI specify node predicates, persistent class vetoes, noncompensatory aggregation, signed permits and commit-before-actuation. Excluding it as merely per-call is wrong. The mapping from class metrics to prevention of every prohibited composed successor remains partial: metric completeness and predictive adequacy are not proved. The paper expressly says evaluated Tier S does not satisfy substrate-isolation assumption A3; hardware/TEE architecture is not a demonstrated hardware boundary. Later class-veto details cannot simply be imported into P1.
- **CAIS:** local operators and a joint global constraint projection, plus structured decision traces, are affirmative disclosures. The simulations report residual violations under projection; they do not demonstrate the ideal constraint-preserving property. Independent protected execution authority is not established by separating mathematical operators. Solver accuracy, feasible-set correctness and enforcement placement remain distinct issues.
- **ActPlane:** OS hooks enforce ordinary event checks plus history-dependent flow/temporal conditions outside the proposer. Its paper expressly points to CamQuery. The current rule documentation includes order-sensitive gates; their precise introduction commit was not established. Full action/policy/history binding for each decision remains partial; semantic feedback is not automatically such a receipt. Prototype evaluations are not universal bypass or semantic-effect coverage.
- **CamQuery:** in-kernel provenance checks can reject a pending operation, including flows through intermediate objects, alongside ordinary access controls. This refutes the stateless-authority/framework-trajectory dichotomy. Userspace/distributed analysis cannot be assigned the same preventive guarantee. Provenance capture and policy attestation do not establish a complete decision-bound policy/history receipt for each transition; that is the strongest remaining core-evidence question.
- **KedgeFlow:** §§3.4, 4, A–B specify local identity/action checks, a separate shared-capacity ledger, mandatory grants and digest-linked admission evidence. The three-node/two-removal example directly instantiates prohibited composition. The complete disclosure applies to Level A with full-scope coordination/fencing and all writers covered. Levels B/C do not inherit commit-time preservation. Reservations survive uncertain outcomes; some failed attempts retain consumption, a narrower D case. §10.4's separate admission/proxy examples and mock effects explicitly do not constitute a complete interoperable deployment. A recent specification still defeats a timeless “not disclosed anywhere” statement, although its prior-art qualification is unresolved.
- **P1:** proof-before-action, noncompensatory gate aggregation, acceptance windows, signed evidence tuples and controlled readmission are disclosed. Multiple metrics or a federated window are not by themselves proof of a separate composition-preventing invariant. Evidence of exact action and complete relevant-history binding is partial. Filing, publication and later L-DREA disclosure remain separate.
- **P2 and P0:** an external governance domain, canonical effects, sealed envelopes, cryptographic/time validation, mandatory authorization and audit lineage are disclosed. Multiple engines/envelopes can all be required. Neither inspected document establishes the full mapping to locally valid actions composing into a prohibited state under a separate global check. Integrity suspension is history-sensitive but does not alone prove that target. They are specifications, not inspected experiments. P0 identifies new governed-compute matter; the 2024 family date cannot be assigned wholesale to it or P2.

### Older adjacent work and remaining gaps

- **LPM/PB-DLP:** Algorithms 2–3 and §5.4 consider individually shareable identifiers whose combined disclosure is prohibited. Provenance ancestors drive a separate prospective transfer check; SELinux protects the collection/enforcement environment. A file-transfer prototype is reported. Its trusted provenance is strong causal evidence, but a retained decision record binding the exact policy basis is not established. Its references lead to provenance-based access control (2009, 2012, 2013); those are further leads, not verified complete disclosures here.
- **Schneider:** a monitor can reject a prefix before an unsafe event, compose automata conjunctively and enforce policies at distinct components. Finite instances and declared event alphabets fit B; this is not a requirement that every automaton be finite. Decision-bound evidence is not established. Thus trace enforcement and strictest binary composition are poor standalone distinctions.
- **O'Neil:** request tests must preserve other escrowed tests; reservations alter the allowable range before final use. The decision-time journal includes transaction, requested change and test criteria. It is not merely a later transaction log. Malicious-agent isolation and binding an entire policy/history snapshot are not established. This is strong pressure on R and composed-state safety, independently of AI terminology.
- **Polymer:** independent policies have query and state-update methods; accepted exception suggestions can update state without running the requested method. D is partial: this permits semantic denial state, but a concrete subsequent-denial-dependent policy was not established. V is partial: conjunction favors restrictive responses, but insertion triggers execution/requery, not a simple total verdict ordering. Type safety protects monitor state under its language assumptions. Causal suggestion/action objects exist; complete durable policy/history evidence is not established. A Java/email prototype is reported.
- **PCA:** the 2001 server checks a requested authorization proof before access; the proof itself is evidence. It does not establish global consumption across proofs. C06/C07 address precisely that gap. **Abadi–Fournet** establishes history-sensitive permissions rather than just stack inspection; full decision evidence and a separately protected deployed authority are not established here. **Chinese Wall** provides a policy whose next permitted access depends on earlier access, but not the complete evidenced execution mechanism.
- **Coordination control:** local supervisors plus a coordinator prevent forbidden composed behavior under controllability/observability assumptions. Independent adversarial security boundaries and decision-bound evidence are not established. The inspected revision treats nonblocking composition, not just independent local safety. **Shield synthesis:** finite safety games synthesize an output interposer with correctness and bounded-deviation conditions; synthesis/prototype experiments do not supply decision evidence. Its recovery state responds to rejected design outputs, a partial D analogue. **Invariant confluence:** locally invariant-preserving transactions may fail after merge, motivating necessary coordination; authorization isolation and evidenced decisions are not established by that theorem.

## 6. Demonstration classification

| Work | Evidence actually inspected | Complete-target demonstration assessment |
|---|---|---|
| C06/C07 | Formal protocol, examples, implemented proof/ratification performance | End-to-end adversarial property not verified; deployment plans are not completed deployment |
| PACE | Conditional certified specification; different evaluated configuration | PACE-p cannot establish PACE-c's full invariant |
| Provenact/MasuGate | Paper prototype; corrected checker/source tests and explicit claim ledger | Strong bounded candidate; complete release gates not rerun here; no accepted independent reproduction listed |
| L-DREA | Architecture, reported software experiments, limited mechanization | Evaluated substrate lacks A3; full hardware property not verified |
| CAIS | Formal idealization and controlled simulations | Residual constraint violations contradict strict empirical prevention |
| ActPlane/CamQuery/LPM | OS/provenance prototypes and measured evaluations | Real enforcement evidence; exact complete evidence combination not verified |
| KedgeFlow | Specification, local integration/race tests, mock effects | Full admission-to-target deployment explicitly not demonstrated by those examples |
| P0/P1/P2 | Patent descriptions and claims | Disclosure; experimental implementation not established |
| Schneider/HIST/WALL/COORD | Formal models, algorithms and examples | Scoped formal results; full evidenced deployment not established |
| Escrow/Polymer/PCA/SHIELD/INV | Mechanisms, formal arguments, prototype or evaluation material as described above | Valuable component evidence; complete target not independently reproduced |
| Morrison | Source inspection, selected tests, finite enumeration, offline lease probe | Positive bounded results plus reproduced failures; no external deployment certification |

“Not verified” here does not mean nobody has demonstrated it. The review does not promote a specification to experiment, an author experiment to independent reproduction, or a prototype to production. A complete *formal* result is evaluated against its formal premises; the remaining question is whether the implemented boundary satisfies them.

## 7. Morrison's actual evidence and A–E falsification

Inspected production paths: `morrison_governance/kernel/{gate,continuity,mediation,evidence}.py`; finite harness: `morrison_governance/global_verification/{governance,verifier,comparison}.py`. Also inspected the existing complete-mediation, global-verification and AOE-falsification reports. Documentation was treated as a hypothesis and checked against code.

| Proposition | Adversarial result |
|---|---|
| A: separate global check can prevent bad composition | Supported for specified history rules and bounded scenarios, not universally. The accumulated-effect model permits three steps into a forbidden state because the operative policy lacks that modeled threshold. The new lease trace defeats a rule that **is** operative in the control. |
| B: authority structurally independent of proposer | Logical API separation exists. Python code does not itself isolate memory, keys, configuration or executors. Resource-side deployment can supply separation; a real isolated deployment was not verified here. |
| C: prohibited transition cannot occur through governed path without valid authority | The exported lease path accepts an authorization after its reservation/decision was released. This contradicts a blanket claim that release prevents subsequent execution across all governed paths. The ordinary `execute` path and resource verifier have different state checks. |
| D: reservations and denials affect later adjudication | YES within the kernel: `_any_read_occurred`, `_denied_read_occurred` and `denial_scrubbing` make these semantic. But reservation continuity does not survive the mint/release/redeem trace. Do not generalize the kernel-only result to portable leases. |
| E: evidence binds action, rules and history causally | Authorization seals an `EvidenceRecord` with action/ruleset/trajectory hashes before reservation/dispatch. Portable `ExecutionLease` carries action/semantic/decision identity but no ruleset or trajectory digest and does not consult current kernel history. Complete end-to-end binding remains partial; the record's integrity does not prove policy truth or actual effect. |

### New concrete trace

The reproduction creates a real kernel with the same relevant configuration as the continuity tests, using dummy keys and inert executors:

1. Control: authorize `query_db`; while its reservation remains, the external `http_post` is `BLOCK`.
2. Attack: authorize the same read (`PERMIT`), mint an execution lease, then call `release(decision)` successfully. The ledger becomes empty.
3. Present the previously issued lease and exact read request to `LeaseVerifier`; verification succeeds. The mock gateway performs the read.
4. Submit the same external send. It receives `PERMIT`; `kernel.execute` invokes the mock send. Both effects occur in order.

`mint_lease` does not mark the reservation as irrevocably exported; `release` removes it, while the resource verifier checks signature/time/action/replay state without learning of release. No access to an agent-held signing secret, mutated decision or ungoverned executor is needed in the trace. Exploitability in a particular service depends on whether it exposes cancellation/release after export; the library permits the composition. A deployment that forbids that sequence can exclude this attack, but that restriction is an additional, testable contract.

Two negative controls also succeeded: the same token was accepted by two default verifiers with separate replay sets, and verification without a request succeeded. The shared atomic `_consume` callback and supplying the exact request are therefore load-bearing integration requirements. These controls do not claim to defeat correctly shared replay state or exact-request verification.

### What was reproduced

| Command / scope | Result |
|---|---|
| `python3 -m pytest -q morrison_governance/test_mediation.py morrison_governance/global_verification/test_aoe_falsification.py` | 22 passed; includes expected unsafe characterizations |
| `python3 -m pytest -q morrison_governance/test_authority_continuity.py morrison_governance/test_governed_execution_veto.py morrison_governance/global_verification/test_global_verification.py` | 106 passed |
| `python3 -m pytest -q morrison_governance/global_verification/test_provenance.py -k 'artifact_carries or evidence_survives or keeps_the_evidence or tamper'` | 6 passed, 20 deselected |
| `python3 -m morrison_governance.global_verification --composition-experiment` | `Safe(A) and Safe(B): True`; `new unsafe path in A+B: False`; `SAFE_WITHIN_MODEL` |
| `python3 docs/prior-art/reproduce_adversarial_2026_10_05.py` | Recorded new lease failure and seven completely enumerated unsafe models; all counterexample steps `PERMIT` |

Tests used system Python 3.12 and pytest 9.1.1. The initial default Python lacked pytest; the system interpreter was used instead. An earlier combined invocation produced an incomplete progress log and is not counted as a completed test run. This is not a full repository test run or a live-agent benchmark.

The shipped composition command governs A, B and A+B; it is not by itself an ablation comparing local-only against local-plus-global enforcement. The verifier's declared transition function and prohibited-state predicates are not automatically inputs to kernel authorization. Complete enumeration proves a claim only for the enumerated abstraction and authorization configuration, including escalation resolution. An unsafe characterization test passing is evidence that the limitation was reproduced.

### Remaining assumptions and strongest next experiment

The result depends on: complete mediation of **every** relevant writer/effect; correct action-to-effect mapping and policy/invariant specification; finite and complete modeled state/action bounds; trusted atomic shared history with rollback-resistant recovery; secret custody and authenticated identities; correct gateway forwarding and atomic resource checks; clocks, expiry and revocation semantics; and faithful external effect reconciliation. A hash or signature authenticates a record, not these assumptions.

Repeat the demonstrated lease trace with a credential-holding gateway in a separate privilege domain and an agent without direct resource access. An independent observer should measure actual effects and ledger state. Enumerate concurrent orderings of mint/release/redeem, policy changes, denied attempts, cross-principal delegation and crash/restart. Fail the property on any protected effect after authority cancellation, any forbidden composed successor, or any effect not reconstructable from its decision/policy/history basis. Test a fixed bounded invariant already encoded in policy so a failure cannot be attributed merely to an omitted harm definition. This is a falsification experiment, not a proposal to broaden claims.

## 8. Small combinations and residue

| Candidate set | What it supplies | Remaining engineering/conceptual work |
|---|---|---|
| C06 alone | Core combination on the stated terminology-neutral reading | Particular AI adapters and policies; stronger complete-history evidence and denied-attempt semantics are separate comparisons |
| Schneider + C06/C07 | General trace predicates, conjunctive local/global decisions, independent proof-gated resource access | Bind monitor-state/version to proof; serialize state changes and execution; establish mediation |
| LPM or CamQuery + C06/C07 | Causal information-flow histories plus action-bound mandatory authorization | Bind policy/provenance checkpoint to permit; atomic check/use across processes and hosts |
| O'Neil + PCA + Polymer | Pending reservations, proof-before-access, restrictive composition and denied-action state updates | Integrate transaction state with authority/evidence; select effect vocabulary and trustworthy adapters |
| Coordination control or shielding + PCA | Bounded reachable-state safety and a proof-checked execution boundary | Bind runtime state to proof and monitor plant fidelity, uncontrollable events and deployment isolation |

These are constructive combination arguments, not proof that a skilled person legally would combine the references. Conversely, identifying integration work does not establish non-obviousness. The updated MasuGate implementation also places substantial pressure on treating R/D/V as a remaining categorical distinction. A policy threshold driven by denied attempts is semantic adjudication even if represented by a counter.

## 9. Search trail, backward citations and limits

This pass searched the nine requested names/identifiers and exact phrases from the target, then concepts rather than branding: local proof/global ratification; noncompensatory class veto; causal provenance enforcement; constrained workflow completion; consumable authorization; escrow reservations; coordination of invariant-preserving transactions; security automata conjunction; shield safety games; history-based access control; Chinese Wall; proof-carrying authorization; and hardware governance-envelope ancestry.

Backward paths actually followed:

- ActPlane → CamQuery → LPM/PB-DLP; LPM's provenance-access-control citations retained as further leads.
- PACE → Schneider/security automata and information-flow antecedents; comparison against certified versus evaluated configuration.
- Provenact → O'Neil escrow and Bailis invariant confluence; checked newer MasuGate correction/history material separately.
- Distributed authorization → C07 → **C06** → PCA and Chinese Wall. C06 was inspected directly, not inferred from C07.
- L-DREA → its earlier patent P1; P2 → P0 and the stated CIP chain. No automatic backdating of new matter.
- Reachability/control search → coordination control and shield synthesis; Ramadge–Wonham 1987 publisher/author records were located but full original text was not obtained.

Representative reproducible queries: `"Consumable Credentials" "2006"`; `"proof carrying authorization" "history"`; `"reference monitor" "constrained task execution"`; `"Schneider" "Enforceable Security Policies"`; `"O'Neil" "escrow"`; `"Bailis" "Coordination Avoidance"`; `"shield synthesis" "2015"`; `"Clark" "Wilson" "1987" security policies`; and each requested patent number. Search engines sometimes returned irrelevant results or misleading crawl dates. Primary documents, author repositories and explicit version headers controlled the conclusions.

**Unresolved leads, not negative findings:** Crampton's 2005 constrained-workflow monitor was located in an indexed PDF and author metadata, but its old host redirected on further inspection; no full mechanism verdict is assigned. Clark–Wilson 1987 was located through bibliographic/teaching references without a successfully inspected original. Appel–Felten 1999 full text retrieval failed. Additional cited provenance-control and contract-signing papers remain follow-up leads. The prior PDF/Claude analysis and first search were inputs to challenge, not independent proof of coverage. This was a substantial bounded search, not an exhaustive search of all patents, languages, private systems or deployment records.

## 10. Corrections to carry forward

- Withdraw the unqualified “no single reference verified” result; preserve it only as dated history.
- Do not require production demonstration to count architectural disclosure.
- Do not equate a call-boundary check with stateless policy or framework placement with avoidable authority.
- Do not promote absence of inspected evidence to feature absence.
- Do not exclude stateful resource accounting, information flow or software clients because terminology differs.
- Do not add R/D/V/H or exhaustive finite verification as new mandatory core elements after finding a match.
- Do not equate a signature, a passing test count or a finite-model result with complete deployed global safety.
- Preserve Morrison's positive scoped results alongside its synthetic counterexamples and the new lease-path failure; no production runtime code was changed by this review.
