# Local/global AOE prior-art search supplement — 5 October 2026

**Status:** Technical comparison and search record; no novelty, anticipation or patentability conclusion.  
**Parent document:** [Prior Art & Novelty Position](../../PRIOR_ART_AND_NOVELTY_POSITION.md).  
**Baseline:** repository commit [0f84a413080f7084cb1974fe8cdf4352548b8f5e](https://github.com/davarntrades/Morrison-Runtime-Governance/commit/0f84a413080f7084cb1974fe8cdf4352548b8f5e), prior-art blob `cb680e579720d0100f6d1034180b3c6ef3b6a55e`.  
**Preserved text:** [verbatim pre-update snapshot](history/2026-10-05-before-web-search.md). The snapshot is historical evidence, not the current conclusion.

## 1. Scope and the two independent questions

**Target:** Separate local and global admissibility checks over a bounded agent environment, preventing locally acceptable actions from composing into a globally prohibited state, enforced by independent pre-execution authority, with decision-bound evidence.

1. **Prior-art/disclosure:** Does an earlier qualifying reference disclose the complete claimed combination?
2. **Demonstration:** Has a system actually demonstrated the complete property under its stated assumptions?

The disclosure question cannot be answered by rejecting a reference merely because it lacks a production deployment or empirical bypass test. The demonstration question cannot be answered solely from an architecture diagram, theorem with assumed mediation, patent description, or intended deployment. Each needs its own evidence. No reviewed prototype was independently reproduced during this search.

A complete match requires the elements together in the relevant reference/version, not a mosaic of separate papers. Assessing possible combinations is a separate inquiry. A date-qualified disclosure determination remains open until the actual Morrison claim text and priority support are checked.

### Fixed element definitions

| ID | Element |
|---|---|
| E1 | A bounded admissible operating envelope for an AI/agent environment; equivalent terminology counts. |
| E2 | Local admissibility evaluated and enforced at individual action/transition boundaries. |
| E3 | A **separate** global admissibility evaluation over composed state or execution trajectory. |
| E4 | Prevention of globally prohibited composition of individually locally acceptable transitions on the governed path. |
| E5 | Independent runtime execution authority, protected from the proposing agent; complete mediation must be assessed for the stated boundary. |
| E6 | Authority exercised before execution through permit, veto/block or escalation. |
| E7 | Decision-bound evidence for the action and local/global evaluation context. Mere operational logging does not establish the full evidence semantics. |

These definitions keep the seven-element target distinct from the narrower features below. A reference need not use “AOE” or “Morrison” terminology. A call-by-call enforcement point can maintain history and enforce global properties. Conversely, a “global” organizational policy is not automatically a separate composed-state check.

### Narrower implementation features

- **R:** reserved/pending actions affect semantic trajectory/global admissibility.
- **D:** denied actions change later semantic admissibility, beyond merely being logged or counted.
- **V:** separate local and global verdicts, with the strictest applicable verdict controlling execution.
- **B:** evidence binds action identity, ruleset/version and trajectory/state basis.
- Exhaustive finite environment-state verification is an additional comparison question, not a substitute for E1–E7.

**Reading the charts:** Entries describe scoped disclosure, partial overlap, or an unresolved mapping. **NE means “not established from the inspected material,” never “absent.”** A described mechanism is not automatically a demonstrated mechanism. No row below receives an unqualified complete-match verdict.

## 2. Reference and date register

All sources were accessed on **5 October 2026**. Dates below identify the inspected version or its source record; they do not establish entitlement to a patent priority date.

| ID | Reference / inspected source | Publication or public-version date | Patent filing date | Priority information | Morrison-date relevance |
|---|---|---|---|---|---|
| S1 | [PACE, arXiv v1](https://arxiv.org/html/2610.01349v1), §§4.1–4.4, C.3–C.6 | 1 Oct 2026 | N/A for this paper | No patent priority assessed | Requires confirmed Morrison claim-specific priority |
| S2 | [Stateful Governance for Concurrent Agentic Systems, Provenact v1](https://arxiv.org/html/2608.02764v1), §§3–6; [MasuGate release record](https://masugate.github.io/blog/masugate-public-source-release/) | Paper v1: 3 Aug 2026. Release article: 16 Aug, updated 25 Aug 2026; identifies v2 dated 10 Aug | N/A for these sources | No patent priority assessed | Date each version separately; do not backdate later MasuGate features to v1 |
| S3 | [L-DREA full paper](https://www.researchgate.net/publication/411276938_Deterministic_Runtime_Enforcement_The_Execution_Authority_for_Autonomous_AI_Agents), §§III–VI, IX, XII; [DOI](https://doi.org/10.1109/ACCESS.2026.3719838) | Paper header: 4 Aug 2026; current version 11 Aug; received 12 Jul, accepted 30 Jul | N/A for paper; S8 is a separate patent reference | Do not assign S8's filing date to later paper additions | Requires confirmed Morrison priority and version-specific disclosure |
| S4 | [Controlled Agentic AI Systems (CAIS), preprint v1](https://www.preprints.org/manuscript/202603.1904), multi-agent extension and experiments | Posted 24 Mar 2026; submitted 21 Mar | N/A for paper | No patent priority assessed | Requires confirmed Morrison priority; submission is not publication |
| S5 | [ActPlane paper record](https://arxiv.org/abs/2606.25189); [rule-language documentation](https://eunomia.dev/actplane/rule-language/), §§1.9, 3, 5–6 | Paper v1: 23 Jun 2026; v2: 30 Jun. Mutable documentation inspected 5 Oct; exact feature-introduction dates NE | N/A for sources | No patent priority assessed | Do not attribute current documentation features to the first paper without version evidence |
| S6 | [CamQuery, Runtime Analysis of Whole-System Provenance](https://arxiv.org/pdf/1808.06049); [arXiv record](https://arxiv.org/abs/1808.06049), design/enforcement sections | Preprint: 18 Aug 2018; CCS publication record: 15 Oct 2018 | N/A for paper | No patent priority assessed | Older antecedent; exact claim applicability still requires comparison |
| S7 | [KedgeFlow specification](https://www.openkedge.io/paper/kedgeflow), §§1, 3, 7–10 and appendices | Inspected page labels v0.9: 5 Oct 2026; earlier public availability NE | N/A for specification | No patent priority assessed | Requires confirmed Morrison priority and archived version/date evidence |
| S8 | [US20260127298A1](https://patents.google.com/patent/US20260127298A1/en), description and claims | 7 May 2026 | 10 Nov 2025 | Record lists 10 Nov 2025; not independently adjudicated | Filing and public disclosure are distinct; qualifying relevance unresolved |
| S9 | [US20260142827A1](https://patents.google.com/patent/US20260142827A1/en), abstract, cross-reference, governance/audit embodiments | 21 May 2026 | 16 Jan 2026 | Record labels 16 Jan 2026 “prior art date”; description identifies a CIP chain reaching 19 Oct 2024 | Do not give new governed-compute material the earliest family date without support analysis |

For S9 the stated intervening parent filing dates are 9 December 2025, 10 November 2025, 2 August 2025 and 4 May 2025. The description explicitly identifies governed-compute extensions in the continuation-in-part. Which passages have support at which date is **unresolved**.

The review has not inspected certified Morrison filing/priority documents. GB2600765.8 and the related filings named in the earlier report cannot be assigned a verified effective date here. The two US publications are comparison leads, not conclusions about their legal effect on a UK filing.

## 3. Element-by-element comparisons

### S1 — PACE

| Element | Inspected disclosure |
|---|---|
| E1 | Finite represented provenance/effect domain; exact AOE equivalence NE. |
| E2 | Concrete-call capability/effect verification. |
| E3 | Separate path-chain check over episode provenance; scoped candidate mapping. |
| E4 | Conditional represented-path separation; arbitrary global-state equivalence NE. |
| E5 | Trusted mediator; hardened distributed protocol specified. |
| E6 | Certified configuration checks before dispatch. |
| E7 | Certificates and append-only records; hardened state/policy/action bindings. |

**Narrow features:** R: global reservation specified, not clearly reservation-inclusive trajectory semantics. D: blocks recorded, but refused/cancelled proposals excluded from active graph. V: certified contract combines both checks; evaluated restoration/repair configuration differs. B: state version, policy epoch and manifest/proposal digests.

**Demonstration:** in-process prototype; distributed hardening not evaluated. Full target NE. See §§4 and C.3; do not transfer certified-contract guarantees to the evaluated configuration.

### S2 — Provenact / MasuGate

| Element | Inspected disclosure |
|---|---|
| E1 | Bounded policies over certified state views. |
| E2 | Normalized governed requests and policy guards. |
| E3 | Shared-state evaluation; distinct local/global verdict pair NE. |
| E4 | Policy-state serializability addresses joint budget/inventory violations. |
| E5 | Runtime/provider boundary; complete mediation required. |
| E6 | Decision protected through governed commit; escalation supported. |
| E7 | Records link request, rules, state reads, decision and effect. |

**Narrow features:** R: holds/reservations supported; semantic-reachability interpretation NE. D: denials recorded; later semantic effect NE. V: exact strictest local/global pair NE. B: structured state/decision linkage; cryptographic trajectory binding NE in v1.

**Demonstration:** PostgreSQL prototype and scripted procurement; external-effect protocol left for future work (§6). MasuGate's later release adds integrations and flags corrected evidence/checker boundaries. Full target NE; later release claims are not backdated to Provenact v1.

### S3 — L-DREA

| Element | Inspected disclosure |
|---|---|
| E1 | Declared predicate/threshold domain; full AOE equivalence NE. |
| E2 | Per-operation predicates and scoped permits. |
| E3 | Separate node/class conditions; composed-state reachability equivalence NE. |
| E4 | Class veto persists despite node-clean operations; exact composition target NE. |
| E5 | Independent authority/substrate tiers specified. |
| E6 | Permit and evidence commitment before actuation. |
| E7 | Signed permits, hash-linked records and replay basis. |

**Narrow features:** R: NE. D: persistent class flag, not established as refused-action semantic trajectory state. V: node/class non-compensatory veto is close overlap. B: operation/trace binding; exact action/ruleset/trajectory tuple NE.

**Demonstration:** software Tier-S evaluated; paper states assumption A3 is not satisfied by that evaluation. Hardware/TEE tiers specified separately. Full target NE. Inspect §§V-G/H, VI and XII rather than treating “global invariant” as semantic reachability.

### S4 — Controlled Agentic AI Systems

| Element | Inspected disclosure |
|---|---|
| E1 | Constraint-defined admissible action space. |
| E2 | Local governance operators. |
| E3 | Global joint-action operator for coupled constraints. |
| E4 | Joint projection addresses unsafe local combinations; sequential target NE. |
| E5 | Decision/governance separation; protected non-bypassable boundary NE. |
| E6 | Governance transforms proposals before executed actions. |
| E7 | Audit mapping includes state, proposals, joint action and constraints. |

**Narrow features:** R: NE. D: NE. V: projection/gating described; strictest separate-verdict mechanism NE. B: state/constraint/action trace; versioned tamper-evident binding NE.

**Demonstration:** controlled multi-agent simulation, not independently verified general-tool deployment. Full target NE. The multi-agent extension and experiment/discussion sections supply substantial local/global overlap without establishing unavoidable authority.

### S5 — ActPlane

| Element | Inspected disclosure |
|---|---|
| E1 | Declared bounded rule/label domain; exact AOE mapping NE. |
| E2 | OS event enforcement. |
| E3 | Cross-event history/flow conditions; separate global check NE. |
| E4 | Temporal/flow sequences constrained; full composition target NE. |
| E5 | eBPF kernel authority on covered operations. |
| E6 | Blocking before protected effects; hook coverage matters. |
| E7 | Rule/event feedback; full decision-bound evidence NE. |

**Narrow features:** R: NE. D: NE. V: exact pair NE. B: full binding NE.

**Demonstration:** reports coding/safety benchmarks, including indirect paths. Current documentation describes stale-gate invalidation. Full target NE; current feature dates unresolved. This source refutes a stateless-only characterization, without establishing Morrison's entire mechanism.

### S6 — CamQuery

| Element | Inspected disclosure |
|---|---|
| E1 | Whole-system provenance/security policies; bounded agent AOE NE. |
| E2 | Linux security-hook checks. |
| E3 | Provenance-history queries; separate local/global pair NE. |
| E4 | Preventive provenance policies; exact composition target NE. |
| E5 | In-kernel enforcement on covered hooks. |
| E6 | Kernel queries execute before actions. |
| E7 | Provenance capture; complete decision binding NE. |

**Narrow features:** R: NE. D: NE. V: NE. B: full binding NE.

**Demonstration:** evaluated runtime-security applications. Userspace/distributed queries support detection rather than guaranteed prevention. Full target NE. This older antecedent establishes why authority and history awareness must be compared separately.

### S7 — KedgeFlow

| Element | Inspected disclosure |
|---|---|
| E1 | Declared protected resource surface and predicates. |
| E2 | Exact-action admission. |
| E3 | Shared-capacity/concurrent-writer coordination; separate global verdict NE. |
| E4 | Addresses jointly unsafe capacity changes; full trajectory target NE. |
| E5 | Independent credential-holding gateway required. |
| E6 | Grants checked before protected mutation. |
| E7 | Proposal, evidence, grant and outcome bindings. |

**Narrow features:** R: capacity reservations; trajectory integration NE. D: NE. V: exact pair NE. B: action/evidence bindings; full trajectory equivalence NE.

**Demonstration:** v0.9 specification reports local verification/race suites; production conformance remains separate. Resource atomicity levels differ. Full target NE; a proposed protected boundary is still relevant disclosure.

### S8 — US20260127298A1

| Element | Inspected disclosure |
|---|---|
| E1 | Metric acceptance bands/control cycles; agent AOE equivalence NE. |
| E2 | Per-cycle metric gate. |
| E3 | Federated/window conditions; separate semantic global check NE. |
| E4 | Exact locally-safe/globally-prohibited composition prevention NE. |
| E5 | Deterministic/secure-element enforcement architecture described. |
| E6 | Proof/commit-before-actuation and safe-state gating described. |
| E7 | Policy/metric/outcome replay records linked to prior evidence. |

**Narrow features:** R: NE. D: violation/readmission state; denied-action semantic trajectory NE. V: non-compensatory metric gating, not established as local/global pair. B: policy/version and cycle evidence; exact action/trajectory binding NE.

**Demonstration:** worked examples and specifications do not independently establish the full target. Do not import L-DREA's later class-veto details into this publication. Relevant passages include replay records, metric evaluation order, window summaries and claims.

### S9 — US20260142827A1

| Element | Inspected disclosure |
|---|---|
| E1 | Sealed governance envelope for computational effects. |
| E2 | Canonicalized-effect validation. |
| E3 | Hierarchical/federated envelopes; separate composed-state check NE. |
| E4 | Exact unsafe-composition prevention NE. |
| E5 | External governance authority and constrained execution architecture. |
| E6 | Authorization required before effects. |
| E7 | Canonical effects, validation outcomes and linked audit records. |

**Narrow features:** R: NE. D: NE. V: all required governance domains must authorize; exact local/global pair NE. B: effect/envelope/audit continuity; exact semantic trajectory binding NE.

**Demonstration:** architecture and embodiments are disclosure, not independent deployment evidence. Full target NE. Neither multiple governance domains nor a globally ordered audit trail alone establishes E3/E4. Priority support must be traced by passage, not family label.

## 4. Result and correction of the earlier framing

**No single reference has yet been verified as disclosing the complete narrow combination.**

This remains a defensible report of verification status because each inspected candidate leaves at least one required mapping unresolved. It does not mean every candidate has been ruled out. PACE's dual checks and hardened protocol, Provenact's state/effect coupling, L-DREA's node/class veto and CAIS's explicit local/global operators materially strengthen the challenge to the earlier search.

The narrower R/D/V/B features must not be used to rescue the seven-element conclusion by silently changing the target. Conversely, partial matches to R/D/V/B must not be presented as disclosure of their whole combination. Exhaustive finite environment-state verification of the complete target was not established from this inspection for any of the nine entries.

**Demonstration result:** the inspected evidence does not establish a verified complete-target demonstration. This is not a claim that no such demonstration exists. This review did not reproduce benchmarks, audit all source code or test deployment bypass paths. Apply the same standard to Morrison: its complete mediation remains deployment-specific and cannot be established from decision-unit tests alone.

The earlier authority dichotomy is withdrawn as a general characterization. History-sensitive checks can run at kernel boundaries; framework or proxy location alone also does not decide mediation. Compare the protected surface, credentials, privilege isolation, state dependencies and bypass coverage of each implementation.

## 5. Search history and limits

### Preserved lineage

| Stage | Record | Treatment |
|---|---|---|
| 2 Oct 2026 | User-supplied 17-page *Adversarial Prior-Art Analysis — Local–Global Admissible Operating Envelope Enforcement* | Original remains unchanged; its footer and summary disclose reliance partly on abstracts/summaries. |
| 5 Oct, before this update | Prior-art section at baseline commit above | Verbatim snapshot retained; earlier references and findings retained in parent document with corrections identified. |
| 5 Oct, web-search pass | Public-web search, GitHub read, targeted full-text inspection | This supplement records new candidates, source locations, scope qualifications and open mappings. |
| This documentation commit | Parent corrections + supplement + historical snapshot | Separate commit; no runtime-code change or new experiment claimed. |

### Search method

Both available web-search engines were used. Searches covered exact wording, equivalent mechanisms, pre-2026 antecedents, current agent systems, OS provenance, multi-agent shielding, reservations, denied-attempt history, evidence binding and patent publications. Representative exact queries from the pass:

- `"Morrison-Runtime-Governance" "prior"`
- `"runtime enforcement" "local" "global" "audit"`
- `"shielding" "local" "global" multi agent safety`
- `"reference monitor" "denied" "history" policy`
- `"agent" "global" "local" "complete mediation"`
- `"agent" "reservation-aware" governance -Morrison`
- `"denied actions" "trajectory" -Morrison`
- `site:patents.google.com autonomous agent global local safety runtime authorization trajectory`
- `CamQuery runtime analysis whole system provenance policy enforcement 2018`
- `"agent" "local" "global" "enforcement" "audit" before:2026-01-01`
- `law governed interaction local global policy enforcement history audit Minsky`
- `"Deterministic Runtime Enforcement: The Execution Authority"`

These are a representative query record, not a complete raw search export or a reproducible index snapshot. Rankings, mutable pages and available versions may change.

Other inspected leads included [PCAS v1](https://arxiv.org/html/2602.16708v1), [AgentFlow](https://arxiv.org/html/2608.22868v1), [2024 compositional shielding](https://arxiv.org/html/2410.10460v1), [2021 multi-agent shielding](https://www.ifaamas.org/Proceedings/aamas2021/pdfs/p483.pdf), [Distributed Simplex](https://www3.cs.stonybrook.edu/~stoller/papers/SETTA2021.pdf), [Law-Governed Interaction](https://people.cs.rutgers.edu/~minsky/papers/coordination-and-control.pdf) and a [WebShield provisional document](https://www.webshield.io/patents/ai-trust-safety-2025-11.pdf). They remain search-history leads, not completed new claim charts or verified earlier qualifying disclosures. In particular, a filing date printed on a hosted provisional PDF does not establish its public availability on that date.

### Review limits and next evidence

- This supplement charts the nine requested additions/updates. Earlier references remain in the parent/history; they have not all received new full-text charts in this update.
- Targeted passages were inspected, not every page, citation, patent-family member or repository commit. Search snippets alone were not treated as complete-target evidence.
- Some arXiv HTML requests failed; successful primary text, paper records or project documentation supplied the bounded observations recorded above.
- Patent text was inspected through Google Patents; official file histories, priority support and legal qualification were not independently checked.
- Missing evidence is marked NE. None of these entries establishes novelty or a universal absence of competing work.
- Next work: confirm Morrison claim-specific priority; pin mutable documentation; inspect relevant code/versions and patent support; distinguish candidate architectural disclosure from measured complete mediation; attempt independent reproduction for the demonstration question.
