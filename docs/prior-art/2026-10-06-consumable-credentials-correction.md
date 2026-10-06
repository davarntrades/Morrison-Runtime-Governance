# Consumable Credentials: autonomous-agent scope correction

> **Combination assessment qualification, 6 October 2026:** subsequent evidence audit withdraws an established strong/short motivated combination characterization. Component mechanisms remain relevant; qualifying timeline, contemporaneous motivation and integrated target remain unestablished. See [controlling combination audit](2026-10-06-combination-evidence-audit.md). Earlier text is preserved as search history.

**Review date:** 2026-10-06. **Corrected commit:** `fc5201dab5ba31380cce3140fdaf5e722a0ad1af`.

The “complete technical match” conclusion is withdrawn. The review broadened the requested target, treating an authorization client as an autonomous proposing component and consumable-resource accounting as the required bounded agent trajectory. Those substitutions require justification from the reference; adaptability is insufficient. This correction does not establish novelty, non-obviousness or Morrison's operational safety.

## Original reference and dates

Bauer, Bowers, Pfenning and Reiter, [Consumable Credentials in Logic-Based Access Control, CMU-CyLab-06-002](https://www.cs.cmu.edu/~fp/papers/CMU-CYLAB-06-002.pdf). Report date: **2006-02-10**. Historical public-release date: not independently established here. Patent filing/priority: not applicable to this report's bibliographic date; no associated patent date inferred. Inspection: **2026-10-06**. All page locators below use printed pages (PDF viewer page = printed page + 1). The 2007 successor is a separate reference and cannot supply missing 2006 disclosure.

## Element-by-element assessment

Categories: **EXPLICITLY DISCLOSED**, **NECESSARILY INHERENT**, **ANALOGOUS BUT REQUIRES ADAPTATION**, **NOT ESTABLISHED**. The latter two do not satisfy the target. “Not established” does not mean absent. A component disclosure does not establish the full conjunction.

| Target element | Classification against the target | Original locator and assessment |
|---|---|---|
| Autonomous decision-making component producing proposed actions | **NOT ESTABLISHED** | §§4, 7, pp.12,16. A requester and automated proof construction are described. Autonomous selection of proposed environmental actions is not established. |
| Independent authority separate from the proposing component | **ANALOGOUS BUT REQUIRES ADAPTATION** | §§4–5, pp.12–14. Requester/authority separation is **EXPLICITLY DISCLOSED** as a component mechanism. Its integration with the required autonomous proposer is not established. |
| Unavoidable pre-execution mediation of those agent proposals; execution dependent on authorization | **ANALOGOUS BUT REQUIRES ADAPTATION** | §4 p.12; §6 pp.14–15. Proof precedes protected resource release. Complete mediation of the target agent's effect surface requires an additional architectural mapping. |
| Bounded agent operating environment | **ANALOGOUS BUT REQUIRES ADAPTATION** | §3.3 p.9. Bounded credential use is explicit; an autonomous-agent state/action environment is not established by that bound. |
| Local/per-transition admissibility | **ANALOGOUS BUT REQUIRES ADAPTATION** | §§3.2–3.3 pp.6–8. Local proof checking is explicit. Its correspondence to the required agent-transition predicate needs a disclosed encoding. |
| Separate global/trajectory admissibility | **ANALOGOUS BUT REQUIRES ADAPTATION** | §3.3 pp.7–9; §4 pp.10–12. Global consumption accounting is explicit. The target's agent-state/trajectory evaluation is not established. |
| Rejection of a locally acceptable action because composition produces a globally prohibited state | **ANALOGOUS BUT REQUIRES ADAPTATION** | §3.3 pp.7–9; §4 pp.10–12. Exhausted credentials prevent ratification despite a potential proof. The autonomous-agent composition mapping remains unestablished. |
| Decision-bound evidence associated with action, governing rules/state and relevant trajectory | **NOT ESTABLISHED** | §3.1 p.5; §§3.3–4 pp.8–12. Signed consent binds credential statement, proof and goal; action includes parameters/nonce. Binding the relevant agent trajectory and governing state is not established. |

No missing element is classified NECESSARILY INHERENT. A human-initiated requester with automated authorization proofs could implement the disclosed mechanism without an autonomous action-selection component. Therefore the latter does not follow necessarily from the former. This is an inference about necessity, not an assertion that autonomous agents did not exist in 2006.

The separate local/global distinction must remain credited. Correcting the full-match error does not justify describing this work as stateless or limited to isolated call arguments. Likewise, its proof-bound authorization cannot accurately be reduced to an after-the-fact audit log. The failure is the unsupported mapping to the complete target.

## Narrower implementation features

| Feature | Classification | Reason / locator |
|---|---|---|
| Reserved actions change semantic agent-trajectory state | **ANALOGOUS BUT REQUIRES ADAPTATION** | Consumption before resource access and atomic ratification (§§3.3–5, pp.8–14) are relevant machinery. The agent reservation lifecycle remains unestablished. |
| Relevant denied attempts change later semantic trajectory adjudication | **NOT ESTABLISHED** | §5 pp.12–14 does not establish this target feature. Failed atomic ratification is not evidence of semantic denied-attempt accumulation. |
| Strictest-verdict composition | **ANALOGOUS BUT REQUIRES ADAPTATION** | Joint proof/ratification prerequisites (§§3.3–5) supply conjunctive authorization. Separate agent local/global verdict composition remains unestablished. |
| Evidence binds action, governing rules/state and relevant trajectory | **NOT ESTABLISHED** | See evidence row above. A signed successful ratification is not by itself proof of the required trajectory binding. |

## Single-reference disclosure versus combination pressure

**Single-reference conclusion:** complete disclosure of this autonomous-agent combination has not been established in C06. Withdraw the finding of technical anticipation; do not repair it by importing the 2007 paper, Morrison's implementation, or later agent architectures.

**Component/combination conclusion:** retain C06 as relevant authorization, global consumption and proof-binding component prior art. The previous C06-plus-Schneider lead is a candidate combination, not a demonstrated reconstruction of the complete target. It still needs an evidenced autonomous proposer, bounded state/action semantics, distinct checks with the required composition behavior, mandatory effect mediation, and evidence covering the relevant governing state and trajectory. Some work may be ordinary integration; that is not established merely by listing mechanisms. No legal obviousness determination follows.

An adequate combination analysis must identify each additional dated source, its exact contribution, why the combination would have been made, and what changes are required. All earlier-reference relevance remains dependent on confirmed Morrison claim-specific priority and supported historical availability. This correction does not resolve those facts.

## Four separate conclusions

1. **Prior art: unresolved overall; C06 complete match withdrawn.** No single reference has yet been verified as disclosing the complete narrow autonomous-agent combination in the corrected assessment. This is a verification status, not an exhaustive search conclusion. Other conditional complete-match claims in the earlier review require remapping before being adopted under this scope.
2. **Combination pressure:** C06 plus trace enforcement remains relevant component pressure, with the architectural and evidence integration listed above unresolved. One-reference sufficiency is withdrawn.
3. **External demonstration: complete target not verified.** C06 §7 pp.16–18 reports a ratification prototype and timings; that does not establish demonstration of this autonomous-agent property. This correction includes no new external reproduction.
4. **Morrison demonstration:** unchanged by the bibliographic correction. The prior review records selected passing tests, finite-model unsafe traces and a released-lease composition failure. Complete deployed safety still depends on complete mediation, correct specification, bounded-model coverage, trusted-state integrity, credential/key custody and execution-boundary integrity. Repeat the released-lease trace through an isolated real gateway with a resource-side effect ledger, including concurrency and restart, to test whether the prohibited composition is reachable in deployment.

## Preservation and validation

The [pre-correction main document](history/2026-10-06-before-agent-scope-correction.md) is preserved verbatim. The [5 October review](2026-10-05-adversarial-review.md) retains its original text beneath an explicit correction notice; source registers, prior searches and reproduction artifacts are retained. This is a documentation-only correction. Validation checks archive equality against the previous commit, relative links and the patch; runtime tests are not rerun because no runtime behavior changes.
