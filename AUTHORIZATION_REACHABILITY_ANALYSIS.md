<div align="center">

![Status](https://img.shields.io/badge/Status-Analysis_·_No_code_change-1f2937?style=flat-square)
![Question](https://img.shields.io/badge/Question-Can_authority_leakage_be_reachability%3F-0f766e?style=flat-square)
![Verdict](https://img.shields.io/badge/Verdict-Yes_for_one_cluster_·_No_for_three-c2410c?style=flat-square)
![Formalism](https://img.shields.io/badge/Set_inclusion-Insufficient-b91c1c?style=flat-square)
![Patent](https://img.shields.io/badge/Patent-GB2600765.8-0075ca?style=flat-square)
![©](https://img.shields.io/badge/©-Davarn_Morrison-555555?style=flat-square)

</div>

# Authorization as Reachability — An Investigation, Not Yet a Formalism

*"The question is whether authority leakage is a reachability phenomenon. It is
— for exactly one of the four failure clusters. Claiming it for the other three
would be the same mistake we spent four rounds removing."*

*— Davarn Morrison, 2026*

---

**This document changes no code and adopts no invariant.** It tests a candidate
formulation against the existing counterexample record, reports where it holds
and where it fails, and proposes the smallest defensible change together with a
test plan. Companion to
[AUTHORITY_SEPARATION.md](AUTHORITY_SEPARATION.md).

---

## 1 · The two meanings of identity, kept apart

Two distinct concepts are in play and the analysis depends on not merging them.

| | **System identity** | **Execution identity** |
| :-- | :-- | :-- |
| Definition | `𝓘(x₀) := [𝓡(t)]_∼` | the continuity key `(tenant, principal, workload)` |
| Type | equivalence class of reachable futures | an index / label |
| Answers | *what this system is* | *who is exercising authority* |
| Role | output of the dynamics | input that selects the dynamics |

The bridge is a composition, not an equivalence:

```text
    p  ──►  T_p  ──►  𝓡_p(x₀)  ──►  [𝓡_p(x₀)]_∼
   who     which        what is        what kind of
  acts   transitions    reachable      system that is
          are allowed
```

**Principal identity indexes; system identity classifies.** They are related by
this composition and are not the same object at any point along it.

This immediately yields a result. **MED-01 is a failure of injectivity of the
first arrow.** `("acme","agent-x/y")` and `("acme","agent-x_y")` mapped to one
key, so two distinct principals selected the *same* transition relation and
therefore the same reachable set. The failure is expressible in reachability
language — but as non-injectivity of an indexing map, not as a property of any
equivalence class.

---

## 2 · The candidate formulation

> `𝓡_α^actual(x₀) ⊆ 𝓡_α^authorized(x₀)`
>
> The futures made reachable by exercising authorization `α` must never exceed
> the futures that authorization was intended to make reachable.

Call this **containment**. It is a genuine and useful idea. Tested below.

A second, independent condition is required and is frequently confused with it:

> `𝓡^actual(x₀) ⊆ ⋃_α 𝓡_α^authorized(x₀)`

Call this **covering** — every reachable effect is attributable to *some*
authorization. This is exactly **T1 / complete mediation**, restated. Containment
says authorizations are not too generous; covering says nothing escapes the
authorization mechanism. **Neither implies the other**, and conflating them is
the single most likely way this formalism could mislead.

---

## 3 · What containment explains

Applied to the counterexample record. Each row is a case where the mechanism
made more transitions reachable than intended.

| Cluster | Counterexamples | Why containment fits |
| :-- | :-- | :-- |
| **Action binding** | ATK-01, ATK-02, ATK-03, L-04, L-05, VETO-03 | `α` authorized edge `a`, execution took edge `a′ ≠ a`. The authorized edge set was wrong, so actual reach exceeded it. |
| **Multiplicity** | VETO-07, CONT-02, L-02, L-09 | One `α` yielded *n > 1* traversals. Reach expands with each. |
| **History truncation** | VETO-01, VETO-10, CONT-01, CONT-04, CONT-06, CONT-07, CONT-09, MED-04, **MED-11** | The authorized set is computed from history `h`. Using `h′ ⊊ h` computes a *larger* authorized set than the true one. |
| **Staleness / time** | VETO-02, ATK-05, MED-03, MED-13, L-07 | The authorized set is time- and policy-indexed. Redeeming against a stale index admits edges the current index forbids. |
| **Identity** | MED-01, CONT-05 (pinned) | Non-injective indexing merges two principals' authorized sets. |
| **Partial effect** | ATK-04 | An effect landed outside the authorized trace; `release()` then treated the trace as untaken. |

This is the largest cluster and it is **precisely the cluster the recent
failures occupied** — binding, identity, continuity. On this evidence,
containment is a real and explanatory idea.

### 3.1 MED-11 stated rigorously

Containment gives the cleanest formal statement yet of an open limitation.
Because more history only ever *restricts* (§5, A4), computing from a local
history yields an over-approximation:

```text
    𝓡_α^authorized(x₀ | h_local)  ⊇  𝓡_α^authorized(x₀ | h_true)
```

The system bounds actual reach against the **left** side. MED-11 is exactly the
gap between the two sides, and R4B-05 is the fact that the size of that gap is
*attested by the store*, not verified. **This does not close either limitation.**
It says what they are.

---

## 4 · What containment does not explain

Three clusters, stated as plainly as the successes.

### 4.1 Availability — the dual direction

| Counterexamples | Why containment is silent |
| :-- | :-- |
| ATK-06, ATK-08, R4B-01, R4B-02, R4B-03 | These are `𝓡^actual ⊊ 𝓡^intended` — legitimate futures became *un*reachable. Containment is satisfied perfectly by a system that authorizes nothing. |

A governance layer a deployment cannot live with gets configured away, so these
were real findings. Containment cannot express them, and a formalism that scores
"deny everything" as perfect is dangerous if used alone as a design target.

### 4.2 Observability — knowledge, not reachability

| Counterexamples | Why containment is silent |
| :-- | :-- |
| MED-05, MED-06, MED-10, R4B-04, **R4B-05** | These concern the mismatch between *what happened* and *what the system knows happened*. An executor that acts then raises leaves reach unchanged in the model and the record wrong. |

Reachability is a property of the transition system. These are properties of the
**evidence chain about** the transition system. Different object.

### 4.3 Specification correctness — class C

| Counterexamples | Why containment is silent |
| :-- | :-- |
| VETO-04, VETO-05, VETO-06, VETO-11, MED-02, ATK-07, and Ω-correctness generally | Containment can hold *perfectly* while harm occurs, if Ω or the manifest is wrong. Both sides of the inclusion are computed from the same declaration. |

**This is the most important negative result.** Containment is a *relative*
guarantee — actual never exceeds intended — and is entirely silent on whether
*intended* was correct. It cannot be used to argue safety.

### 4.4 Covering failures need the other condition

VETO-08, VETO-08b, VETO-09, VETO-12 and MED-12 are cases where **no `α` existed
at all**. `𝓡_α^actual ⊆ 𝓡_α^authorized` is vacuously true when there is no `α`
to index by. These require the covering condition of §2, i.e. T1.

---

## 5 · Is set inclusion sufficient? No — and there is direct evidence

Five reasons, the first of which is empirical rather than argued.

### 5.1 Multiplicity is invisible to a state-set formalism — measured

A probe run against the current implementation (scratch, not committed):
authorize an **idempotent** read, execute it, then replay the same decision.

```text
  1st execute  →  (True,  'V1')          executor invoked
  2nd execute  →  (False, 'refused: decision has already been used;
                           a PERMIT authorises one execution of one transition')
  executor invocations: exactly 1
```

The reachable **state set** is identical whether the read happens once or twice.
A guarantee phrased as `𝓡^actual ⊆ 𝓡^authorized` therefore **cannot distinguish
the two**, and would rate a replay as compliant.

The implementation refuses it anyway. **The code already enforces a trace
property that the proposed formalism cannot express.** Adopting set inclusion as
the invariant would be a formal *weakening* of what is currently true.

### 5.2 Effects outside the state abstraction

A pure disclosure — data read and exfiltrated — may leave the modeled state
unchanged while being the entire harm. Any state-reachability formulation
inherits the fidelity of its state abstraction, which is an input (T6/L5).

### 5.3 The authorized set is not a function of `x₀` alone

Every history-truncation and staleness counterexample shows the real object is

```text
    𝓡_α^authorized( x₀ │ h, ρ, τ, p )
        h = governed history      ρ = policy version
        τ = redemption time       p = principal
```

Written as `𝓡_α^authorized(x₀)` the formulation is under-specified, and the
under-specification is exactly where MED-03, MED-04, MED-13 and MED-11 live.

### 5.4 One inclusion, two conditions

Containment and covering are independent (§2, §4.4) and need stating separately.

### 5.5 Direction

Inclusion is one-sided and cannot express the availability cluster (§4.1).

### Conclusion

**Set inclusion over reachable states is necessary but not sufficient.** The
defensible object is inclusion over **authorized traces with multiplicity** — a
labelled transition system in which an authorization is a *token that is spent*,
not a region that is entered.

---

## 6 · On `𝓘_α(x₀) = [𝓡_α(x₀)]_∼` — coherent, but do not adopt it

**It is well-formed.** `𝓡_α(x₀)` is a set of reachable states; applying `[·]_∼`
is defined wherever `∼` is defined on such sets. No formal objection.

**It is nonetheless the wrong tool, for a precise reason.** The quotient map

```text
    π : 𝓡  ⟼  [𝓡]_∼
```

is deliberately **not injective**. Forgetting detail is what makes `𝓘(x₀)` a
useful notion of identity — identity persists *through* change. But the facts
authorization containment depends on are exactly the facts `π` discards: *which*
edge, *how many times*, *issued to whom*, *valid until when*.

Concretely: an authorization to transfer **$1** and an authorization to transfer
**$4,500,000** plausibly induce topologically equivalent reachable sets — each a
single edge out of `x₀`. `𝓘_α` identifies them. Distinguishing them is the whole
job. **CONT-02 is invisible under `𝓘_α`.**

> **Authority separation lives below the quotient. System identity lives above
> it. `π` is the bridge, and `π` being non-injective is precisely why the two
> must not be conflated** — authorization violations are not recoverable from
> identity data.

**Recommendation: do not adopt `𝓘_α` as an authorization invariant.** It may be
retained as a *non-load-bearing descriptor* — "what kind of system does this
authorization turn the agent into" — useful for coarse capability
classification, and it must never enter the veto path.

---

## 7 · New falsifiable invariants that follow

Two are new and were probed for this analysis. The probes are bounded searches,
**not proofs**, and are reported as such.

| # | Invariant | Status |
| :-: | :-- | :-- |
| **A1** | **Containment.** The realized trace lies in the authorized trace set. | Existing, distributed across many tests |
| **A2** | **Covering.** Every effect is attributable to some `α`. | = T1. Deployment property, **not closable here** |
| **A3** | **Injectivity.** `p₁ ≠ p₂ ⟹ key(p₁) ≠ key(p₂)`. | MED-01 was the counterexample; now pinned |
| **A4** | **History antitonicity.** `h ⊆ h′ ⟹ Auth(·│h′) ⊆ Auth(·│h)`. Adding history must never turn a refusal into a permission. | **NEW.** Probed: 80 history/target combinations, **0 violations**. Not currently an explicit test. |
| **A5** | **Policy antitonicity at redemption.** Tightening `ρ` never enlarges an outstanding `α`'s authorized set. | MED-03 was the counterexample; implicitly held by the live ruleset hash, not stated as an invariant |
| **A6** | **No amplification.** One `α` yields at most one effect, *including when the action is idempotent*. | **NEW framing.** Probed: executor invoked exactly once, replay refused. |
| **A7** | **Scope honesty.** `Auth(·│h_local) ⊇ Auth(·│h_true)`; guarantees bound only against the local set. | Formal statement of **MED-11 / R4B-05**. Both remain **open**. |

A4 is the highest-value new candidate: it is cheap to test, currently unstated,
and its violation would mean history can *manufacture* authority — which would
undermine the trajectory-dependence property the continuity work rests on.

---

## 8 · Assumptions the formulation requires

1. The state abstraction represents the effects that matter (T6/L5). Inherited,
   not established.
2. The trace model is faithful — every consequential effect appears as a
   labelled transition. Violated by any effect the transition model omits.
3. `Ω`, capability policy and manifest are correct. Containment is silent on
   this (§4.3).
4. Covering (T1) holds for the boundary under discussion, otherwise containment
   is vacuous where it matters most.
5. Key custody: `k ∉ 𝔄`. An agent that can mint `α` satisfies containment
   trivially and meaninglessly.
6. `∼` is never used in the veto path (§6).

---

## 9 · What would disprove this

Stated so the formulation is falsifiable rather than decorative.

| # | Counterexample that would disprove | What it would show |
| :-: | :-- | :-- |
| **D1** | A binding/identity/continuity failure that **cannot** be expressed as unintended reach expansion | §3 is not a real cluster; the unification fails |
| **D2** | Containment provably holds, yet a prohibited effect occurs | Containment is **not sufficient** for safety — expected via §4.3, and a concrete instance would settle it |
| **D3** | Containment is violated with **no** security consequence in any deployment | Containment is not *necessary*; too strong as an invariant |
| **D4** | An A4 violation — some history that turns a refusal into a permission | History can manufacture authority; the trajectory-dependence property is unsound |
| **D5** | A single `α` producing two effects that the trace model records as one | The trace formulation inherits the state-abstraction gap it was meant to fix |
| **D6** | Two authorizations with materially different consequence that are **provably** equivalent under `∼` | Confirms §6 — would close the question of whether `𝓘_α` is usable |

**D4 is the cheapest to attack and the most informative.** D2 is expected to
succeed, and demonstrating it would be a contribution, not a defeat.

---

## 10 · Smallest mathematically defensible change

Deliberately minimal. Four items, none of which touches the implementation.

1. **Do not adopt `𝓘_α` as an invariant.** Record it as a non-load-bearing
   descriptor with the §6 argument for why it cannot carry the veto.
2. **State containment over traces, not state sets**, with the authorized set
   explicitly indexed `(x₀ │ h, ρ, τ, p)`. This matches what the code already
   enforces (§5.1) rather than weakening it.
3. **Separate containment from covering** in all prose, and identify covering
   with T1 so it inherits the existing open-limitation treatment.
4. **Add A4 and A6 as named invariants** with tests. Adopt A7 as the formal
   statement of MED-11/R4B-05 — **as a restatement, not a closure.**

Explicitly **not** proposed: replacing authority separation as the primary
property; changing the derived status of Ω-exclusion; any claim that containment
implies safety; any narrowing of the open limitations.

### Test plan, before any code change

| Step | Test | Expected | Falsifies |
| :-: | :-- | :-- | :-- |
| 1 | **A4 exhaustive** — widen the probe to the full tool manifest, `r ≤ 3`, both orderings, with and without approvals | no refusal becomes a permission | D4 |
| 2 | **A4 adversarial** — construct history specifically to *unlock*: denied-then-approved, expired-then-renewed, cross-workload | no unlock | D4 |
| 3 | **A6 idempotent probe** as a committed regression test | executor invoked exactly once | D5 |
| 4 | **A3 fuzz** — random principal/tenant/workload triples through `ContinuityKey.fingerprint`, assert no collisions | injective | — |
| 5 | **A5 explicit** — mint `α` under `ρ₀`, tighten to `ρ₁`, redeem | refused | — |
| 6 | **D2 hunt** — deliberately mis-specify Ω, verify containment still holds while harm occurs | containment holds, harm occurs | confirms §4.3 |

Steps 1–2 first: if A4 fails, §3's history-truncation cluster needs rethinking
before anything is built on it.

---

## 11 · Verdict

Containment **does** unify the binding, identity, continuity, multiplicity and
staleness failures — the cluster the recent rounds actually occupied — and it
gives MED-11 its cleanest formal statement to date.

It **does not** unify availability, observability, or specification-correctness
failures, and it is silent on whether the authorized set was ever the right one.
Roughly **two-thirds** of the counterexample record falls inside it.

Set inclusion over states is too weak to adopt: the implementation already
enforces a strictly stronger trace property, demonstrated by measurement.

`𝓘_α` is coherent and should not be adopted, because the quotient discards
exactly what authorization depends on.

**No limitation is closed by this analysis. No claim is strengthened.**

---

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   Authority separation lives BELOW the quotient.                 ║
║   System identity lives ABOVE it.                                ║
║                                                                  ║
║   π : 𝓡 ⟼ [𝓡]_∼   is not injective —                            ║
║   which is exactly why the two must not be conflated.            ║
║                                                                  ║
║   Morrison Runtime Governance™          GB2600765.8              ║
╚══════════════════════════════════════════════════════════════════╝
```

---

Morrison Runtime Governance™ · Morrison Framework™ · Authorization as Reachability

GB2600765.8 · GB2602013.1 · GB2602072.7 · GB26023332.5

© 2026 Davarn Morrison — Intelligence Invariant™ · All Rights Reserved

**Related work:**
[Authority Separation](AUTHORITY_SEPARATION.md) ·
[Pre-Pilot Adversarial Evaluation](PRE_PILOT_ADVERSARIAL_EVALUATION.md) ·
[Complete Mediation Analysis](COMPLETE_MEDIATION_ANALYSIS.md) ·
[Pilot Briefing Card](PILOT_BRIEFING_CARD.md) ·
[Limitations](morrison_governance/LIMITATIONS.md)
