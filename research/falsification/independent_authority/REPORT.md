# Independent Authority Falsification Study

**Status:** falsification study. Adversarial, not confirmatory.
**Scope:** bounded finite models. Nothing here establishes a property of any
deployed system.
**Result:** both hypotheses as stated are **FALSIFIED**. Narrower claims survive.

---

## 1. Research Questions

**A.** Can independent execution authority make declared prohibited states
unreachable while preserving admissible capability?

**B.** Can independent evidence authority make executed consequential
transitions independently reconstructable even when the governed party
controls, suppresses, modifies, or contradicts its own telemetry?

**C.** What additional assumptions are required for either property to hold?

The short answers: **A — yes, but only under an antecedent that the attacks
break.** **B — no.** **C — the two properties turn out to share one antecedent,
which is the most consequential finding here.**

---

## 2. Definitions

| Term | Definition as used |
| :--- | :--- |
| `E` | finite, deterministic, fully observable environment |
| `X0` | admissible initial states |
| `Ω` | declared prohibited set, defined as state predicates |
| `T` | transition system |
| `G` | independent execution authority |
| `Reach_T(X0)` | states reachable without governance |
| `Reach_G(X0)` | states reachable when every transition is mediated by `G` |
| `L_V` | vendor-controlled evidence |
| `L_I` | independently controlled evidence |
| **Executed reality** | consequential transitions actually committed to the external world |
| **Recorded reality** | transitions an independent verifier can reconstruct from `L_I` |
| **Integrity** | `Verify(L_I) = VALID` — hashes, chain links, signatures |
| **Completeness** | every executed consequential transition appears in `L_I` |
| **Soundness** | every transition in `L_I` was actually executed |
| **Undetected divergence** | executed ≠ recorded **and** `Verify(L_I) = VALID` |
| **Undetected harm** | a real prohibited consequence occurred and no `Ω` predicate registered it |

Two distinctions are load-bearing and are kept apart throughout:
**Ω-unreachability ≠ harm-freedom**, and **integrity ≠ completeness**.

---

## 3. Hypotheses

**H1.** If every executable transition is causally mediated by `G`, and `G`
rejects every transition whose execution would enter `Ω`, then
`Reach_G(X0) ∩ Ω = ∅` while admissible capability remains reachable.

**H2.** For every consequential executed transition, an independently
controlled tamper-evident evidence system preserves enough information for an
independent verifier to establish that the transition occurred, even when
vendor telemetry is deleted, modified, withheld, contradicted or fabricated.

**H2′ (stronger candidate).** If consequential execution is causally dependent
on successful independent evidence commitment, then no consequential transition
can execute without producing independently verifiable evidence.

---

## 4. Experimental Assumptions

Stated up front because several attacks work by violating exactly these.

1. Finite, deterministic, fully observable environment.
2. `Ω` is expressible as predicates over the modeled state vector.
3. Declared action semantics equal actual transition semantics.
4. Every executable transition passes through the modeled channel.
5. Authorization and commit are atomic.
6. A single agent; no unmediated delegates.
7. The evidence recorder observes every consequential execution.
8. The evidence writer is honest.

Assumptions 3–8 are each falsified below. **Assumption 4 is the one that
matters most**, for reasons given in §7.

### Harness expressiveness (stated, not worked around)

Morrison's `ExhaustiveVerifier` computes the successor and the governance
decision inside one indivisible step, and `_is_executable` is **total** — every
edge is mediated *by construction*. The production harness therefore
**structurally cannot express** bypass, delegation, effect divergence, TOCTOU,
or mutation-before-commit. It assumes H1's antecedent rather than testing it.

That inexpressibility is itself a finding. To test those attacks at all, this
study adds `MediatedExecutor`, which splits the step into
`propose → authorize → interfere → execute → commit`. It is an **experimental
harness**, explicitly not a replacement governance architecture. The H1
baseline (§5) uses Morrison's real verifier unchanged.

---

## 5. H1 — Independent Execution Authority

### Baseline

Independently constructed environment (`h1_model.py`), not reused from
`global_verification.scenarios`, so this is a reproduction rather than a re-run.
Exhaustive BFS via Morrison's production `ExhaustiveVerifier`. No sampling.

| | Control (no `G`) | Governed (oracle `G`) |
| :--- | ---: | ---: |
| Verdict | `UNSAFE_COUNTEREXAMPLE_FOUND` | `SAFE_WITHIN_MODEL` |
| Complete enumeration | yes | yes |
| Reachable states | **48** | **8** |
| Reachable `Ω` states | **40** | **0** |
| Executed edges | 1010 | 15 |
| Blocked edges | 0 | 43 (all `Ω`-entering) |
| Shortest `Ω` path | 1 | — |
| Admissible capability preserved | — | **all 3 of 3** |

**Disagreement with the preliminary figures.** The preliminary experiment
reported 12 states / 9 prohibited → 3 / 0. This study reports 48 / 40 → 8 / 0.
The counts differ because the model is independently constructed and larger.
The *qualitative* result reproduces; the specific integers do not, and should
not be cited as reproduced. Any claim resting on "12 states, 9 prohibited" is a
claim about one particular model, not about the principle.

### Exhaustive Results

`Reach_G(X0) ∩ Ω = ∅` holds within the model, with admissible capability fully
preserved. **This is the ceiling, not the finding.** It was obtained with an
oracle authority that evaluates the *actual successor state*. Real governance
evaluates a *declared proposal*. §5 adversarial tests attack that gap.

### Adversarial Tests

14 attacks. **8 falsify, across 5 distinct categories.**

| ID | Attack | Ω reached | Real harm | Undetected | Category |
| :--- | :--- | :--- | :--- | :--- | :--- |
| A01 | direct prohibited transition | no | no | no | — |
| A02 | multi-step prohibited trajectory | no | no | no | — |
| A03 | admissible composition reaching Ω | no | no | no | — |
| A04 | context-dependent transition | no | no | no | — |
| A05 | history-dependent transition | no | no | no | — |
| A06 | state alias / semantic mismatch | no | **yes** | **yes** | 2 AOE_SPEC |
| A07 | omitted state variable | no | **yes** | **yes** | 3 ENV_MODEL |
| A08 | omitted transition (out-of-model) | no | no | no | — |
| A09 | governance-boundary bypass | **yes** | — | no | 5 BYPASS |
| A10 | multi-agent delegation (unmediated) | **yes** | — | no | 5 BYPASS |
| A11 | effect divergence (declared ≠ actual) | **yes** | — | no | 4 SEMANTICS |
| A12 | time-dependent transition | **yes** | — | no | 4 SEMANTICS |
| A13 | TOCTOU: state changes before commit | **yes** | — | no | 1 PRINCIPLE |
| A14 | environment mutation before commit | **yes** | — | no | 1 PRINCIPLE |

Categories are **not collapsed**. A09/A10 violate H1's *antecedent* (mediation)
rather than its consequent — they are not evidence against the principle.
A11/A12 defeat an authority that reasons over declarations. A13/A14 are the
serious ones: **the authority was neither bypassed nor lied to**, and `Ω` was
still entered.

### Counterexamples

**A06/A07 deserve separate emphasis.** They report `Ω reached = false` — and
that is precisely the problem. A real prohibited consequence occurred and *no
predicate ranged over it*. An earlier draft of this harness scored these as
"H1 survived". That was wrong, and it is the exact error the study exists to
catch: **a model that cannot see a harm reports safety.**

> **Ω-unreachability is a property of the model, not of the world.**

### Surviving Claim

> Within a bounded model, given (i) complete mediation of every executable
> transition, (ii) authority evaluation over the **actual successor state**
> rather than the declared proposal, (iii) atomicity of authorization and
> commit, and (iv) an `Ω` specification that ranges over every consequence the
> environment can produce — independent execution authority makes `Ω`
> unreachable while preserving admissible capability.

Every one of (i)–(iv) is an assumption, and each is individually falsifiable.
**H1 as originally stated is falsified**; the conditional above survives.

---

## 6. H2 — Independent Evidence Authority

### Baseline

`L_I` is Morrison's **real** `EvidenceChain` / `EvidenceRecord` — SHA-256
record hashes, `prev_hash` chaining, HMAC signatures, fail-closed invariant.
`L_V` is a plain mutable list.

Vendor-side attacks (withhold + delete + modify, all three at once):

| Metric | Result |
| :--- | :--- |
| Completeness | **1.00** |
| Integrity | VALID |
| Strong unhideability | **holds** |

**Simple vendor manipulation does not falsify H2.** This reproduces the
preliminary finding.

### 64-Combination Reproduction

Exhaustive enumeration of all `2^6 = 64` fault combinations. Independently
recomputed, not assumed.

| | Count |
| :--- | ---: |
| Total combinations | 64 |
| Strong unhideability **holds** | **8** |
| **Fails** | **56** |
| Undetected divergence | 56 |

**The preliminary 8/64 and 56/64 counts reproduce exactly.**

Three single faults each break the property alone:

| Fault | Completeness | Soundness | Integrity | Undetected |
| :--- | :--- | :--- | :--- | :--- |
| `recorder_crash_before_commit` | **fails** | holds | **VALID** | **yes** |
| `execution_bypasses_recorder` | **fails** | holds | **VALID** | **yes** |
| `evidence_writer_compromised` | **fails** | **fails** | **VALID** | **yes** |

**A refinement the preliminary study does not make.** The 8/64 headline is
robust to how writer compromise is defined, but *the property being broken is
not*:

| Compromise semantics | Completeness | Soundness | Count |
| :--- | :--- | :--- | ---: |
| can omit records | **fails** (0.67) | fails | 8/64 |
| can only fabricate | holds (1.00) | **fails** | 8/64 |

Same number, different failure, different remedy. Citing "8/64" without
naming which property failed conflates an omission problem with a fabrication
problem.

### Integrity vs Completeness

The central result, reproduced against Morrison's real chain:

```
Executed reality :  x0 → x1 → x2 → Ω
Recorded in L_I  :  x0 → x1 → x2
```

with **valid hashes, valid signatures, intact chain, and zero detectable
tampering**. `EvidenceChain.verify()` returns `(True, [])`.

> **Integrity ≠ Completeness.** A cryptographically intact history can still be
> an incomplete history.

**Expressiveness limit of the CURRENT IMPLEMENTATION, stated explicitly as
required.** `EvidenceChain.verify()` checks per-record integrity, `prev_hash`
continuity, and the fail-closed invariant. It has **no predicate over records
that were never appended**. An empty chain verifies as `(True, [])`. The
current evidence architecture therefore **cannot express evidence
completeness** — not as a defect, but as a scope boundary. Completeness is not
a property of a hash chain; it is a property of the coupling between execution
and recording.

Additionally, `EvidenceChain.record_execution()` appends the outcome as a
**separate record after execution**. The window between commit and record is
structural, not incidental.

### Adversarial Tests

10 conditions × 3 commit orderings = 30 runs.

| Ordering | Completeness violations | Soundness violations | Silent (integrity VALID) | Verifier fully blind |
| :--- | ---: | ---: | ---: | :--- |
| `execute_then_record` | **3** | 1 | 4 | crash, partition |
| `record_then_execute` | **0** | **2** | 2 | none |
| `two_phase_intent_outcome` | 2 | **0** | 2 | **none** |

### Surviving Claim

**H2 as stated is falsified.** Independent evidence defeats *vendor-side
manipulation* completely, and does not survive *independent-side* faults.

> What survives: independent, tamper-evident custody removes the vendor's
> unilateral ability to suppress a record it already holds. It does not
> establish that a record exists for everything that happened.

---

## 7. Executed Reality vs Recorded Reality

The state the prompt asked to be tested explicitly:

```
Executed Reality ≠ Recorded Reality    while    Verify(L_I) = VALID
```

**Reachable. In 56 of 64 fault combinations, and under every one of the three
single independent-side faults.** Cryptographic integrity alone does not
establish evidence completeness.

### H2′ and the atomicity problem

Moving evidence commitment before execution does **not** solve it:

- `record_then_execute` eliminates completeness violations (0) and
  **introduces soundness violations (2)** — `L_I` asserts executions that never
  happened.
- `execute_then_record` has the mirror failure, and leaves the verifier
  **entirely blind** under crash or partition.

> **H2′ is falsified.** Ordering does not eliminate divergence. It chooses
> which side diverges.

This is the two-generals problem wearing a governance hat. With two independent
failure domains and no atomic commit across them, you cannot have completeness
and soundness simultaneously under partition.

**What two-phase buys.** `two_phase_intent_outcome` (record intent → execute →
record outcome) still has 2 completeness violations, but the verifier is
**never blind**: it always knows an attempt occurred, and can bound the
uncertainty to a named transition. The achievable property is not *complete
knowledge* but **no silent omission**:

> **Achievable:** every consequential execution is preceded by an independently
> committed intent, so an unresolved transition is *visible as unresolved*.
> **Not achievable without atomic commit:** that the outcome is known.

---

## 8. 2×2 Authority Experiment

All four cells attacked with the **same** attack set, including attacks that
defeat execution authority and attacks that defeat evidence.

| Cell | Ω reached | Admissible preserved | Blocked | Bypass | False allow | Completeness | Integrity | Verifier reconstructs | Undetected divergence |
| :--- | ---: | :--- | ---: | ---: | ---: | ---: | :--- | :--- | :--- |
| **A** vendor ev., no exec auth | 4 | yes | 0 | 1 | 0 | 0.20 | — | no | no¹ |
| **B** indep. ev., no exec auth | 4 | yes | 0 | 1 | 0 | 0.60 | VALID | no | **yes** |
| **C** vendor ev., exec auth | 2 | yes | 2 | 1 | 1 | 0.33 | — | no | no¹ |
| **D** indep. ev., exec auth | **2** | yes | 2 | **1** | **1** | **0.67** | VALID | **no** | **yes** |

¹ Cells A and C show `undetected_divergence = no` only because vendor evidence
carries no integrity guarantee to begin with — there is nothing to be falsely
reassured *by*. This is worse, not better. A metric read without its definition
inverts the conclusion.

**D is not strictly safe.** `d_is_strictly_safe = False`. D reaches Ω twice
(`boundary_bypass`, `effect_divergence`) and still exhibits undetected
divergence.

### The common-mode finding

The single most important result in the study:

> **`boundary_bypass` appears in D's `omega_reached` *and* in D's
> `missing_events`.**

One attack defeats both authorities simultaneously. A transition that never
reaches the governance boundary also never reaches the recorder. The two
independent authorities are **not independent failure domains** — they share
one antecedent: *complete mediation of execution*.

The hoped-for symmetry was:

```
EXECUTION SIDE:  no prohibited transition without authority
EVIDENCE SIDE:   no consequential execution without evidence
```

The actual symmetry is a **negative** one: both properties are conditional on
the same assumption, so they fail *together*, not independently. Adding
independent evidence to independent execution authority does not give two
independent guarantees. It gives one guarantee with two expressions.

---

## 9. Minimal Counterexamples

All five are deterministic and pinned as regression tests in
`test_falsification.py` (16 tests, all passing).

| # | Counterexample | Steps | Assumption violated |
| :--- | :--- | ---: | :--- |
| **CX1** | Bypass reaches Ω | 1 | A4 mediation |
| **CX2** | Effect divergence: authority permits admissible *declared* successor, committed effect is prohibited; `blocked == []` | 1 | A3 declared = actual |
| **CX3** | TOCTOU: authorisation sound when made, invalidated before commit | 1 | A5 atomicity |
| **CX4** | `Verify(L_I) = VALID` while `Ω` transition absent from the chain | 3 | A7 recorder observes all |
| **CX5** | `record_then_execute`: soundness violation — evidence asserts an execution that did not occur | 1 | atomicity across domains |

CX4 is the one to carry forward. It uses Morrison's real `EvidenceChain`, and
Morrison's own verifier returns `(True, [])` on an incomplete history.

---

## 10. Required Assumptions

**For H1 to hold:**

1. **Complete mediation** — every executable transition passes through `G`.
   Violated by A09, A10. *Not provable from inside the model.*
2. **Semantic fidelity** — declared effect = committed effect. Violated by
   A11, A12.
3. **Atomicity** — no state change between authorization and commit. Violated
   by A13, A14.
4. **Ω completeness** — predicates range over every consequence the
   environment can produce. Violated by A06.
5. **Environment-model completeness** — the state vector represents every
   consequential variable. Violated by A07.

**For H2 to hold, additionally:**

6. **Recorder observation completeness** — the recorder sees every
   consequential execution.
7. **Writer honesty** — or a threshold/multi-writer construction.
8. **Durability before acknowledgement**.
9. **Atomic commit across execution and evidence** — *unavailable under
   partition*, which is why H2′ fails.

Assumptions 1 and 6 are **the same assumption viewed from two sides**. That is
the common-mode result of §8.

---

## 11. What Was Falsified

| Claim | Status |
| :--- | :--- |
| H1 as stated (unconditional) | **FALSIFIED** — 8/14 attacks, 5 categories |
| H2 as stated (strong unhideability) | **FALSIFIED** — 56/64 combinations |
| H2′ (evidence-gated execution) | **FALSIFIED** — trades completeness for soundness |
| "Integrity implies completeness" | **FALSIFIED** — CX4, against the real chain |
| "Ω-unreachable implies harm-free" | **FALSIFIED** — A06, A07 |
| "Cell D is strictly safe" | **FALSIFIED** — `d_is_strictly_safe = False` |
| "Execution and evidence authority are independent guarantees" | **FALSIFIED** — common-mode bypass |
| Preliminary counts 12/9 → 3/0 | **NOT REPRODUCED** — model-specific |

## 12. What Survived

| Claim | Status |
| :--- | :--- |
| Control condition reaches Ω; governed does not | **PROVEN IN BOUNDED MODEL** |
| Admissible capability preserved under governance | **PROVEN IN BOUNDED MODEL** (3/3) |
| Vendor-side manipulation alone does not defeat independent evidence | **PROVEN IN BOUNDED MODEL** (completeness 1.00) |
| 8/64 and 56/64 enumeration | **REPRODUCED EXACTLY** |
| Three single independent-side faults each break H2 alone | **REPRODUCED** |
| Integrity ≠ Completeness | **PROVEN IN BOUNDED MODEL** |
| Two-phase gives *no silent omission* (verifier never blind) | **PROVEN IN BOUNDED MODEL** |
| Conditional H1 (§5, four assumptions) | **SURVIVED this attack set** |

All eight key distinctions the prompt asked about are **genuinely separate
properties**, each with a counterexample separating it from its neighbour:
Representation ≠ Causal Enforcement · Integrity ≠ Completeness ·
Authorization ≠ Execution (CX3) · Evidence Commitment ≠ External State Change
(CX5) · Recorded ≠ Executed Reality (CX4) · Detection ≠ Evidence ·
Evidence ≠ Custody · Custody ≠ Disclosure.

## 13. What Remains Unknown

- **NOT YET TESTED:** unbounded/infinite state spaces; probabilistic and
  partially observable environments; adversarial `Ω` specification (an
  adversary choosing the predicates); real distributed clocks; concurrent
  multi-agent execution with genuine interleaving (modeled only as sequential
  delegation); threshold/multi-writer evidence; economic and legal custody.
- Whether assumption 1 (complete mediation) is *verifiable* from outside the
  system. This study assumes or violates it; it never establishes it. It may
  not be establishable by any in-model method — which would make it an
  irreducibly architectural, not analytical, property.
- Whether "no silent omission" is the strongest achievable evidence property,
  or merely the strongest this attack set found.

## 14. Architectural Implications

Stated as implications of the bounded results, not as product claims.

1. **Complete mediation is the load-bearing assumption for both properties.**
   It is prior to both, and it is an architectural fact about deployment, not a
   theorem. Effort spent hardening the boundary is worth more than effort spent
   strengthening either property downstream of it.
2. **An authority that reasons over declarations inherits the declarations'
   fidelity.** Successor-aware authority is strictly stronger than
   proposal-aware authority (CX2), and real systems have the weaker one.
3. **Do not report chain validity as evidence integrity.** `Verify(L_I) = VALID`
   answers "was this record altered", never "is this record set complete".
   Reporting the first as the second is the precise error CX4 isolates.
4. **Prefer known uncertainty to silent omission.** Two-phase intent/outcome
   does not achieve completeness, but it never leaves the verifier blind —
   the difference between "we cannot confirm transition X" and no signal at all.
5. **Two authorities over one channel are one authority.** Independent
   execution authority and independent evidence authority must not share a
   mediation point, or the bypass that defeats one defeats both.
6. **`Ω` specification is a first-class failure mode.** A06 and A07 produced
   real consequences with a clean bill of health. `Ω` coverage deserves the
   same adversarial attention as the enforcement mechanism.

## 15. Reproduction Instructions

```bash
cd Morrison-Runtime-Governance

# full study -> RESULTS.json
python3 -m research.falsification.independent_authority.run_study

# all counterexamples as regression tests
python3 -m pytest research/falsification/independent_authority/test_falsification.py -q
```

Expected: `16 passed`, and

```
H1 control  : reachable=48  omega=40
H1 governed : reachable=8   omega=0   capability_preserved=True
H1 adversarial: 8/14 falsify, categories=['1_PRINCIPLE','2_AOE_SPEC','3_ENV_MODEL','4_SEMANTICS','5_BYPASS']
H2 enumeration: 8/64 hold, 56 fail
2x2 cell D  : omega=2  undetected_divergence=True
```

Everything is exhaustive enumeration over finite models. No sampling, no
randomness, no wall-clock dependence.

| File | Role |
| :--- | :--- |
| `h1_model.py` | independently constructed environment, `Ω`, `X0` |
| `h1_baseline.py` | control vs governed via Morrison's real `ExhaustiveVerifier` |
| `h1_adversarial.py` | 14 attacks + `MediatedExecutor` harness extension |
| `h2_evidence.py` | `L_V`/`L_I` models, 2^6 enumeration, metrics |
| `h2_adversarial.py` | commit orderings, H2′, atomicity |
| `matrix2x2.py` | 2×2 authority experiment |
| `test_falsification.py` | 16 regression tests pinning every counterexample |
| `RESULTS.json` | full machine-readable output |

### Status vocabulary

**CURRENTLY IMPLEMENTED** — Morrison's `ExhaustiveVerifier`, `EvidenceChain`,
`GovernanceKernel`, used unmodified.
**EXPERIMENTAL HARNESS** — `MediatedExecutor`, `OracleAuthority`, the `L_V`/`L_I`
fault models. This study only.
**PROPOSED PROPERTY** — H2′ and "no silent omission".
**PROVEN IN BOUNDED MODEL** — §12.
**FALSIFIED** — §11.
**NOT YET TESTED** — §13.

---

*No Morrison implementation, test, verification logic, AOE logic, evidence
infrastructure or existing research claim was modified by this study. All files
are additive under `research/falsification/`.*
