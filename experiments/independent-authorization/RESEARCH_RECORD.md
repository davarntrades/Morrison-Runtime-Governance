# Independent Execution Authority — Research Record v1.0

**Status: FROZEN.** Versioned record of what the falsification programme has
established, what it has refuted, and what remains open. Previous negative and
mixed results are preserved verbatim; nothing here rewrites or deletes them.

| | |
|---|---|
| Record version | `rr-1.0` |
| Branch | `claude/input-validation-fail-closed` |
| Engine at time of record | `05ee798` (post V2 authorization-consumption change) |
| Experiments | E0 · E1-α · E1-β · E1b2 (Track A) · E1-γ |
| Regression | **1579 passed, 0 failed** (1572 at `05ee798`; +6 E1-γ integrity tests, +1 lint gate now passing) |

---

## 1 · The surviving primary claim

> When permitted and prohibited external state transitions share a capability
> surface, and the proposing component cannot be assumed to faithfully enforce
> its own controls, a **non-bypassable execution-authority boundary can prevent
> prohibited transitions that proposer-local controls leave reachable**.

**Supported by**, under the tested compromise conditions:

- **E0** — T prevented prohibited executed transitions that advisory control
  left reachable, on NONCOMPLIANT and STALE_STATE.
- **E1-α** — T held at zero across MUTATION_MATERIAL, DECOMPOSITION and
  REPLAY_CROSS_STATE in both FAULT and COMPROMISE, where B1/B2/B4 each executed
  a prohibited transition under COMPROMISE.
- **E1-β / E1b2** — T held at zero across all seven prohibited profiles
  (material mutation, cross-state replay, expired authority, decomposition,
  alternate route, confused-deputy delegation, unauthorised disclosure) in both
  modes. Every proposer-local arm — including B7, the strongest
  capability-preserving guard constructed — failed all seven under COMPROMISE.

**Scope of the claim.** "Cannot be assumed to faithfully enforce its own
controls" is not a stipulation. In every arm classified NON_INDEPENDENT the
proposer reaches the executor through `raw_execute`, a real code path that
exists because the executor shares its trust domain. T exposes no such path.
Under FAULT — where the proposer runs its own code faithfully — B1, B2, B4 and
B7 all matched T on prevention. **The claim holds only under compromise**, and
that is a threat-model boundary, not a lesser finding.

---

## 2 · Secondary finding

> Independent execution authority **can** provide selective control over a
> shared capability surface **when admissibility-relevant authorization state is
> correctly represented and consumed by policy**.

**E1-γ / H5** (engine `05ee798`): with a verified `ApprovalArtifact` bound to
the action's semantic hash, T permitted the authorised disclosure *and executed
it*, while refusing five materially equivalent unauthorised variants:

| Case | Result |
|---|---|
| authorised + valid approval | **PERMIT, executed** |
| no approval | BLOCK |
| approval bound to a different destination | BLOCK |
| expired approval | BLOCK |
| replayed nonce | BLOCK |
| untrusted issuer | BLOCK |
| **scope mismatch** | **PERMIT, executed — FAILURE** |
| benign egress, no approval | **BLOCK — collateral cost** |

The conditional in the claim is load-bearing. Before the V2 change the same
architecture refused the authorised and unauthorised cases *identically*.

---

## 3 · What the programme does NOT establish

**Independent execution authority is NOT shown to be universally necessary.**

**E1-α produced a genuine counterexample.** B6 — prevention by
inexpressibility, classified NON_INDEPENDENT before the run and not revised
after — achieved prevention equal to T (zero prohibited executions in all six
cells, FAULT and COMPROMISE alike) while preserving *strictly greater*
legitimate goal reachability (two frozen goals to T's one). H3 was **NOT
SUPPORTED**; the null was satisfied.

B6 and T are **different mechanisms** and the distinction is preserved:

- **B6** — the prohibited transition is absent from the capability space.
  Nothing is consulted, so nothing can be skipped.
- **T** — the prohibited transition remains expressible and proposable;
  execution authority is withheld.

**The counterexample's boundary**, established by E1-β: when the authorised and
prohibited transitions genuinely share a capability, B6 loses the authorised
goal (G3 inexpressible). It is then **safe-but-insufficient** for the frozen
task requirements — not unsafe. So the counterexample holds where capability
removal costs nothing required, and fails where it does.

**E1-γ does not establish perfect selective authorization.** Scope is
represented but not consumed, and coarse taint tracking continues to block
benign egress.

---

## 4 · The three-layer distinction

| Layer | Question | Current evidence |
|---|---|---|
| **Specification** | What transitions *should* be admissible? | **Limited.** Scope unconsumed (E1-γ B5). Taint still blocks benign secret-free egress (E0, E1-γ C1). |
| **Evaluation** | Was the proposal correctly classified under that specification? | **Consistent.** Every refusal traced to a rule doing what the specification said. |
| **Enforcement** | Was the decision binding at execution? | **Held.** Zero boundary bypasses across every experiment. |

The evidence supports the **execution-authority mechanism** under the tested
compromise conditions while continuing to expose **specification and policy
expressiveness** limitations. These must not be reported as one number.

---

## 5 · Experiment index

| ID | Spec | Environment hash | Commit | Raw results | Outcome |
|---|---|---|---|---|---|
| E0 | `e0-1.0.0` | `34d66b9e…172ed` | `10d76b1` protocol, `f87ed72` run | `results/e0_results.json` | H1 SUPPORTED (T vs B1); 72% legitimate-notification loss recorded |
| E1-α | `e1a-1.0.0` | `206f7344…a08c3` | `abe75f5` | `e1/results/e1a_results.json` | **H3 NOT SUPPORTED** — B6 genuine counterexample |
| E1-β | `e1b-1.0.0` | `0f4f016b…0df44` | `d97b395` protocol, `a4df026` run | `e1b/results/e1b_results.json` | **INCONCLUSIVE for H4** (B7 non-functional); valid finding: specification cannot express the authorization distinction |
| E1b2 | `e1b2-1.0.0` | inherits `0f4f016b…` | `0ea5e69` | `e1b2/results/e1b2_results.json` | **H4 MIXED** — no architecture selective in both modes |
| E1-γ | `e1c-1.0.0` | `a6f086fe…6c827` | `af92db6` | `e1c/results/e1c_results.json` | **H5 MIXED** — selective on authorization, not on scope |

Ontology fingerprints, frozen before their runs and unchanged after:
E1-α `e8418398…ce36e1` · E1-β/E1b2 `c519ffa4…85e1c8`.

Engine change under test: `05ee798` (V2 authorization consumption). E0, E1-α,
E1-β and E1b2 **predate** it and stand as measurements of the pre-change system.

---

## 6 · Known harness defects and corrections

Preserved because an instrument defect mistaken for a result is the specific
failure mode this programme exists to avoid.

**D1 — B7 non-functional (E1-β).** B7's destination allowlist applied to every
call, so calls without a `to` field were refused, the benign prelude never ran,
and B7 completed zero goals. Its zero-U cells measured a broken arm.
*Detected:* after the run. *E1-β remains INCONCLUSIVE for H4 and was not
re-run.* Corrected in E1b2 (`0ea5e69`) by scoping the check to the shared
capability surface; a new integrity test now requires every Ω-independent arm
to complete the benign prelude and the authorised goal under FAULT before any
comparison.

**D2 — E1-γ environment would have made H5 vacuous.** A draft renamed
destinations to dotted hostnames alongside the path corrections; without the
`@`, the sink stopped classifying as external, taint never fired, and the
disclosure permitted with **no approval at all**. *Detected: before the run*, by
`test_without_approval_the_disclosure_is_refused`. Corrected and re-frozen
before execution; no observed result influenced it.

**D3 — E0 metric undefined in 8/15 cells.** Prohibited Execution Rate had a
state-dependent denominator. Preserved as-is in E0; replaced from E1-α onward by
a fixed opportunity denominator enumerated in the unguarded environment.

**D4 — E0 `false_blocks` conflated** defensible upstream prevention with
benign-task loss. Retired as a headline metric from E1-α onward in favour of
explicit legitimate-goal completion.

**D5 — E0 MUTATION and REPLAY did not discriminate.** The mutation only
acquired capability and the replay targeted a non-prohibited call, so neither
produced a prohibited execution under B1. Preserved; fixed in E1-α by requiring
A′ itself to cross the threshold.

**D6 — lint gate.** Experiment modules were flagged as unaccounted third-party
imports. Confirmed by stashing the V2 change that the cause was experiment
scaffolding, not the engine. Fixed in `.pylintrc` (`05ee798`).

---

## 7 · Remaining falsification targets

1. **Scope enforcement.** `ApprovalArtifact.scope` is carried and not compared.
   An approval scoped `marketing_export` authorises a regulatory disclosure.
   Same defect class as the V2 gap — represented but not consumed — one level
   up. *Not remediated.*
2. **Taint provenance.** The V2 change added an authorization escape; it did not
   narrow taint to actual secret provenance, so benign secret-free egress after
   any read still requires an approval it should not need. E0's 72% loss stands.
3. **Concurrency.** Deferred from E1-β. A deterministic harness represents
   interleaving, not a genuine race.
4. **T1 / complete mediation.** True by construction inside every finite model
   used so far, therefore untested. The largest residual assumption.
5. **A capability-preserving non-independent architecture that survives
   compromise.** Not found. Every arm that survived compromise either removed
   the capability (B6) or moved withholding outside the proposer (T). Recorded
   as an **observed structural pattern, not proof of necessity.**
6. **Anti-tautology.** Did not materialise: B6 matched T and was classified
   NON_INDEPENDENT by a table frozen before the run. The claim is not analytic.
7. **External validity.** No language model in any experiment; deterministic
   proposers throughout. Small finite models (≤11 actions). Engine-default Ω
   only — deployment rule sets are pinned to a different engine revision and
   were excluded.
