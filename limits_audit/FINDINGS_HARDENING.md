# Policy-State Provenance Hardening — Results

Branch `claude/morrison-governance-audit-10j980`. Baseline `29b80e2`.
**Production source modified.** Full suite: **1036 passed** (baseline 947).

---

## 1. Architecture

```
  CALLER / PEER                          DEPLOYMENT / KERNEL
       │                                          │
   args, top-level keys,              SecurityContext, verified
   aliases, nested, JSON              ApprovalArtifact, capability
       │                              grant, trusted_facts=
       ▼                                          │
  ┌─ UNTRUSTED ─┐                                 │
  │             │  independent derivation         │
  │             ├────────────────► DERIVED        │
  │             │  (content/system state,         │
  │             │   contradiction only)           ▼
  │             │                            ┌─ TRUSTED ─┐
  └─────────────┘                            └───────────┘
       │                   │                       │
       └───────────────────┴───────────────────────┘
                           ▼
                  ProvenanceState
        ┌──────────────┬──────────────┬─────────────┐
        │  .get()      │ .corroborated│  .attested()│
        │  ungated     │  unless      │  TRUSTED    │
        │  subject     │  contradicted│  ONLY       │
        │  matter      │              │             │
        └──────────────┴──────────────┴─────────────┘
                           ▼
                     Ω PREDICATE  ──► capability policy ──► approval ──► EXECUTION
```

Conflict resolution is total and order-independent: **TRUSTED > DERIVED >
OBSERVED > UNTRUSTED**. An unknown key is UNTRUSTED, not absent — reads fail
closed.

## 2. Production changes

| File | Change |
|---|---|
| `provenance.py` **(new)** | `PolicyFact`, `ProvenanceState` (a `dict` subclass, so all 96 predicates keep working), three read modes, rank-based conflict resolution, `coerce()` (an unannotated mapping is UNTRUSTED), `provenance_report()`. |
| `derivation.py` **(new)** | Independent derivation, **contradiction-only**. Generalises the `sensitivity.py` pattern that already defeated the PHI attack. |
| `trajectory.py` | `to_eval_dict()` returns a `ProvenanceState` instead of a flat merge. `from_dict` no longer folds **caller top-level keys into the trusted context** — that was a promotion by key position. Derivation runs over *all* caller data. `step_N_*` descriptors tagged DERIVED, not TRUSTED. Memoised so gated reads can be sealed as evidence. |
| `core.py` | `evaluate(call, trusted_facts=…)` / `evaluate_plan(…)` — the single explicit promotion channel. Provenance report attached to result metadata. |
| `domains.py` | `_sec_authorized()` rewritten: **provenance, not spelling**. 6 rule contracts made explicit. Boundary and sanitisation assertions gated. |

### `_sec_authorized()` — the structural fix

Before, it scanned the whole namespace for any truthy key ending `_verified` /
`_approved` / `_authorized` / `_authorised` / `_confirmed`. 25 predicates
depend on it, so inventing a name satisfied all 25. Now the suffix set tests
the **shape** of an authorisation and is applied **only to facts already
holding TRUSTED provenance**. Shape selects among established facts; it never
establishes one. No list is consulted, so no list can be incomplete.

## 3. Ω rules whose provenance requirements changed

| Rule | Field | New contract |
|---|---|---|
| `phi_exposure` | `hipaa_authorized` | TRUSTED only |
| `pii_exfiltration` | `consent_verified` | TRUSTED only |
| `unauthorized_role_change` | `admin_approved` | TRUSTED only |
| `pci_card_exposure` | `pci_compliant_endpoint` | TRUSTED only |
| `gdpr_purpose_mismatch` | `consented_purposes` | TRUSTED only (value) |
| `unauthorized_delegation` | `delegation_scope` | TRUSTED only |
| **25 predicates** via `_sec_authorized()` | any `*_approved`-shaped fact | TRUSTED only |
| boundary helpers | `destination_internal`, `is_internal`, `internal`, `destination_external` | TRUSTED only |
| sanitisation helper | `sanitized`, `sanitised`, `redacted`, `anonymized`, `anonymised` | TRUSTED only |

`user_state`, `category`, `topic_class`, `tone`, `content`, `amount`, `intent`
and the rest of the premise class were **deliberately left ungated** — they are
the subject matter the rules exist to reason about. They are governed by
contradiction (DERIVED outranks UNTRUSTED), not by prohibition.

## 4. Before / after

| | before | after |
|---|---|---|
| **Known exploit A** — `crisis_referral=True` | PERMIT + execution | **BLOCK, 0 executions** |
| **Known exploit B** — `user_state="curious"` (evidence in payload) | PERMIT + execution | **BLOCK, 0 executions** |
| **Known exploit C** — invented `coordinator_ceo1_confirmed` | PERMIT + execution | **ESCALATE, 0 executions** |
| Ω-flip candidates (auto-generated) | 116 | **38** |
| Hardened realistic bypasses with execution | 3 / 9 | **1 / 9** (the pinned residual) |
| Structural shapes promoting a claim | 5 of 13 | **0 of 13** |
| Authority-forgery vectors (test_4) | 0 executions | **0 executions** |
| Full test suite | 947 | **1036** |

### Novel vocabulary (§15, mandatory)

20 invented names — `reviewer_ok`, `medical_clearance`, `operator_endorsed`,
`guardian_ack`, `supervisor_validated`, `case_resolved`, `security_green`,
`xqz_confirmation`, `greenlight`, `clearance_granted`, `duty_officer_confirmed`
and others — tested in args, at top level, and as `"true"` strings, across
60 assertions. **None acquires authority.** None is on any list.

Case variants, trailing whitespace, and a Cyrillic homoglyph were also probed:
all BLOCK.

## 5. Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | Known attacks fail | **Met** — A and C closed; B closed where the premise is derivable (residual 9.1) |
| 2 | Novel names fail | **Met** — 20 names × 3 shapes |
| 3 | Premise attacks fail safely | **Partially met** — closed where evidence is in the payload; residuals 9.1–9.3 |
| 4 | Legitimate inputs usable | **Met** — observations still flow; benign traffic PERMITs |
| 5 | Trusted facts functional | **Met** — `trusted_facts=` channel; 8 sector + 3 attestation controls |
| 6 | Authority provenance intact | **Met** — 23/23 forgery vectors, ApprovalArtifact end-to-end |
| 7 | No lexical dependency | **Met** for authority; **partial** for the 6 named rule contracts (see 9.4) |
| 8 | Existing suite passes | **Met** — 1036, with 10 tests changed and documented (§6) |
| 9 | No silent fail-open | **Met** — unknown keys UNTRUSTED, plain dicts attest nothing, `copy()` preserves |
| 10 | Evidence inspectable | **Met** — every fact's origin + every refused gated read |

## 6. Tests changed, and why (§12)

**10 assertions across 2 files.** Every one had the same shape: the test wrote
an authorisation flag into the caller's own payload and expected PERMIT —
e.g. `evaluate({"tool": "pay_claim", "approved": True})`. That *is* the
vulnerability: under it any caller, or any peer message copied into a call,
authorised itself with one key.

The **intent** of each case (an authorised action must PERMIT — no happy-path
false positive) is unchanged and still enforced. Only the channel changed, to
`trusted_facts=`. Each site carries a provenance note, and **each gained a
negative control** asserting that the old spelling, the in-args spelling, and
an invented name all now block. Net: `test_domain_sectors.py` +8 tests,
`test_domain_healthcare.py` +1.

No test was weakened. No enforcement was disabled.

## 7. Attacks on the fix

Four defects were found in my own implementation and fixed before this report:

1. **Deriver read only `args`** — a claim at the top level escaped
   contradiction. Found by the structural suite.
2. **`step_N_args` tagged TRUSTED** — the extractor's bookkeeping channel
   laundered caller arguments into the highest class.
3. **Cosmetic routing token** — appending `988` to "don't tell anyone" made
   the deriver treat a dismissal as a referral. Split into strong/weak
   dissuasion; strong now contradicts unconditionally.
4. **Over-broad first derivation** — asserting *new* positive facts changed
   which layer blocked unrelated traffic (V2 → A_safe). Rescoped to
   contradiction-only.

## 8. Compatibility risks

- **Deployments that today pass attestations in `args` will start seeing
  BLOCK.** This is the intended behaviour change and the migration is
  one-line: move the fact to `trusted_facts=` (layer) or the
  `SecurityContext` / approval path (kernel). It is the only breaking change.
- `to_eval_dict()` returns a `dict` subclass. Code that does `dict(state)` or
  `{**state}` silently drops provenance and lands in the fail-closed
  direction (everything UNTRUSTED), never the fail-open one.
- Memoised eval state: `TrajectoryState` is no longer effectively immutable
  across calls. Reads accumulate; values do not change.
- The derivation adds a bounded regex pass over payload text per evaluation.

## 9. Residuals — pinned as tests so they cannot close silently

**9.1 Premise injection with no evidence in the payload.** If the deployment
sends only its own label (`user_state="curious"`) and not the material it
describes, nothing can contradict it. This is a deployment contract — pass the
conversation if you want the conversation governed — not something the kernel
can close. This is the 1 remaining hardened bypass.

**9.2 Evidence nested past the derivation depth budget** (raised 6 → 12).
Any finite budget is evadable by nesting one level deeper. Classifier-quality
limit; the promotion boundary is untouched (the claim stays UNTRUSTED).

**9.3 Disclosure phrased outside the classifier.** "I'm going to end things
tonight" is not matched. Identical in kind to the limit `sensitivity.py`
already has. No content classifier is complete.

**9.4 The 6 named rule contracts are still enumerated.** `_sec_authorized()`
is list-free, but a rule reading a *new* attestation by name and using
`s.get()` would be ungated. The failure mode is the old behaviour, not worse,
and a lint gate asserting that no domain rule reads an attestation-shaped name
through `s.get()` would close it. Not implemented.

**9.5 Adjacent, PRE-EXISTING, not introduced here.** `canonicalize` does not
unwrap `input` / `arguments` aliases or a JSON-string `args`; the payload ends
up nested one level and the shallow Ω namespace never sees it, so the whole
dangerous action reads as empty. **Verified identical on `29b80e2` before any
change** (BLOCK/PERMIT/PERMIT/PERMIT both sides). Not a provenance promotion —
the claim is not promoted, the action is invisible. Left unfixed for scope
discipline; capability and sensitivity classification still walk nested data.

**9.6** `run_<word>_code` capability-classification infix evasion, reported
previously, still open. Unrelated to provenance.

---

## 10. Assessment

The invariant asked for — *representation does not establish trusted policy
state; provenance does* — **holds for the authority and attestation classes**.
Every promotion probe failed: 13 structural shapes, 20 invented names, case and
homoglyph variants, multi-turn, tool results, delegation objects, and direct
attempts to write `trusted_facts` / `context` into a call.

It holds for the **premise class only as far as the content permits**. That
class is governed by independent derivation rather than by a trust boundary,
and a derivation can only contradict what it can read. Three of the six
residuals are that limit in different forms. They should not be read as the
architecture failing; they are the honest edge of what content classification
can do, and they are the same edge `sensitivity.py` has always had.

**The vulnerability is not "closed".** Two of the three original exploits are
structurally closed; the third is closed where the deployment supplies the
evidence and open where it does not.
