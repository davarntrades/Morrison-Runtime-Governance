<div align="center">

![Primary Property](https://img.shields.io/badge/Primary_Property-Authority_Separation-0f766e?style=flat-square)
![Status](https://img.shields.io/badge/Status-Demonstrated_under_attack-1f2937?style=flat-square)
![Derived](https://img.shields.io/badge/Ω--exclusion-Derived_·_Boundary--conditional-c2410c?style=flat-square)
![Evidence](https://img.shields.io/badge/Evidence-48_Counterexamples-b91c1c?style=flat-square)
![Patent](https://img.shields.io/badge/Patent-GB2600765.8-0075ca?style=flat-square)
![©](https://img.shields.io/badge/©-Davarn_Morrison-555555?style=flat-square)

</div>

# Authority Separation — The Primary Demonstrated Property

*"Reachability was never the thing we proved. What we proved is that the agent
cannot mint the authority to act. Forbidden-state exclusion is what follows,
inside a boundary somebody else has to establish."*

*— Davarn Morrison, 2026*

---

This document is the canonical mathematical framing for the governed-execution
work. Where any other document in this repository states a reachability
identity, it is either labelled an **objective** or derived from what is stated
here, and links back to this file.

---

## 1 · Why the framing changed

Earlier material presented

```text
Reach_G(X₀) ∩ Ω = ∅
```

as the primary Morrison guarantee. Four rounds of adversarial evaluation
established that this is not what the implementation demonstrates, for a
specific and instructive reason.

Almost none of the 48 counterexamples were failures of reachability computation.
The reachability engine generally computed the right answer about the wrong
object. The failures clustered in **binding, identity, and continuity**:

- **ATK-01** — two different actions hashed identically, so an approval verified
  against an action nobody approved.
- **ATK-02** — the action was mutated after it was hashed and before it was
  executed.
- **MED-01** — two distinct principals collapsed to one identity, merging
  governed history.
- **CONT-02** — one single-use approval moved $13.5M across three sessions.

In each case `Reach ∩ Ω = ∅` was a true statement about a transition that was
not the transition that executed. A reachability identity cannot express that
failure mode, because the failure is in the **binding between a proposal and the
authority to perform it** — which is exactly what the hardened implementation
now enforces and what the evidence actually supports.

---

## 2 · The primary demonstrated property

### 2.1 Notation

| Symbol | Meaning |
| :----: | :------ |
| `a ∈ A` | a proposed action |
| `𝔄` | the **agent's derivable closure** — everything the agent can compute from what it holds: its inputs, its code paths, and any credential in its reach |
| `K` | the governance kernel: the sole issuer of authorization |
| `k` | the lease signing secret (`lease_signing_key`), held by `K` and by resource-side verifiers |
| `h(a)` | the byte-canonical action hash (`kernel.canonical.action_hash`) |
| `hₛ(a)` | the semantic action hash, used for policy and approval binding |
| `Λ(a)` | an authorization artifact bound to `a` (`ExecutionLease`) |
| `Effect(a)` | an external effect of `a` at a governed resource |

### 2.2 The artifact

`Λ(a)` is exactly what `kernel/mediation.py` constructs:

```text
Λ(a) = ⟨ ℓ, h(a), hₛ(a), principal, tenant, session, decision_id,
          family, iat, exp, σ ⟩

        σ = HMAC-SHA256_k( payload )
```

### 2.3 The separation

```text
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║      Propose(a) ∈ 𝔄        the agent always retains              ║
║                             proposal capability                  ║
║                                                                  ║
║      Λ(a)       ∉ 𝔄        the agent cannot manufacture          ║
║                             execution authority                  ║
║      ──────────────────────────────────────────────────────      ║
║                                                                  ║
║      Effect(a) ⟹ ∃ Λ(a) issued by K and valid at redemption     ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

Read directly: **the agent can always ask, and can never authorise.** The
artifact that permits an effect is one the proposing agent cannot mint, forge,
replay, retarget, or carry across identities.

### 2.4 The artifact properties, and what pins each one

Each property is a named passing test, not an assertion.

|  #   | Property | Statement | Pinned by |
| :--: | :------- | :-------- | :-------- |
| **P1** | unforgeable | `σ` requires `k`, and `k ∉ 𝔄` | `L-03`, `L-03b`, `L-05` |
| **P2** | action-bound | `verify(Λ, a′)` succeeds ⟹ `h(a′) = h(a)` | `L-04`, `ATK-02`, `ATK-10` |
| **P3** | single-use | `redeem(ℓ)` succeeds at most once, atomically, including under concurrent redemption | `L-02`, `L-09`, `CONT-02` |
| **P4** | expiring | valid only while `now < exp + skew`, where `skew ≤ exp − iat` | `L-07`, `ATK-05`, `MED-04` |
| **P5** | issuer-bound | mintable only from a `PERMIT` decision holding a live trajectory reservation | `L-06` |
| **P6** | resource-verified | where a `LeaseVerifier` is deployed, `verify` runs in a process that is **not** the agent, and its failure path denies | `L-01`, `L-08`, `L-10` |

P6 is the one that converts an assumption into a mechanism. An agent that skips
the kernel arrives at the resource carrying nothing, and is refused **there**, by
something that does not depend on its cooperation.

### 2.5 What P1 rests on

`k ∉ 𝔄` is a **key-custody condition**, not a theorem. An agent that can read
`lease_signing_key` mints its own authority and every property above collapses.
`lease_signing_key` is deliberately distinct from the approval `signing_key`: a
gateway must verify leases and has no business minting approvals.

---

## 3 · Forbidden-state exclusion, as a derived property

Reachability exclusion is retained, and only in this form:

```text
Let B be a governed boundary in which every path to a consequential
effect is mediated — that is, M1–M7 established and T1–T7 holding.

    Within B:   Reach_B(X₀) ∩ Ω = ∅

    [ DERIVED, BOUNDARY-CONDITIONAL — not an unconditional guarantee ]
```

It is derived from §2 plus the correctness of the specification, and it is
conditional on all of the following, each of which is documented, open, or
external:

| Condition | Where it is recorded |
| :-------- | :------------------- |
| Complete mediation holds for `B` | **T1 / L1** — a deployment property. [COMPLETE_MEDIATION_ANALYSIS.md](COMPLETE_MEDIATION_ANALYSIS.md) |
| The declared Ω, capability policy and tool manifest are correct | **T6 / L5** — an input, not a result |
| Governed history reaches all of `B` | **MED-11 / L2** — *open*: multi-host continuity needs a deployment-supplied store |
| The store's `scope()` claim is true | **R4B-05 / L10** — *open*: attested, not verified |
| `k ∉ 𝔄`, and the approval signing key is secret | **T5** and §2.5 — key custody |
| The transition model represents the real effect | **L5**, §9 item 4 |
| No fail-open timeout sits in front of the kernel | **§9 item 9** |

**Outside `B`, no exclusion claim is made at all.** An effect path that neither
calls `K` nor redeems `Λ` is ungoverned, and Morrison never sees it.

---

## 4 · What this framing does not say

Stated as plainly as the property itself.

1. It does **not** say complete mediation is achieved. That is a property of the
   deployment; Morrison cannot attest a route nobody declared.
2. It does **not** say `Reach ∩ Ω = ∅` holds unconditionally, or that dangerous
   states are unreachable in general. Both are conditional on §3.
3. It does **not** claim authority over model cognition, over the correctness of
   the specification it is given, or over whether a human approver was
   manipulated.
4. It does **not** treat a passing test suite as evidence of the derived
   property. The suite is the record of what was already tried.

---

## 5 · Where the older formulation may still appear

`Reach_G(X₀) ∩ Ω = ∅` and its variants remain legitimate in two roles, and only
when explicitly labelled as such:

- as a **high-level safety/reachability objective** — what the system is *for*;
- as the **conditional property of a declared finite model**, in the AOE and
  global-verification tracks, where the declared Ω and transition function are
  the object of study rather than a claim about production.

Neither role is a demonstrated unconditional guarantee, and no document in this
repository may present it as one.

---

## 6 · Migration record — every file changed and why

The framing change was applied by sweep, not by memory. Three classes of change:

- **(R) Reframe** — the primary claim was restated; reachability demoted to objective or derived.
- **(L) Label** — the equation is legitimate in place and was explicitly marked `objective` / `under study` / `within model`.
- **(P) Pointer** — already correctly qualified; a link to this document was added.

| File | Old formulation | Replacement | Class | Why required |
| :--- | :--- | :--- | :-: | :--- |
| `AUTHORITY_SEPARATION.md` | *(new)* | canonical notation: `Propose(a) ∈ 𝔄`, `Λ(a) ∉ 𝔄`, P1–P6 | R | No single authoritative statement of the demonstrated property existed |
| `README.md` | badge `Safety ℛ(t) ∩ Ω = ∅`; "makes the claim operational" | badge `Demonstrated: Authority Separation` + `Objective: ℛ(t) ∩ Ω = ∅`; authority-separation block first, reachability labelled objective/derived | R | Front door presented reachability as the demonstrated guarantee |
| `PILOT_BRIEFING_CARD.md` | closing box `Reach(s₀,A,t) ∩ Ω = ∅` under "Morrison Safety Invariant™ · I4" | box split into `DEMONSTRATED` (authority separation) and `DERIVED` (Ω-exclusion, conditional on T1–T7, M1–M7, MED-11, R4B-05) | R | Pilot-facing doc asserted the reachability identity as the headline invariant |
| `ENTERPRISE.md` | badge `Invariant ℛ(t) ∩ Ω = ∅`; `Safe ⟺ ∀E, ℛ_E(t) ∩ Ω = ∅`; mermaid node | `Objective:` prefix + `DEMONSTRATED:` block; mermaid node now `Λ(a) ∉ 𝔄 — agent cannot mint execution authority` | R | Buyer-facing doc claimed an unconditional invariant |
| `Domain Strategy.md` | badge `Invariant`; "the same invariant"; closing box | `Objective`; "the same objective"; box shows `OBJECTIVE` and `DEMONSTRATED` separately | R | Positioned reachability as the thing the repo implements |
| `deployable infrastructure repository.md` | badge `Safety`; bare equations; mermaid decision node | `Objective` badge; `[objective; demonstrated property is Λ(a) ∉ 𝔄]`; labelled node | L | Deployment doc stated the identity unqualified |
| `global_governance/README.md` | "## Governing invariant"; "Invariant `ℛ(t) ∩ Ω = ∅` preserved" | "## Governing objective"; "Objective … preserved" + authority-separation paragraph | R | Called it the governing invariant |
| `artifacts/live-runtime-governance/.../README.md` | "Core invariant: Safe ⟺ …" | "Safety objective (not an unconditional guarantee)" + demonstrated block | R | Artifact README asserted a core invariant |
| `Pricing Strategy.md` | two boxes `ℛ(t) ∩ Ω = ∅` | `ℛ(t) ∩ Ω = ∅ [objective]` | L | Commercial doc implied a guarantee |
| `runtime_eval/results/DEEPSEEK_R1_MILESTONE.md` | "Morrison **guarantees**, per the reachability invariant, that an admitted trajectory satisfies …" | "**evaluates, against the reachability objective**, whether …; holds only inside an established governed boundary" | R | The word *guarantees* exceeded the evidence |
| `runtime_eval/HARDENING.md` | `ℛ(t) ∩ Ω = ∅` | `… [objective; see AUTHORITY_SEPARATION.md]` | L | Bare equation |
| `morrison_governance/core.py` | "Core invariant: Safe ⟺ ∀E, ℛ_E(t) ∩ Ω = ∅" | "Safety OBJECTIVE" + note that the demonstrated property is authority separation | R | Library docstring is the most-copied statement in the repo |
| `morrison_governance/stability.py` | `∀ E ∈ ℰ, ℛ_E(t) ∩ Ω = ∅` | `OBJECTIVE (not an unconditional guarantee)` + pointer | L | Module docstring |
| `morrison_governance/manifold.py` | `∀ E ∈ B(ℰ,r), R̂_E(t) ∩ Ω = ∅` | same, labelled objective + pointer | L | Module docstring |
| `morrison_governance/reachability.py` | "V3: rejects when `ℛ̂(F(x,u),k) ∩ Ω ≠ ∅`" | unchanged, plus "one enforcement layer serving the objective; not the demonstrated guarantee" | L | Layer description could be read as the guarantee |
| `morrison_governance/demo.py` | prints `ℛ(t) ∩ Ω = ∅` | prints `objective:` and `demonstrated:` lines | L | User-visible output |
| `morrison_governance/test_kernel_redteam.py` | "action is now structurally unreachable" | "structurally unreachable **on the kernel path** — within the governed boundary these tests establish, not unconditionally" | R | Test-suite prose asserted unconditional unreachability |
| `quickstart.py` | `Invariant: ∀E, ℛ_E(t) ∩ Ω = ∅` | `Objective: …` | L | First thing a new user runs |
| `audit/report.py` | report footer `V5+). ℛ(t) ∩ Ω = ∅.` | `V5+). Objective: ℛ(t) ∩ Ω = ∅.` | L | Generated audit reports carried the claim |
| `artifacts/visualizations/architecture.py` | `"Invariant:   ∀ E ∈ ℰ, …"` | `"Objective:   …"` | L | Diagram label |
| `artifacts/visualizations/architecture.svg` | `<!-- Invariant: … -->` | `<!-- Objective: … -->` | L | Build artifact kept in sync with its source |
| `multi_agent_eval/README.md`, `__init__.py`, `joint_trajectory.py` | `JointReach(…) ∩ Ω = ∅ ?` | `… (objective under study)` | L | Research track, not a demonstrated claim |
| `PRE_PILOT_ADVERSARIAL_EVALUATION.md` | §1 stated the operational claim only | added: demonstrated property is authority separation; Ω-exclusion derived | P | Report is the evidence base; framing now matches |
| `GOVERNED_EXECUTION_VETO_EVALUATION.md` | box: "`Reach(s₀) ∩ Ω = ∅` holds only where the authorizer can name which edge is being taken" | same, plus "That binding — not reachability — is the demonstrated property: `Λ(a) ∉ 𝔄`" | P | Already conditional; made the positive statement explicit |
| `COMPLETE_MEDIATION_ANALYSIS.md` | companion link | added link to this document | P | Cross-reference |
| `AOE_FALSIFICATION_REPORT.md` | `∀x₀, Reach_G(x₀) ∩ Ω = ∅` as "claim under test" | marked "under study **in a declared finite model**, not the primary demonstrated property" | P | Already well-qualified; distinguished model-study from production claim |
| `GLOBAL_SAFETY_VERIFICATION.md` | `Reach_G(x₀) ∩ U = ∅`, "the tested property" | added: not the primary demonstrated property; pointer | P | Already bounded by `SAFE_WITHIN_MODEL`; needed the distinction |
| `CODEX_DYNAMICAL_SCM_CAUSAL_OVERLAY_PROMPT.md` | "makes Ω unreachable in the appropriate known case" | "makes Ω unreachable **within the declared model**" | L | Prototype success criterion read as a general claim |

**Deliberately unchanged**, because the usage is not a safety claim: `newly_unreachable_states` (a computed metric in `global_verification`); "unreachable store"/"unreachable host" in `continuity.py`, `gate.py`, `test_authority_continuity.py`, `REMEDIATION_REPORT.md`, `RED_TEAM_CYBER_ASSESSMENT.md` (network and dependency availability); `REMEDIATION_REPORT.md` "High-severity harmful actions unreachable — **Met on the kernel path**" (already boundary-scoped); Intelligence and Identity Invariant rows in `Domain Strategy.md` (different invariants that merely use `ℛ(t)` notation).

**Living Boundary was not touched.** `docs/LIVING_BOUNDARY_BLUEPRINT.md` and `living-boundary/**` were excluded from the sweep by construction and verified unmodified.

---

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   PRIMARY   Propose(a) ∈ 𝔄,  Λ(a) ∉ 𝔄                           ║
║             Effect(a) ⟹ ∃ Λ(a) issued by K                      ║
║                                                                  ║
║   DERIVED   Reach_B(X₀) ∩ Ω = ∅   inside an established          ║
║             governed boundary B, conditional on T1–T7,           ║
║             M1–M7, and the open limitations                      ║
║                                                                  ║
║   The assumption did not disappear.                              ║
║   It got smaller, and it got auditable.                          ║
║                                                                  ║
║   Morrison Runtime Governance™          GB2600765.8              ║
╚══════════════════════════════════════════════════════════════════╝
```

---

Morrison Runtime Governance™ · Morrison Framework™ · Authority Separation

GB2600765.8 · GB2602013.1 · GB2602072.7 · GB26023332.5

© 2026 Davarn Morrison — Intelligence Invariant™ · All Rights Reserved

**Related work:**
[Pilot Briefing Card](PILOT_BRIEFING_CARD.md) ·
[Pre-Pilot Adversarial Evaluation](PRE_PILOT_ADVERSARIAL_EVALUATION.md) ·
[Complete Mediation Analysis](COMPLETE_MEDIATION_ANALYSIS.md) ·
[Governed Execution Veto Evaluation](GOVERNED_EXECUTION_VETO_EVALUATION.md) ·
[Limitations](morrison_governance/LIMITATIONS.md)
