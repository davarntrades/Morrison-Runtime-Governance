# Morrison Global Governance — meta-governance layer

The runtime governance core answers a **local** question: *can this
trajectory reach Ω?* "Global" safety needs more than a local check.
This package implements — as concrete, deterministic, **tested**
mechanisms on top of the existing reachability core — the nine
additional requirements a meta-governance system needs.

> **Honest framing.** This is a *mechanism-level* implementation, not a
> proof of global safety. Seven requirements ship as full deterministic
> mechanisms; two (distributed trust, institutional legitimacy) ship as
> the governance-layer-side mechanism of a larger socio-technical /
> infrastructure problem. Every claim below is bounded to the in-tree
> test suite.

## The requirement table → what this package ships

| # | Requirement | Why it matters | Module | Status |
|--:|:------------|:---------------|:-------|:------:|
| 1 | Runtime governance | the validated core | `morrison_governance.GovernanceLayer` | **core** |
| 2 | Cross-system trajectory analysis | multi-agent / multi-service | `cross_system.py` | **implemented** |
| 3 | Adaptive Ω evolution | new failure modes emerge | `adaptive_omega.py` | **implemented** |
| 4 | Hierarchical governance layers | local + regional + global | `hierarchy.py` | **implemented** |
| 5 | Formal interface standards | shared execution geometry | `interface_standard.py` | **implemented** |
| 6 | Continuous adversarial auditing | reality changes | `continuous_audit.py` | **implemented** |
| 7 | Memory-aware governance | long-horizon effects | `memory_governance.py` | **implemented** |
| 8 | Self-verifying controllers | governance integrity | `self_verifying.py` | **implemented** |
| 9 | Distributed trust architecture | no single failure point | `distributed_trust.py` | **mechanism** |
| 10| Human override / institutional | political & ethical legitimacy | `institutional.py` | **mechanism** |

`MetaGovernance` (`meta.py`) composes them into one deny-by-default
stack: a trajectory must clear the hierarchical tiers **and** the
distributed quorum **and** self-verification, then memory-aware
escalation and the institutional layer apply. Any layer that blocks →
BLOCK.

## How each mechanism preserves the ontology

Every mechanism delegates the actual safety decision to
`morrison_governance.GovernanceLayer` (the reachability hierarchy
A_safe → V2 → V3 → V4 → V4+ → V5 → V5+). None of them classify text.
The meta-layer only changes *how the local verdicts compose*:

- **Cross-system** flattens independent systems into one joint
  trajectory so an acquire-by-A / egress-by-B chain is governed as a
  single reachable set (blocks at V2). Handoffs are attribution
  metadata, not governed steps.
- **Adaptive Ω** is versioned + hash-chained: a case that bypasses at
  v0 blocks at v1 once the closing rule is ingested, and v0 remains
  replayable.
- **Hierarchy** is strict-strengthening: any tier that blocks → BLOCK;
  the first blocking tier is reported, all tiers evaluated for audit.
- **Interface standard** pins the ToolCall / Trajectory / Verdict
  contract + a conformance checker so heterogeneous components compose.
- **Continuous audit** snapshots + diffs an adversarial corpus and
  surfaces *regressions* (was-blocked → now-permitted) deterministically.
- **Memory-aware** keeps a bounded decaying per-entity cumulative risk;
  it can only **escalate** a PERMIT to a human-review BLOCK across
  sessions — never relax a BLOCK. Fail-closed direction preserved.
- **Self-verifying** checks determinism + strict-strengthening
  monotonicity of its own decision and **fails closed** (BLOCK,
  `integrity_violation`) if either invariant is violated; emits a hash-
  chain attestation.
- **Distributed trust** runs N replicas under a **deny-by-default
  quorum**: permitted only if *every* replica permits; a corrupt or
  crashed replica can only force BLOCK, never PERMIT.
- **Institutional** allows an always-available veto (more restriction)
  and a permit-override **only** with a scoped, signed authorization,
  all appended to a tamper-evident audit chain.

## Test results (bounded)

```
python3 global_governance/tests/test_global_governance.py
→ 27 passed, 0 failed
→ scorecard: addressed 10/10  (core=1, implemented=7, mechanism-only=2)
```

Full repository regression after adding this package: **23 suites ·
281 cases · 0 failures**. The 20 morrison_governance suites and the
runtime_eval suites are byte-for-byte unchanged (this package is
purely additive).

## What "mechanism-only" honestly means

- **Distributed trust** — implemented as an in-process deny-by-default
  quorum over replica diversity. A real deployment needs Byzantine-
  fault-tolerant consensus across physically distributed, independently
  operated nodes with cryptographic attestation. That infrastructure is
  out of scope; what is implemented and tested is the governance-side
  invariant: *safety holds as long as at least one honest replica says
  BLOCK*.
- **Institutional governance** — implemented as scoped signed
  authorizations + a tamper-evident audit chain. Real political /
  ethical *legitimacy* (who may sign, under what mandate, with what
  accountability) is a socio-technical question outside any codebase.
  This layer makes the override mechanism auditable; it does not confer
  legitimacy.

## Limitations & honesty

- This package does **not** make the system "globally safe". It
  implements and tests the *mechanisms* the requirement table lists.
- All metrics are bounded to the in-tree deterministic suite — not
  third-party security coverage.
- Memory-aware escalation is a tunable signal; aggressive thresholds
  trade false-positive (over-block, human review) against long-horizon
  sensitivity. The default is conservative and the direction is
  fail-closed.
- See `CRITICAL_EVALUATION.md` (repo root) for the project-wide
  skeptical self-assessment.

## Governing invariant

```
ℛ(t) ∩ Ω = ∅
```

preserved throughout. The meta-layer composes local reachability
verdicts; it never weakens the underlying check.

-----

## Merge audit (verified)

This package was reviewed against a 10-condition merge gate before
acceptance. Every condition held; the merge is additive.

| # | Condition | Result |
|--:|:----------|:------:|
| 1 | Invariant `ℛ(t) ∩ Ω = ∅` preserved | ✅ delegated, never reimplemented |
| 2 | Core `A_safe → V2 → V3 → V4 → V4+ → V5 → V5+` untouched | ✅ `git diff` over `morrison_governance/` + `runtime_eval/` for the merge commit is **empty** |
| 3 | New layers compose around the core, not replace it | ✅ every decision-bearing module imports + calls `GovernanceLayer.evaluate{,_plan}` |
| 4 | No RLHF / semantic classifiers / moderation / non-determinism / regression | ✅ source scan: zero `random`/`time`/`datetime`/`uuid` in non-test code; zero `embedding`/`classifier`/`torch`/`moderat`/`rlhf`/`softmax` anywhere |
| 5 | Suites green · deterministic replay · deny-by-default · fail-closed · delegation | ✅ 23 suites · 281 cases · 0 failures; byte-identical replay; targeted deny-by-default + fail-closed checks pass |
| 6 | Nine new modules structurally validated | ✅ 27 functional tests across all nine + `MetaGovernance` |
| 7 | Claims honestly bounded | ✅ scorecard marks exactly 2 rows `mechanism-only`; bounded language throughout |
| 8 | Full regression + suite + replay + adversarial checks run | ✅ see condition 5 |
| 9 | Clean additive merge + consistent README/scorecard | ✅ this section |
| 10| Reject if any layer weakens reachability / adds moderation | ✅ no weakening or moderation found — **accepted** |

**What was added:** nine meta-governance mechanisms (cross-system,
adaptive Ω, hierarchy, interface standard, continuous audit, memory-aware,
self-verifying, distributed trust, institutional) + `MetaGovernance`
composition + readiness scorecard.

**What stayed unchanged:** the entire runtime governance core and the
`runtime_eval` harness — byte-for-byte. The invariant `ℛ(t) ∩ Ω = ∅`
and deny-by-default / fail-closed semantics are inherited unchanged from
the delegated `GovernanceLayer`.

**What remains explicitly out of scope:** real Byzantine-fault-tolerant
distributed consensus (distributed trust is an in-process deny-by-default
quorum model) and real political / ethical legitimacy (institutional
governance ships the auditable mechanism, not the mandate). Both are
labelled `mechanism-only` in the scorecard.
