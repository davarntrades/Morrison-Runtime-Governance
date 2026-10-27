# Dynamic Ω: formal definitions

This note defines the objects that `world.py`, `model.py`, `governance.py` and `oracle.py` implement.
Every claim below is tied either to an argument or to a named benchmark case; none is assumed from Morrison's intended architecture.

## 1. The actual system Ω(t)

Ω(t) = (X, A_t, δ_t, τ_t, W_t)

| symbol | meaning | in the benchmark |
|---|---|---|
| X = O × H | state: observable part O, hidden part H | `World.observe()` returns O; `_storage_build` is H |
| A_t | transitions the executor can actually perform at t | `registry` (tools) plus pathways reachable through them (`jobs`) |
| δ_t : X × A_t → X | actual transition function; depends on installed dependencies and on H | `World.apply` |
| τ_t : X → X | autonomous dynamics per tick (periodic mechanisms) | `World.tick` (retention sweeper) |
| W_t | other principals that write state without passing through the authority | environment events (`external_allocate`, `admin_pool`, `admin_config`) |

Ω evolves when A_t, δ_t, τ_t or W_t change. Ω(t+1) = Ω(t) is never assumed.

## 2. The authority's represented model R(t)

R(t) = (K_t, Ŝ_t)

- **Knowledge K_t** = (Â, δ̂, schema, τ̂, versions): the transitions the authority has effect models for, those effect models, the config schema it understands, the periodic mechanisms it knows about, and the dependency versions δ̂ was written for. In the benchmark it is `KNOWLEDGE_T0`, and only a verified attestation can change it (condition 5 only).
- **State estimate Ŝ_t** ∈ O: the t0 observation projected through the executed trajectory (static, condition 3), or a fresh `observe()` at decision time (refreshed, conditions 4/5).

The authority can only ever inspect O. It can inspect a *proposed* transition a only through Â and δ̂.

## 3. Properties

- **Local**: a predicate on a single transition (x, a, x′), e.g. "the ledger is not rewritten by this call".
- **Global (state)**: a predicate on states that individually admissible transitions can jointly violate, e.g. Σ pools + Σ external ≤ capacity.
- **Global (temporal)**: a predicate over a trajectory segment of horizon H, including τ, e.g. "every record present now is still present H ticks later".
- **Behavioural**: a predicate measured by running the system, e.g. "a fresh record reaches the replica". It cannot be read off any single field.

The benchmark protects `ledger_records_persist` (temporal, also expressible at the resource), `quota_within_capacity` (global state, also expressible at the resource) and `replication_delivers` (behavioural, not expressible as a resource-side constraint).

## 4. A governed transition

1. At decision time t_d the authority computes d = Auth(R(t_d), a) ∈ {ALLOW, BLOCK, ESCALATE, NOT_ESTABLISHED} and a binding β = h(scope(obs(x_{t_d}))).
2. At check time t_c the executor re-computes h(scope(obs(x_{t_c}))) and refuses if it differs from β.
3. At effect time t_e the world performs x_{t_e+} = δ_{t_e}(x_{t_e}, a). After that, τ and W continue.

**Soundness requirement for ALLOW.** For every x consistent with what the authority knows and has bound, the trajectory δ(x, a) followed by τ (and any W the authority does not mediate) over the horizon keeps P.

## 5. The four failure modes, distinguished

| mode | definition | benchmark cases |
|---|---|---|
| **Incomplete representation** | a ∉ Â, or a reaches a mechanism or state component outside δ̂'s domain (unknown job, unknown key, unknown tool) | A1, A2, E1, E2 |
| **Outdated representation** | Ŝ ≠ obs(x_t), or K was written for a δ that has since changed observably (dependency version, capacity) | B1, F1, F2, F3 |
| **Incorrect transition model** | Ŝ = obs(x) exactly, yet δ̂(Ŝ, a) ≠ obs(δ(x, a)): a hidden change in H, a wrong footprint (the set of state the transition depends on), a wrong attestation | B2, G1, G2, G3, G4 |
| **Authorization-to-execution race** | x changes between t_d and t_c (outside the binding scope), between t_c and t_e (no lease/atomicity), or after t_e by an unmediated writer | C1, C2, C3, G5 |

Composition and deferred effects (D1, D2, G6) cut across all four. A per-action check, or a check without a temporal horizon, cannot see them at all.

## 6. Claims tested (each is falsifiable, with the case that tests it)

- **C-static.** If K can become stale and the authority treats an unmodelled transition as having no effect (PR #43 `project` semantics), there are transitions it ALLOWs that violate P. *Tested by A2, B1, E1, D2.*
- **C-refresh.** Refreshing Ŝ does not refresh K. It also leaves the t_d→t_e race open. *Tested by A2, B1, E1 (K), C2, C3 (race) under condition 4.*
- **C-NE.** A three-valued verdict (ALLOW / BLOCK / NOT_ESTABLISHED) prevents failures of incomplete and observable-outdated representation without complete knowledge, at a measurable utility cost. *Tested by A2, B1, E1 (prevented), E2, F3, G5 (false refusals).* But the adequacy check is itself a model: it can only flag what it knows to look at. *Tested by G1.*
- **C-observability.** If a change lives in H (unobservable) and alters δ for a, no authority-side check over O can separate the safe world from the unsafe one. A sound ALLOW of a would have to hold in every H-consistent world. *Tested by B2, G2, G3.* Post-execution verification turns some of these into detection, but only if the divergence shows in O inside the verification window. *G3 shows a case where it does not.*
- **C-mediation.** A global property over a resource that an unmediated principal also writes cannot be enforced by mediating only the governed agent, however exact the binding. *Tested by C3 under condition 5.*
- **C-resource.** If P can be expressed as an invariant over a resource's own state transitions and the resource enforces it for every writer, P holds regardless of how accurate R is. *Tested by B2, G1, G3, G4, G6, C3 under 5R.* This does not extend to behavioural properties. *Tested by G2 under 5R.*
