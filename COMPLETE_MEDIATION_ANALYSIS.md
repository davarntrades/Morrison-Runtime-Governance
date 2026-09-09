# Complete Mediation: What Must Be True, What Morrison Can Enforce, What Cannot Be Enforced From Here

**Repository:** `davarntrades/Morrison-Runtime-Governance`
**Head:** `1a7abb3`
**Companion to:** [Pre-Pilot Adversarial Evaluation](PRE_PILOT_ADVERSARIAL_EVALUATION.md)

---

## Why this document exists separately

Every claim Morrison makes is conditional on one assumption:

> **T1 — every consequential executor is reachable only through
> `GovernanceKernel.execute`.**

Four rounds of adversarial evaluation closed 43 counterexamples inside the
kernel and left T1 untouched, because T1 is not a property of the kernel. It is
a property of the environment the kernel is installed in. A veto authority that
governs what calls it is exactly as complete as the discipline of everything
that could call something else.

This document says precisely what "complete mediation" would require, what the
library can now enforce or attest by itself, and what irreducibly remains a
deployment obligation. It is deliberately separate from the evaluation report,
because a reader deciding whether to pilot needs to weigh this independently of
how the mechanism performs under attack.

---

## 1 · What would have to be true

Complete mediation for a deployment means: **there is no sequence of operations
available to the agent that produces a consequential effect without a Morrison
authorization bound to that exact effect.**

Decomposed into conditions a deployment can actually check:

| # | Condition | Why it is load-bearing |
|---|---|---|
| **M1** | **The agent holds no credential that reaches a consequential resource directly.** Every credential is held by an executor the agent must ask, never by the agent. | The single most common violation. An agent with a database password does not need any tool. |
| **M2** | **Every executor requires a valid, fresh, action-bound authorization.** Not "checks a policy" — *requires an artifact it cannot mint*. | An executor that merely consults a policy can be induced to consult it wrongly. One that demands an unforgeable token cannot be talked past. |
| **M3** | **The authorization is verified by the resource side, not by the caller.** | A check performed by the component being governed is advice. VETO-08 was exactly this: adapters that evaluated and then dispatched themselves. |
| **M4** | **Every network path from the agent to a consequential resource passes an enforcement point.** Egress is default-deny; the enforcement points are the only exceptions. | Without this, M1–M3 govern the paved road while the agent walks around it. |
| **M5** | **The set of consequential resources is enumerated, and the enumeration is maintained.** | An unenumerated resource is an unenforced one. This is where deployments rot over time. |
| **M6** | **The agent cannot alter the enforcement configuration**, including its own identity, the tool manifest, allowlists, policy values, and the continuity store. | Otherwise mediation is self-referential: the governed thing edits the governor. |
| **M7** | **Effects are reconciled against authorizations**, and unexplained effects are investigated. | The only way to detect a violation of M1–M6 that is already happening. |

M1–M4 are preventive. M5–M7 are what stop the first four decaying silently.

---

## 2 · What Morrison can enforce or attest by itself

Everything in this section is code in this repository with tests behind it.

### 2.1 Enforced: the decision itself

The kernel is a complete reference monitor **for calls that reach it**. Rounds
1–4 establish this in detail: pre-execution refusal, trajectory dependence
across sessions/processes/workers, single-use decisions, single-use approvals,
action-hash binding through a deep copy, semantic invariance under renaming and
encoding, fail-closed on unreadable payloads and unattributable identity.

That is the whole of what a library can enforce from inside the process it is
called in.

### 2.2 Newly enforceable: the resource-side check (M2, M3)

`kernel/mediation.py` moves part of the check out of the caller.

```
agent ──proposal──▶ kernel ──lease──▶ agent ──request + lease──▶ gateway
                                                                    │
                                                       LeaseVerifier.verify()
                                                                    │
                                                              resource
```

`GovernanceKernel.mint_lease(decision)` issues an `ExecutionLease` — signed,
short-lived, single-use, bound to the canonical action hash, the principal, the
tenant, the session and the decision. A `LeaseVerifier` deployed **in the
gateway, sidecar, or tool server** — a different process from the agent —
refuses any request without a valid one.

This converts M2 and M3 from assumptions into mechanisms, for every resource
that adopts it. An agent that skips the kernel arrives carrying nothing and is
refused by something that does not depend on its cooperation.

The mechanism was attacked before being trusted (`test_mediation.py`, L-01…L-10).
One defect was found and closed in that pass: the verifier allowed five seconds
of clock skew unconditionally, so a deployment minting one-second leases got a
grace period it had not asked for. Skew is now bounded by the lease's own
lifetime.

Properties that held under attack: a leaseless request is refused; a lease is
single-use, including under concurrent redemption; an agent cannot mint or
re-sign one; **verify-one-request-forward-another is refused** (ATK-02 relocated
to the gateway, which is why the lease binds the action hash and the verifier
re-derives it from the request it is about to forward); tampering invalidates
the signature; a BLOCK or a preview decision cannot mint a lease; an unkeyed
verifier and a malformed token both fail closed.

`lease_signing_key` is deliberately separate from the approval `signing_key`: a
gateway must verify leases and has no business being able to mint approvals.

### 2.3 Newly attestable: coverage and scope (M5)

- `MediationReport` records the **declared** execution surfaces and which of
  them enforce leases. Its `complete` property means *every declared surface is
  enforced* and its own `caveat` field says so, because Morrison cannot discover
  a route nobody told it about.
- `Decision.continuity_scope` reports how far governed history actually reaches
  (`process` / `host` / `deployment`), so a deployment can **assert** the reach
  of the guarantee it relies on rather than believe it. Pinned in
  `test_r4b_05` as an attestation **by the store**, not a verified property: a
  store returning `"deployment"` while writing to a host-local file is believed.

The value here is not the number. It is that the unenforced set becomes an
explicit list somebody signed, rather than a blanket assumption nobody wrote
down.

### 2.4 Newly enforceable: reconciliation (M7)

`GovernanceKernel.unconfirmed()` lists dispatches whose outcome was never
confirmed; `reconcile(decision, executed, attestation)` settles one, requiring
an external attestation naming what was checked and by whom, sealed into the
evidence chain. Morrison cannot determine whether an effect landed — it can
record who says it did not and stand behind that record.

This is a partial M7: it reconciles *Morrison's own uncertain dispatches*. It
does not reconcile effects Morrison never saw, which is the harder half.

---

## 3 · What remains an external deployment assumption

None of these is closable from inside a Python library, and saying otherwise
would be the most dangerous thing in this document.

| # | Assumption | Who must establish it | How it fails |
|---|---|---|---|
| **M1** | Agents hold no direct credentials | IAM / secret management | An agent with a DB password needs no tool. Morrison never sees the connection. |
| **M4** | Default-deny egress with enforcement points as the only exceptions | Network policy, service mesh, egress proxy | The agent reaches the resource by a path with no verifier on it. |
| **M5** | The enumeration of consequential resources is complete and maintained | Architecture review, change control | A new service ships without a verifier; the report stays green because nobody declared it. |
| **M6** | Enforcement configuration is outside the agent's reach | Deployment topology, config management | If the agent can edit the manifest, allowlists, or the continuity store, mediation is self-referential. |
| **M7** | Observed effects are reconciled against authorizations | SIEM / audit pipeline | The only detector for a violation already in progress. |
| — | The lease secret is not reachable by the agent | Secret management | An agent with `lease_signing_key` mints its own authority. |
| — | The continuity store is trusted, shared, and atomic | Platform | `consume` and `transaction` carry the single-use and serialisation properties. A store that lies about `scope` is believed. |
| — | Verifiers actually deny on failure | Gateway implementation | A verifier whose failure path logs and forwards is not a verifier. |

### The honest summary of the delta

Before this work, T1 was a single unqualified assumption covering everything.
After it, T1 decomposes into:

- **enforced by Morrison** — the decision, the binding, the trajectory, the
  single-use properties;
- **enforceable by Morrison at any boundary a deployment adopts** — the
  resource-side lease check (M2, M3);
- **attestable but not verifiable** — declared coverage and continuity scope
  (M5, partially);
- **irreducibly external** — credential placement, network topology, enumeration
  maintenance, configuration custody, effect reconciliation (M1, M4, M5, M6, M7).

That is a smaller assumption than the one we started with, and it is one a
deployment can audit line by line. It is not complete mediation.

---

## 4 · What a pilot should do about it

In priority order, because the first item dominates the rest:

1. **Enumerate every consequential resource** and, for each, name the executor
   that fronts it and the credential it holds. This is the artifact everything
   else hangs off, and most deployments do not have it.
2. **Move credentials off the agent** onto those executors (M1). Nothing else in
   this list matters if the agent can act directly.
3. **Put a `LeaseVerifier` in front of the highest-consequence resources first**
   — payments, credentials, bulk data, infrastructure mutation — and make its
   failure path deny (M2, M3).
4. **Make egress default-deny** with the enforcement points as the only
   exceptions (M4).
5. **Configure a shared, atomic `ContinuityStore`** if the deployment is
   multi-host, and assert `continuity_scope == "deployment"` in preflight.
6. **Reconcile**: alert on any effect at a governed resource with no
   corresponding authorization, and on `unconfirmed()` entries that age.
7. **Record the unenforced set** in a `MediationReport` and review it on every
   architecture change. An unenforced surface is not a failure; an *unrecorded*
   one is.

A pilot that does 1–3 has converted the largest part of T1 from belief into
mechanism. A pilot that does none of them is relying on the assumption exactly
as much as before, whatever the test suite says.

---

Morrison Runtime Governance™ · Complete Mediation Analysis

GB2600765.8 · GB2602013.1 · GB2602072.7 · GB26023332.5

© 2026 Davarn Morrison — Intelligence Invariant™ · All Rights Reserved
