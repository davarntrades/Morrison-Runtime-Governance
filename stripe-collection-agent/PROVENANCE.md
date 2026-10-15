# What existed before the hackathon, and what was built during it

## Pre-existing (Morrison Runtime Governance repository, commit `06b9b55`; unmodified)

- `morrison_governance/kernel/gate.py`: `GovernanceKernel` (authorize, reservations, execute, mint_lease, release, revocation, evidence sealing).
- `morrison_governance/kernel/mediation.py`: `ExecutionLease` (mrl2, Ed25519), `LeaseVerifier`, `SQLiteLeaseStore`, `mint_lease`.
- `morrison_governance/kernel/trust.py`: `SecurityContext` (trusted_facts, resource_scopes, policy_values, approvals), `Principal`, `issue_approval`, authority quarantine.
- `morrison_governance/kernel/continuity.py`: `FileContinuityStore`, ledger states (RESERVED / EXPORTED / EXECUTED).
- `morrison_governance/kernel/evidence.py`: `EvidenceChain`, `EvidenceRecord`, `ruleset_hash`.
- `morrison_governance/kernel/ed25519.py`: Ed25519 verification.
- `morrison_governance/core.py`, `reachability.py`, `domains.py`, `provenance.py`, `trajectory.py`: `GovernanceLayer`, the Ω engine, `OmegaRule`, provenance-aware evaluation state.

## Built during the event (`stripe-collection-agent/`)

| File | Purpose |
|---|---|
| `collection_agent/envelope.py` | Financial Admissible Operating Envelope as two Morrison Ω rules (local, global) |
| `collection_agent/governance.py` | Kernel configuration: principal, manifest, capability policy, continuity, resource scopes, trusted facts, leases, approvals, agreement changes |
| `collection_agent/signer.py` | External Ed25519 lease signer (Morrison ships verify-only) |
| `collection_agent/governance_service.py` | Trusted HTTP service around the kernel |
| `collection_agent/executor_service.py` | Trusted Stripe executor behind Morrison's `LeaseVerifier` |
| `collection_agent/stripe_gateway.py` | Stripe test-mode invoice workflow and accounting |
| `collection_agent/agent.py` | Untrusted agent (Claude tool use, or a rule-based fallback) |
| `collection_agent/agent_steps.py` | Keyless agent-side steps for the scenario harness |
| `collection_agent/launcher.py` | Process separation and per-process secret routing; Stripe test fixtures |
| `collection_agent/scenarios.py` | Adversarial scenarios S0–S12, Stripe-audited classification, evidence output |
| `collection_agent/dashboard.py`, `static/index.html` | Demonstration dashboard |
| `collection_agent/stripe_double.py` | Local Stripe API double for offline tests only (never reported as Stripe) |
| `collection_agent/web.py`, `demo.py` | HTTP plumbing; demo launcher |
| `collection_agent/verify_live.py` | Independent post-run re-read of Stripe effects; never counts the double as live |
| `scripts/export_standalone.sh` | Exports the app as a standalone public repository (Morrison as a pinned submodule) |
| `tests/` | 26 automated tests |
| `../.github/workflows/stripe-collection-live.yml` | CI: offline suite, plus the live Stripe test-mode run when the secret is set |

Repository-level edits outside this directory: `pytest.ini` (`norecursedirs` += this app) and `.pylintrc` (`ignored-modules` += `stripe`, `cryptography`, `collection_agent`).
