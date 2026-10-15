# Exported execution authority: mrl2 migration

This repairs exported-lease failures reproduced at
`f93c010e98530874787a3e3f6c8485343a62f94f`. Original commits and negative
findings remain valid historical evidence. Direct kernel execution already
required binding; the affected resource path was detached verification.

## Required configuration

```python
from morrison_governance.kernel import LeaseVerifier, SQLiteLeaseStore
registry = SQLiteLeaseStore('/trusted/shared/leases.sqlite')
ctx.lease_signer = external_ed25519_sign  # deployment-owned bytes -> 64-byte signature
ctx.lease_store = registry
# Construct the kernel with this authenticated context and appropriate continuity store.
decision = kernel.authorize(actual_action)
token = kernel.mint_lease(decision).encode()
# Separate resource process: public key only; same atomic registry.
resource = LeaseVerifier(issuer_public_key, registry)
executed, result = resource.execute(token, actual_action, executor)
```

The signer belongs to authenticated issuer infrastructure, e.g. a signing
service or protected key manager. Production private-key management is not
implemented here. The repository test signer is only for disposable tests.
Resources receive the raw 32-byte public key, never the private signing seed.

Strict schema, Ed25519 signature, finite deadlines, actual action hash, and
atomic consumption of the exact issuer-registered token precede dispatch.
Missing request, store, invalid binding, duplicate/cancelled/unissued token, or
dependency failure refuses. `execute()` hashes and forwards the same private
snapshot. A lower-level `verify()` caller must forward that verified request.

## Compatibility and trust domains

- mrl1 HMAC leases are rejected with no symmetric fallback. `lease_signing_key`
  is deprecated and unused for export. The `key=` mint override is rejected.
- All issuers/verifiers must use one durable atomic registry. There is no
  implicit process-local redemption store.
- SQLite supports independent processes sharing one **local host** file. It
  is not a multi-host database. Fleet deployments supply a `LeaseStore` service
  implementing atomic register/consume/cancel. That backend is not supplied or
  experimentally certified by this patch.
- Use issuer-only registration, resource consumption, authenticated service
  identities and separate issuer keys for separate trust domains. SQLite assumes
  trusted processes and does not implement role ACLs. Do not expose its object
  or database to proposing agents.
- Multi-kernel/restart continuity also requires a shared durable
  `ContinuityStore`; a new independent in-memory store cannot recover history.
  The included durable regression uses `FileContinuityStore` on one host.
- Key rotation and key discovery are deployment responsibilities. Each verifier
  accepts one configured public key; drain/cancel old leases before retiring it.
  Policy revocation requiring immediate resource denial must also cancel the
  outstanding registered tokens; changing an issuer's context alone does not
  change a detached verifier's configuration.
- Consumption precedes dispatch: **at-most-once dispatch**, not distributed
  exactly-once effects. A crash may leave zero effects or an unknown outcome.
  Redemption is never refunded after dispatch.

## Trajectory lifecycle

Export persists `EXPORTED` history and spends local execution before signing
and registering authority. Local execution and another export are refused.
Dependency failure after persistence retains conservative history.

Release atomically cancels the resource token **before** erasing history. If
redemption won, release fails and history remains. Exported entries survive
ordinary retention and cannot be erased by free-text `reconcile(..., False)`.
Token expiry alone does not establish that no effect occurred. Authenticated
remote settlement is not implemented; unknown outcomes can retain history
indefinitely. This is an availability tradeoff, recorded rather than hidden.

## Provenance and strict envelopes

The policy-fact injection was already repaired by
`b1e44163cf6adedf776015e448ab3c4e8d8067d9`. This patch preserves that repair.
Trusted facts must originate in authenticated server-side state, never peer
messages copied into trusted configuration.

Authority-shaped fields are now quarantined recursively through dictionaries
and arrays, retaining JSON Pointer locations as evidence. Material unsupported
claims block by default. A strict envelope rejecting every such claim, even on
benign actions, explicitly sets `reject_untrusted_authority_claims=True`.
Default False preserves the documented noise/materiality distinction. The flag
participates in policy fingerprints; changes invalidate outstanding local
PERMIT decisions. The Petri finite oracle is run with the strict flag enabled.

## Reproduction

```sh
python -m pytest -q morrison_governance/test_exported_lease_security.py morrison_governance/test_mediation.py
```

Disposable keys, list effects, SQLite writes and spawned independent verifier
processes cover missing/wrong binding, malformed metadata, duplicate redemption,
public-key forgery, cancellation races, release/read/send composition, persistent
continuity, mutation and strict-envelope changes. No production infrastructure
or secrets are involved.
