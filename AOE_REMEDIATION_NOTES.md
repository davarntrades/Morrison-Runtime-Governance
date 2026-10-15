# Proposed remediation — not implemented

Scope: findings at `331db2096632d2f7633a42c712a067320b495d43`.
Approval for implementation is still required. These are designs, not verified fixes.

## E1 — Decision reuse

The same genuine permitted Decision can be passed twice to `GovernanceKernel.execute`.
This produces two callback effects. Hazard requires non-idempotent execution and
an integration that reuses the decision without external deduplication.

Candidate: a kernel-issued unique decision ID with atomic single-use consumption,
bound to principal, session and action, plus executor-side idempotency. Define
failure/retry semantics explicitly: an executor exception may follow a partial
effect, so returning the token to an available state is not automatically safe.

Acceptance tests: duplicate sequential use; concurrent duplicate use; a failed
callback after a partial effect; cross-session use; legitimate reauthorization;
and remote-runtime receipt retries. Preserve ALLOW/BLOCK/ESCALATE semantics.

## E2 — Policy changes before commit

A decision obtained before an in-memory trusted policy change can still execute,
even when fresh authorization of identical bytes is refused.

Candidate: bind policy/configuration version and a validity interval to the
decision, and atomically revalidate at the committing executor. Account for
resolved resource identity and state-version changes where relevant.

Acceptance tests: revocation between authorization and commit; stale snapshots;
expiry boundaries; same-policy execution; racing commits; and policy changes
that do not invalidate an existing authorization under explicitly defined lease
semantics. The desired revocation semantics must be chosen before implementation.

## Synthetic semantic coverage cases

Do not add blanket denial rules merely to make the seven prior fixtures safe.
First supply real connector effect contracts, operative Ω requirements, benign
controls and model-conformance evidence. A restrictive capability policy may
resolve a bounded case without a successor-state API. Compare both approaches
for safety and useful progress, including justified non-executing escalation.

## Uncontrollable transitions

Do not route a human/environment transition through a fake authorization gate.
Model it as uncontrollable and check controlled invariance. If no safe strategy
exists, return that result; remediation requires changed authority, initial
conditions or environment, not a cosmetic policy change.
