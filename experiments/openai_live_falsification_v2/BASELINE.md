# Independent OpenAI falsification V2 rebuild: canonical baseline

This experiment is an independent rebuild. Its executable provenance begins at
`davarntrades/Morrison-Runtime-Governance` `main` commit
`0ba8f882590f34ee4f2ab7cee09b0d5e57d44248`. It does not use, reproduce, or
claim byte continuity with any prior inaccessible Codex workspace.

## Repository state before modification

- Remote: `https://github.com/davarntrades/Morrison-Runtime-Governance.git`
- Canonical commit: `0ba8f882590f34ee4f2ab7cee09b0d5e57d44248`
- Starting tree: clean
- Work branch: `experiment/openai-live-falsification-v2-work`
- Python test configuration: repository `pytest.ini`; package metadata in
  `morrison_governance/pyproject.toml`

## Production security boundary at the canonical commit

The primary in-process execution boundary is:

1. `GovernanceKernel.authorize(call)` canonicalises the proposal, quarantines
   caller authority claims, classifies capability/destination, verifies an
   approval, evaluates the Omega rules, seals evidence, and reserves a
   trajectory slot. It returns a `Decision`.
2. `GovernanceKernel.execute(decision, executor, call=None)` rechecks the
   decision lease, copies and hashes the exact action, atomically consumes the
   decision, commits trajectory state, and only then calls the executor.
3. `GovernanceKernel.submit` holds the local kernel lock across both stages.

Additional mediation layers do not replace that boundary:

- `GovernanceGuard` and the framework adapters in `integrations.py` delegate
  dispatch to the kernel.
- `ExecutionLease`/`LeaseVerifier` in `kernel/mediation.py` optionally move an
  action-bound check to a resource-side enforcement point.
- `GovernanceInterceptor` is an older advisory `GovernanceLayer`-based harness
  and is not the production approval/lease authority.

Complete mediation still depends on every consequential executor using the
kernel or a resource boundary that verifies its lease.

## Relevant existing suites

- `morrison_governance/test_kernel_redteam.py`
- `morrison_governance/test_governed_execution_veto.py`
- `morrison_governance/test_authority_continuity.py`
- `morrison_governance/test_authorization_containment.py`
- `morrison_governance/test_adversarial_round2.py`
- `morrison_governance/test_adversarial_round4.py`
- `morrison_governance/test_mediation.py`
- remaining `morrison_governance/test_*.py` and
  `morrison_governance/global_verification/test_*.py`
- `runtime_eval/tests/`, including adversarial hardening tests

## Canonical implementation findings

At the pinned commit, an approval HMAC covers semantic action hash, issuer,
scope, timestamps, and nonce. It does not cover principal or tenant. Approval
verification does not enforce `now >= issued_at`; nonce validation is
truthiness-based; and trusted issuance defaults to an empty nonce.

Semantic action identity uses the broad canonical tool family. Consequently,
distinct executors in one family can share an approval. `Decision` binds
session, principal, ruleset, exact action, semantic action, expiry, and use
state, but carries tenant only inside mutable authorization-report metadata and
does not compare it during redemption.

