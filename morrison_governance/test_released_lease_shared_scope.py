"""LEASE-SCOPE-01: a cancelled exported lease must stop counting against the
shared-resource budget.

Before the fix, `release()` of an exported decision dropped the principal's own
entry but not its `__resource__/<scope>` copies: those were still EXPORTED and
`drop` only removes RESERVED/UNCONFIRMED entries. EXPORTED never ages out, so
one mint-and-release with zero effects consumed shared budget for every
principal, including the releaser, permanently. Fail-safe, but a cross-principal
denial of service. The safety direction (a redeemed lease keeps counting) is
pinned alongside so the fix cannot trade it away.
"""
from __future__ import annotations

import dataclasses
import hashlib

import pytest

from morrison_governance._ed25519_test_signer import public_key, sign
from morrison_governance.kernel import (FileContinuityStore, InMemoryContinuityStore,
                                        LeaseVerifier, SQLiteLeaseStore)
from runtime_eval.falsification.harness import (account_scopes,
                                                aggregate_outflow_rule,
                                                make_kernel)

SEED = hashlib.sha256(b"disposable-lease-scope-test-seed").digest()
PUBLIC = public_key(SEED)
LIMIT, AMOUNT = 15_000, 9_000          # one transfer is admissible, two are not
T = {"tool": "transfer", "args": {"from": "SHARED", "to": "VENDOR-1", "amount": AMOUNT}}


def _kernel(principal, store, registry, window=None):
    k = make_kernel(principal=principal, store=store,
                    rules=[aggregate_outflow_rule("SHARED", LIMIT)],
                    resource_scopes=account_scopes)
    k.ctx = dataclasses.replace(k.ctx, lease_signer=lambda m: sign(SEED, m),
                                lease_store=registry)
    if window is not None:
        k.ctx.continuity_window_s = window
    return k


@pytest.fixture(params=["memory", "file"])
def stores(request, tmp_path):
    registry = SQLiteLeaseStore(tmp_path / "leases.sqlite")
    if request.param == "memory":
        shared = InMemoryContinuityStore()
        return registry, lambda: shared
    return registry, lambda: FileContinuityStore(tmp_path / "history.jsonl")


def test_cancelled_lease_frees_the_shared_budget_for_other_principals(stores):
    registry, store = stores
    a = _kernel("agent-a", store(), registry)
    d = a.authorize(T)
    assert d.verdict == "PERMIT"
    token = a.mint_lease(d).encode()
    assert a.release(d) is True
    effects = []
    assert LeaseVerifier(PUBLIC, registry).execute(token, T, effects.append)[0] is False
    assert effects == []
    assert not [e for e in store().entries("__resource__/account:SHARED")
                if e.decision_id == d.decision_id]
    b = _kernel("agent-b", store(), registry)
    other = b.authorize(T)
    assert other.verdict == "PERMIT"
    assert b.release(other) is True          # an ordinary (unexported) release
    # and the releasing principal itself, on a fresh kernel
    assert _kernel("agent-a", store(), registry).authorize(T).verdict == "PERMIT"


def test_redeemed_lease_still_counts_after_a_refused_release(stores):
    registry, store = stores
    a = _kernel("agent-a", store(), registry)
    d = a.authorize(T)
    token = a.mint_lease(d).encode()
    effects = []
    assert LeaseVerifier(PUBLIC, registry).execute(token, T, effects.append)[0] is True
    assert a.release(d) is False
    # the redeemed entry must survive even a retention window that has lapsed
    b = _kernel("agent-b", store(), registry, window=0.000001)
    decision = b.authorize(T)
    assert decision.verdict == "BLOCK"
    assert decision.rule == f"aggregate_outflow_SHARED_le_{LIMIT}"
    assert effects == [T]


def test_repeated_mint_and_release_cannot_exhaust_the_shared_budget(stores):
    registry, store = stores
    a = _kernel("agent-a", store(), registry)
    for _ in range(5):
        d = a.authorize(T)
        assert d.verdict == "PERMIT"
        a.mint_lease(d)
        assert a.release(d) is True
    assert _kernel("agent-b", store(), registry).authorize(T).verdict == "PERMIT"
