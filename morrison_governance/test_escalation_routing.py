"""BUG B — ESCALATE must have a destination.

Before this, an ESCALATE was a synchronous refusal that went nowhere: nothing
persisted, nobody notified, no timeout, no default, and indistinguishable from
BLOCK to the caller. Each of those is proven closed below, end to end, through
the real kernel.

The four scenarios the finding demanded, in order:
  1. trigger an ESCALATE and confirm it is persisted and queryable
  2. simulate a timeout with no response and confirm the default fires
  3. simulate a valid response arriving in time and confirm the original
     action proceeds
  4. (added) confirm a late response cannot revive an expired request
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import GovernanceLayer, OmegaDomain  # noqa: E402
from morrison_governance.escalation import (  # noqa: E402
    APPROVED, DENIED, EXPIRED, PENDING, TIMEOUT_ESCALATE,
    EscalationRouter, FileEscalationStore, InMemoryEscalationStore,
)
from morrison_governance.kernel import (  # noqa: E402
    GovernanceKernel, Principal, SecurityContext,
)

ORG_KEY = b"org-approval-signing-key"
REVIEWER = "security-review"

# A payment large enough to require an approval: capability payment.move_funds
# is APPROVAL by default policy, so this escalates rather than blocking.
CALL = {"tool": "wire_transfer", "args": {"amount": 4_500_000, "payee": "acct-9931"}}

_SEQ = [0]


def _kernel(router, approvals=()):
    _SEQ[0] += 1
    gov = GovernanceLayer(domains=[OmegaDomain.FINANCE], log_all=False)
    ctx = SecurityContext(
        principal=Principal(id=f"agent-{_SEQ[0]}", tenant="corp"),
        signing_key=ORG_KEY, trusted_issuers=frozenset({REVIEWER}),
        approvals=tuple(approvals),
        tool_manifest={"wire_transfer": ["payment.move_funds"]})
    return GovernanceKernel(gov, ctx, session_id=f"esc-{_SEQ[0]}",
                            escalation_router=router)


# ═══════════════════════════════════════════════════════════════
# 1. PERSISTED AND QUERYABLE
# ═══════════════════════════════════════════════════════════════

def test_escalate_is_persisted_and_queryable():
    router = EscalationRouter(ttl_s=600)
    k = _kernel(router)
    d = k.authorize(CALL, now=1000.0)

    assert d.verdict == "ESCALATE", d.reason
    assert d.escalation is not None, "the ESCALATE was not routed anywhere"

    queued = router.pending()
    assert len(queued) == 1
    esc = queued[0]
    assert esc.state == PENDING
    assert esc.tool == "wire_transfer"
    assert esc.principal == k.ctx.principal.id
    assert esc.semantic_hash == d.semantic_hash
    assert esc.expires_at == 1000.0 + 600
    # Queryable by id and by owner, not only as an opaque list.
    assert router.get(esc.id).id == esc.id
    assert router.query(state=PENDING, principal=esc.principal) == [esc]
    # And it is in the decision the caller already holds.
    assert d.as_dict()["escalation"]["id"] == esc.id


def test_a_retrying_agent_does_not_flood_the_reviewer():
    """500 retries of the same refused action open ONE review.

    The finding measured 500 authorize rounds producing 1002 ledger entries
    and nothing else. Unbounded retries must not become unbounded review
    workload either.
    """
    router = EscalationRouter(ttl_s=600)
    k = _kernel(router)
    for i in range(500):
        d = k.authorize(CALL, now=1000.0 + i * 0.001)
        assert d.verdict == "ESCALATE"
    assert len(router.pending()) == 1


def test_escalations_survive_a_restart():
    """An in-memory queue loses a pending review on restart; a human-answerable
    request must outlive the worker that opened it."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "escalations.jsonl")
        router = EscalationRouter(store=FileEscalationStore(path), ttl_s=600)
        k = _kernel(router)
        d = k.authorize(CALL, now=1000.0)
        esc_id = d.escalation.id

        # A new process opens the same file.
        reloaded = EscalationRouter(store=FileEscalationStore(path), ttl_s=600)
        assert [e.id for e in reloaded.pending()] == [esc_id]
        with open(path, encoding="utf-8") as fh:
            assert json.loads(fh.readline())["state"] == PENDING


# ═══════════════════════════════════════════════════════════════
# 2. NOTIFICATION
# ═══════════════════════════════════════════════════════════════

def test_a_reviewer_is_notified_once_per_escalation():
    paged = []
    router = EscalationRouter(ttl_s=600, notifier=paged.append)
    k = _kernel(router)
    for _ in range(5):
        k.authorize(CALL, now=1000.0)
    assert len(paged) == 1, "notifier fired per retry instead of per review"
    assert paged[0].tool == "wire_transfer"


def test_a_broken_notifier_cannot_change_the_verdict():
    """A pager being down is not a reason to permit anything."""
    def explode(_esc):
        raise RuntimeError("pagerduty is down")

    router = EscalationRouter(ttl_s=600, notifier=explode)
    k = _kernel(router)
    d = k.authorize(CALL, now=1000.0)
    assert d.verdict == "ESCALATE"
    assert len(router.pending()) == 1, "the record was lost with the page"
    assert router.notify_failures and "pagerduty" in router.notify_failures[0][1]


# ═══════════════════════════════════════════════════════════════
# 3. TIMEOUT — the default fires when nobody answers
# ═══════════════════════════════════════════════════════════════

def test_timeout_with_no_response_blocks_by_default():
    router = EscalationRouter(ttl_s=600)
    k = _kernel(router)
    d = k.authorize(CALL, now=1000.0)
    esc_id = d.escalation.id

    assert router.outcome(esc_id, now=1000.0) == PENDING
    assert router.outcome(esc_id, now=1599.0) == PENDING     # still inside TTL
    assert router.outcome(esc_id, now=1601.0) == EXPIRED      # nobody answered

    esc = router.get(esc_id)
    assert esc.resolved_by == "timeout"
    assert "no reviewer response" in esc.resolution_reason
    assert router.pending(now=1601.0) == [], "an expired request is not pending"


def test_timeout_default_is_block_not_approve():
    """Stated explicitly: waiting must never be a way to obtain an action."""
    router = EscalationRouter(ttl_s=10)
    assert router.on_timeout == "block"
    k = _kernel(router)
    d = k.authorize(CALL, now=0.0)
    assert router.outcome(d.escalation.id, now=10_000.0) == EXPIRED
    # And the action itself is still refused afterwards.
    assert _kernel(router).authorize(CALL, now=10_000.0).verdict != "PERMIT"


def test_on_timeout_escalate_holds_the_request_open():
    """The one alternative offered: stay open for review, on the record."""
    router = EscalationRouter(ttl_s=10, on_timeout=TIMEOUT_ESCALATE)
    k = _kernel(router)
    d = k.authorize(CALL, now=0.0)
    assert router.outcome(d.escalation.id, now=10_000.0) == PENDING
    assert "held open" in router.get(d.escalation.id).resolution_reason


# ═══════════════════════════════════════════════════════════════
# 4. A VALID RESPONSE IN TIME — the action proceeds
# ═══════════════════════════════════════════════════════════════

def test_reviewer_approval_lets_the_original_action_proceed():
    """The whole loop: ESCALATE -> queued -> approved -> PERMIT -> executed."""
    router = EscalationRouter(ttl_s=600)
    k1 = _kernel(router)
    d1 = k1.authorize(CALL, now=1000.0)
    assert d1.verdict == "ESCALATE"

    ran = []
    # The lease is checked on the SAME clock the decision was issued against,
    # so a caller driving a model clock must pass it here too.
    ok, _out = k1.execute(d1, lambda a: ran.append(a), now=1000.0)
    assert ok is False and ran == [], "an unapproved action executed"

    # A reviewer works the queue and approves, in time.
    artifact = router.approve(d1.escalation.id, issuer=REVIEWER,
                              key=ORG_KEY, now=1100.0)
    assert router.get(d1.escalation.id).state == APPROVED
    assert router.get(d1.escalation.id).resolved_by == REVIEWER

    # The caller re-proposes with the artifact the reviewer minted.
    k2 = _kernel(router, approvals=(artifact,))
    d2 = k2.authorize(CALL, now=1100.0)
    assert d2.verdict == "PERMIT", d2.reason
    ok, _out = k2.execute(d2, lambda a: ran.append(a), now=1100.0)
    assert ok is True and len(ran) == 1


def test_reviewer_denial_keeps_the_action_refused():
    router = EscalationRouter(ttl_s=600)
    k = _kernel(router)
    d = k.authorize(CALL, now=1000.0)
    router.deny(d.escalation.id, issuer=REVIEWER, now=1050.0,
                reason="payee not on the approved list")
    esc = router.get(d.escalation.id)
    assert esc.state == DENIED and "payee" in esc.resolution_reason
    assert _kernel(router).authorize(CALL, now=1050.0).verdict != "PERMIT"


def test_a_late_approval_cannot_revive_an_expired_request():
    """Approving after the timeout resolved it must fail loudly.

    Otherwise the timeout is decorative: a reviewer answering a week late
    would still hand out the action, and the default would not be a default.
    """
    router = EscalationRouter(ttl_s=60)
    k = _kernel(router)
    d = k.authorize(CALL, now=1000.0)
    with pytest.raises(ValueError, match="expired"):
        router.approve(d.escalation.id, issuer=REVIEWER, key=ORG_KEY, now=9999.0)
    assert router.get(d.escalation.id).state == EXPIRED


def test_the_approval_is_the_ordinary_artifact_not_a_second_authority():
    """The router mints nothing the existing trust boundary would not verify."""
    router = EscalationRouter(ttl_s=600)
    k = _kernel(router)
    d = k.authorize(CALL, now=1000.0)
    artifact = router.approve(d.escalation.id, issuer=REVIEWER,
                              key=ORG_KEY, now=1010.0)

    # Wrong signing key -> refused, exactly as any forged artifact is.
    forged = router  # same router, different key
    router2 = EscalationRouter(ttl_s=600)
    k2 = _kernel(router2)
    d2 = k2.authorize(CALL, now=2000.0)
    bad = router2.approve(d2.escalation.id, issuer=REVIEWER,
                          key=b"not-the-org-key", now=2010.0)
    assert _kernel(router, approvals=(bad,)).authorize(
        CALL, now=2010.0).verdict != "PERMIT"

    # Untrusted issuer -> refused.
    router3 = EscalationRouter(ttl_s=600)
    k3 = _kernel(router3)
    d3 = k3.authorize(CALL, now=3000.0)
    untrusted = router3.approve(d3.escalation.id, issuer="the-agent-itself",
                                key=ORG_KEY, now=3010.0)
    assert _kernel(router, approvals=(untrusted,)).authorize(
        CALL, now=3010.0).verdict != "PERMIT"

    # The genuine one works.
    assert _kernel(router, approvals=(artifact,)).authorize(
        CALL, now=1010.0).verdict == "PERMIT"


# ═══════════════════════════════════════════════════════════════
# 5. WITHOUT A ROUTER — unchanged, still fail-closed
# ═══════════════════════════════════════════════════════════════

def test_a_kernel_without_a_router_behaves_exactly_as_before():
    """Routing is opt-in. A deployment that has not configured it gets the
    same fail-closed refusal it got before, with no new failure mode."""
    _SEQ[0] += 1
    gov = GovernanceLayer(domains=[OmegaDomain.FINANCE], log_all=False)
    ctx = SecurityContext(
        principal=Principal(id=f"noroute-{_SEQ[0]}", tenant="corp"),
        signing_key=ORG_KEY, trusted_issuers=frozenset({REVIEWER}),
        tool_manifest={"wire_transfer": ["payment.move_funds"]})
    k = GovernanceKernel(gov, ctx, session_id=f"noroute-{_SEQ[0]}")
    d = k.authorize(CALL, now=1000.0)
    assert d.verdict == "ESCALATE"
    assert d.escalation is None
    ran = []
    ok, _ = k.execute(d, lambda a: ran.append(a))
    assert ok is False and ran == []
