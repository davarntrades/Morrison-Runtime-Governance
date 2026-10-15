"""Regression tests for defects found by the adversarial falsification run
(runtime_eval/results/ADVERSARIAL_LOCAL_GLOBAL_FALSIFICATION.md, E5, E7, E10,
E11). Each test reproduces the pre-repair counterexample and asserts the
repaired outcome."""

import secrets
import threading

from morrison_governance import GovernanceLayer
from morrison_governance.domains import OmegaDomain
from morrison_governance.kernel import GovernanceKernel, issue_approval
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.trust import Principal, SecurityContext

DOMAINS = [OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY, OmegaDomain.DATA_PRIVACY,
           OmegaDomain.ENTERPRISE, OmegaDomain.COMPLIANCE]
ISSUER = "approval-service"
PAY = {"tool": "transfer", "args": {"from": "OPS", "to": "VENDOR-1", "amount": 5000}}


def _kernel(key, principal="agent-a", store=None, approvals=()):
    ctx = SecurityContext(
        principal=Principal(id=principal, tenant="acme"),
        continuity_store=store if store is not None else InMemoryContinuityStore(),
        tool_manifest={"transfer": ["payment.move_funds"]},
        signing_key=key, trusted_issuers=frozenset({ISSUER}),
        approvals=tuple(approvals))
    return GovernanceKernel(GovernanceLayer(domains=DOMAINS, log_all=False), ctx)


def _effects(kernel, call, n):
    done = []
    for _ in range(n):
        d = kernel.authorize(call)
        if d.permitted:
            ok, _ = kernel.execute(d, lambda a: done.append(a))
    return len(done)


def test_approval_without_nonce_authorises_one_effect():
    key = secrets.token_bytes(32)
    art = issue_approval(PAY, ISSUER, key, nonce="")
    assert _effects(_kernel(key, approvals=(art,)), PAY, 3) == 1


def test_one_approval_cannot_be_spent_by_a_second_principal():
    key, store = secrets.token_bytes(32), InMemoryContinuityStore()
    art = issue_approval(PAY, ISSUER, key, nonce=secrets.token_hex(8))
    total = sum(_effects(_kernel(key, who, store, (art,)), PAY, 1)
                for who in ("agent-a", "agent-b", "agent-c"))
    assert total == 1


def test_simultaneous_cross_principal_presentation_yields_one_permit():
    key, store = secrets.token_bytes(32), InMemoryContinuityStore()
    art = issue_approval(PAY, ISSUER, key, nonce=secrets.token_hex(8))
    kernels = [_kernel(key, f"agent-{i}", store, (art,)) for i in range(8)]
    barrier, verdicts = threading.Barrier(len(kernels)), []

    def go(k):
        barrier.wait()
        verdicts.append(k.authorize(PAY).verdict)

    threads = [threading.Thread(target=go, args=(k,)) for k in kernels]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert verdicts.count("PERMIT") == 1


def test_evidence_failure_after_commit_is_not_reported_as_refusal():
    key = secrets.token_bytes(32)
    k = _kernel(key, approvals=(issue_approval(PAY, ISSUER, key, nonce="n1"),))
    d = k.authorize(PAY)
    assert d.permitted

    def broken(*a, **kw):
        raise RuntimeError("evidence store unavailable")

    k.chain.record_execution = broken
    effects = []
    ok, _ = k.execute(d, lambda a: effects.append(a))
    assert effects and ok is True
    assert k.evidence_failures and k.evidence_failures[0]["decision_id"] == d.decision_id


def test_resolved_escalation_does_not_harden_the_next_payment_into_block():
    key = secrets.token_bytes(32)
    k = _kernel(key)
    first = {"tool": "transfer", "args": {"from": "OPS", "to": "V-1", "amount": 1000}}
    assert k.authorize(first).verdict == "ESCALATE"            # workflow: escalate,
    k.ctx.approvals = (issue_approval(first, ISSUER, key, nonce="a1"),)
    d = k.authorize(first)                                    # then approve,
    assert d.permitted and k.execute(d, lambda a: None)[0]    # then execute
    k.ctx.approvals = ()
    second = {"tool": "transfer", "args": {"from": "OPS", "to": "V-2", "amount": 1000}}
    assert k.preview(second).verdict == "ESCALATE"


def test_approval_binds_to_a_whole_number_float_argument():
    """E13: issue_approval hashed the raw call while the kernel hashes the
    canonicalised one, so `amount: 1200.0` never matched `1200`."""
    key = secrets.token_bytes(32)
    call = {"tool": "transfer", "args": {"from": "OPS", "to": "VENDOR-1", "amount": 1200.0}}
    k = _kernel(key, approvals=(issue_approval(call, ISSUER, key, nonce="f1"),))
    assert _effects(k, call, 1) == 1
