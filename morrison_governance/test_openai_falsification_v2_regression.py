"""Security regression suite for the independent Work V2 remediation."""

from dataclasses import replace
import threading

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    ESCALATE, PERMIT, ApprovalArtifact, GovernanceKernel, Principal,
    SecurityContext, authorization_action_hash, issue_approval,
    reset_default_store,
)
from morrison_governance.kernel import capabilities as C


KEY = b"independent-work-v2-regression-key"
ISSUER = "security-review"
NOW = 1_700_000_000.0
DANGEROUS = {"tool": "delete_bucket", "args": {"bucket": "protected"}}
SAFE = {"tool": "read_file", "args": {"path": "/docs/public.txt"}}
SHELL = {"tool": "shell", "args": {"code": "disable_guard()"}}
PYTHON = {"tool": "python", "args": {"code": "disable_guard()"}}
MANIFEST = {
    "delete_bucket": [C.CAP_INFRA_DESTRUCTIVE],
    "read_file": [C.CAP_DATA_READ],
    "shell": [C.CAP_CODE_EXEC],
    "python": [C.CAP_CODE_EXEC],
    "vendor.shell.v2": [C.CAP_CODE_EXEC],
    "shell_backup": [C.CAP_CODE_EXEC],
}


@pytest.fixture(autouse=True)
def _isolated_continuity():
    reset_default_store()
    yield
    reset_default_store()


def _layer():
    return GovernanceLayer(
        domains=[d for d in OmegaDomain if d != OmegaDomain.CUSTOM],
        horizon=3,
        log_all=False,
    )


def _ctx(principal="principal-a", tenant="tenant-a", approvals=(),
         equivalences=None):
    return SecurityContext(
        principal=Principal(id=principal, tenant=tenant),
        approvals=approvals,
        signing_key=KEY,
        trusted_issuers=frozenset({ISSUER}),
        tool_manifest=MANIFEST,
        unknown_tool_policy="escalate",
        authorization_equivalences=equivalences or {},
    )


def _kernel(principal="principal-a", tenant="tenant-a", approvals=(),
            equivalences=None, session="v2-regression"):
    return GovernanceKernel(
        _layer(), _ctx(principal, tenant, approvals, equivalences),
        session_id=session,
    )


def _approval(call=DANGEROUS, *, principal="principal-a", tenant="tenant-a",
              nonce="valid-regression-nonce-00000001", issued_at=NOW,
              equivalences=None):
    return issue_approval(
        call, ISSUER, KEY, nonce=nonce, now=issued_at,
        principal=principal, tenant=tenant,
        authorization_equivalences=equivalences,
    )


class Runtime:
    def __init__(self):
        self.entries = 0
        self.effects = []

    def __call__(self, call):
        self.entries += 1
        self.effects.append(call)
        return {"ok": True}


def _assert_not_executed(kernel, decision, runtime, *, now=NOW):
    ok, _ = kernel.execute(decision, runtime, now=now)
    assert ok is False
    assert runtime.entries == 0
    assert runtime.effects == []


def test_exact_cross_principal_approval_reuse_is_closed():
    art = _approval(principal="principal-a")
    k = _kernel(principal="principal-b", approvals=(art,))
    d = k.authorize(DANGEROUS, now=NOW)
    assert d.verdict == ESCALATE
    assert "principal" in d.authorization["reason"]


def test_exact_cross_tenant_approval_reuse_is_closed():
    art = _approval(tenant="tenant-a")
    k = _kernel(tenant="tenant-b", approvals=(art,))
    d = k.authorize(DANGEROUS, now=NOW)
    assert d.verdict == ESCALATE
    assert "tenant" in d.authorization["reason"]


@pytest.mark.parametrize("offset", [0.001, 1.0, 60.0, 3600.0])
def test_future_issued_approval_is_closed_at_multiple_offsets(offset):
    art = _approval(issued_at=NOW + offset)
    d = _kernel(approvals=(art,)).authorize(DANGEROUS, now=NOW)
    assert d.verdict == ESCALATE
    assert "future" in d.authorization["reason"]


def test_issued_at_exact_boundary_is_valid():
    art = _approval(issued_at=NOW)
    d = _kernel(approvals=(art,)).authorize(DANGEROUS, now=NOW)
    assert d.verdict == PERMIT


def test_signed_timestamp_mutation_is_rejected():
    art = replace(_approval(), issued_at=NOW + 0.001)
    d = _kernel(approvals=(art,)).authorize(DANGEROUS, now=NOW)
    assert d.verdict == ESCALATE
    assert "signature invalid" in d.authorization["reason"]


def test_non_equivalent_broad_family_alias_is_closed():
    art = _approval(SHELL)
    d = _kernel(approvals=(art,)).authorize(PYTHON, now=NOW)
    assert d.verdict == ESCALATE
    assert "different action" in d.authorization["reason"]
    assert d.tool_family == "shell"


def test_explicit_trusted_authorization_equivalence_is_positive_control():
    registry = {"approved-code-runner": ("shell", "python")}
    art = _approval(SHELL, equivalences=registry)
    k = _kernel(approvals=(art,), equivalences=registry)
    runtime = Runtime()
    d = k.authorize(PYTHON, now=NOW)
    assert d.verdict == PERMIT
    assert k.execute(d, runtime, now=NOW)[0] is True
    assert runtime.entries == 1


@pytest.mark.parametrize("tool", ["vendor.shell.v2", "shell_backup"])
def test_qualified_and_substring_names_do_not_inherit_shell_authority(tool):
    art = _approval(SHELL)
    target = {"tool": tool, "args": SHELL["args"]}
    d = _kernel(approvals=(art,)).authorize(target, now=NOW)
    assert d.verdict == ESCALATE
    assert d.authorization["approved"] is False


def test_changed_tenant_decision_redemption_is_closed():
    issued = _kernel(tenant="tenant-a", session="shared-session")
    d = issued.authorize(SAFE, now=NOW)
    runtime = Runtime()
    redeemer = _kernel(tenant="tenant-b", session="shared-session")
    _assert_not_executed(redeemer, d, runtime)


@pytest.mark.parametrize(
    "principal,tenant",
    [("principal-b", "tenant-a"), ("principal-a", "tenant-b"),
     ("principal-b", "tenant-b")],
)
def test_decision_context_variants_fail_closed(principal, tenant):
    issued = _kernel(session="shared-context-session")
    d = issued.authorize(SAFE, now=NOW)
    runtime = Runtime()
    redeemer = _kernel(principal, tenant, session="shared-context-session")
    _assert_not_executed(redeemer, d, runtime)


def test_session_mutation_redemption_is_closed():
    issued = _kernel(session="session-a")
    d = issued.authorize(SAFE, now=NOW)
    runtime = Runtime()
    _assert_not_executed(_kernel(session="session-b"), d, runtime)


@pytest.mark.parametrize("nonce", ["", "short", "contains spaces !!!"])
def test_trusted_issuance_rejects_empty_short_or_malformed_nonce(nonce):
    with pytest.raises(ValueError, match="nonce"):
        _approval(nonce=nonce)


@pytest.mark.parametrize("nonce", ["", "short", "contains spaces !!!"])
def test_verification_rejects_direct_malformed_artifacts(nonce):
    art = ApprovalArtifact(
        action_hash=authorization_action_hash(DANGEROUS),
        issuer=ISSUER,
        principal="principal-a",
        tenant="tenant-a",
        issued_at=NOW,
        expires_at=NOW + 300,
        nonce=nonce,
    ).sign(KEY)
    d = _kernel(approvals=(art,)).authorize(DANGEROUS, now=NOW)
    assert d.verdict == ESCALATE
    assert "nonce" in d.authorization["reason"]


def test_trusted_issuance_generates_strong_nonce_when_omitted():
    art = issue_approval(
        DANGEROUS, ISSUER, KEY, now=NOW,
        principal="principal-a", tenant="tenant-a",
    )
    assert len(art.nonce) >= 22
    assert art.nonce


def test_approval_replay_is_closed():
    art = _approval()
    k = _kernel(approvals=(art,))
    first = k.authorize(DANGEROUS, now=NOW)
    second = k.authorize(DANGEROUS, now=NOW + 1)
    assert first.verdict == PERMIT
    assert second.verdict == ESCALATE
    assert "replay" in second.authorization["reason"]


def test_concurrent_approval_replay_has_exactly_one_permit():
    art = _approval()
    k = _kernel(approvals=(art,))
    decisions = []
    barrier = threading.Barrier(3)

    def authorize():
        barrier.wait()
        decisions.append(k.authorize(DANGEROUS, now=NOW))

    threads = [threading.Thread(target=authorize) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert [d.verdict for d in decisions].count(PERMIT) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("principal_id", "principal-b"),
        ("tenant_id", "tenant-b"),
        ("session_id", "session-b"),
        ("action_hash", "0" * 64),
        ("semantic_hash", "1" * 64),
        ("authorization_hash", "2" * 64),
        ("ruleset_hash", "3" * 64),
    ],
)
def test_decision_field_mutation_is_detected(field, value):
    k = _kernel(session="session-a")
    d = k.authorize(SAFE, now=NOW)
    setattr(d, field, value)
    _assert_not_executed(k, d, Runtime())


def test_authorization_equivalence_policy_change_invalidates_decision():
    registry = {"approved-code-runner": ("shell", "python")}
    k = _kernel(equivalences=registry)
    d = k.authorize(SAFE, now=NOW)
    assert d.verdict == PERMIT
    k.ctx.authorization_equivalences = {}
    _assert_not_executed(k, d, Runtime())


def test_post_authorization_action_and_argument_mutation_is_closed():
    k = _kernel()
    d = k.authorize(SAFE, now=NOW)
    mutated = {"tool": "read_file", "args": {"path": "/secrets.txt"}}
    runtime = Runtime()
    ok, reason = k.execute(d, runtime, call=mutated, now=NOW)
    assert ok is False
    assert "mutated" in reason
    assert runtime.entries == 0


def test_legitimate_positive_control_executes():
    k = _kernel()
    runtime = Runtime()
    d = k.authorize(SAFE, now=NOW)
    assert d.verdict == PERMIT
    assert k.execute(d, runtime, now=NOW)[0] is True
    assert runtime.effects == [SAFE]
