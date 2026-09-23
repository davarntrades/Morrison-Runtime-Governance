"""Frozen instrument controls for the independent Work V2 experiment."""

import json

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    BLOCK, PERMIT, GovernanceKernel, Principal, SecurityContext,
    canonicalize, issue_approval, reset_default_store,
)
from morrison_governance.kernel import capabilities as C


KEY = b"independent-work-v2-instrument-key"
ISSUERS = frozenset({"security-review"})
DANGEROUS = {"tool": "delete_bucket", "args": {"bucket": "protected"}}
LEGITIMATE = {"tool": "read_file", "args": {"path": "/docs/public.txt"}}
MANIFEST = {
    "delete_bucket": [C.CAP_INFRA_DESTRUCTIVE],
    "read_file": [C.CAP_DATA_READ],
}


@pytest.fixture(autouse=True)
def _isolated_continuity():
    reset_default_store()
    yield
    reset_default_store()


def _kernel(*, approvals=(), session="instrument"):
    layer = GovernanceLayer(
        domains=[d for d in OmegaDomain if d != OmegaDomain.CUSTOM],
        horizon=3,
        log_all=False,
    )
    context = SecurityContext(
        principal=Principal(id="instrument-agent", tenant="instrument-tenant"),
        approvals=approvals,
        signing_key=KEY,
        trusted_issuers=ISSUERS,
        tool_manifest=MANIFEST,
        unknown_tool_policy="escalate",
    )
    return GovernanceKernel(layer, context, session_id=session)


class StatefulRuntime:
    def __init__(self, *, raise_after_effect=False):
        self.prohibited = False
        self.handler_entries = 0
        self.raise_after_effect = raise_after_effect

    def __call__(self, call):
        self.handler_entries += 1
        if call["tool"] == "delete_bucket":
            self.prohibited = True
        if self.raise_after_effect:
            raise RuntimeError("synthetic failure after effect")
        return {"ok": True}


def _enforcement_failure(before, runtime):
    return before is False and runtime.handler_entries > 0 and runtime.prohibited


def test_control_a_direct_bypass_reaches_prohibited_state():
    runtime = StatefulRuntime()
    before = runtime.prohibited
    runtime(DANGEROUS)
    assert _enforcement_failure(before, runtime)


def test_control_b_block_never_enters_protected_handler():
    runtime = StatefulRuntime()
    decision, executed, _ = _kernel().submit(DANGEROUS, runtime)
    assert decision.verdict != PERMIT
    assert executed is False
    assert runtime.handler_entries == 0
    assert runtime.prohibited is False


def test_controls_c_and_d_legitimate_permit_changes_expected_state():
    runtime = StatefulRuntime()
    decision, executed, _ = _kernel().submit(LEGITIMATE, runtime)
    assert decision.verdict == PERMIT
    assert executed is True
    assert runtime.handler_entries == 1
    assert runtime.prohibited is False


def test_control_e_deliberately_vulnerable_dispatch_is_detected():
    runtime = StatefulRuntime()
    decision = _kernel().authorize(DANGEROUS)
    assert decision.verdict in (BLOCK, "ESCALATE")
    before = runtime.prohibited
    runtime(DANGEROUS)  # deliberate mutant: dispatch despite non-PERMIT
    assert _enforcement_failure(before, runtime)


def test_control_f_dangerous_action_survives_parser_and_canonicalisation():
    wire = {
        "tool": "delete_bucket",
        "arguments": json.dumps({"bucket": "protected"}),
    }
    parsed = canonicalize(wire)
    assert parsed == DANGEROUS
    decision = _kernel().authorize(wire)
    assert decision.verdict != PERMIT
    assert C.CAP_INFRA_DESTRUCTIVE in decision.capabilities


def test_control_g_effect_then_raise_is_recorded_as_effect_possible():
    approval = issue_approval(
        DANGEROUS,
        issuer="security-review",
        key=KEY,
        nonce="instrument-effect-then-raise-0001",
    )
    runtime = StatefulRuntime(raise_after_effect=True)
    kernel = _kernel(approvals=(approval,))
    decision, executed, outcome = kernel.submit(DANGEROUS, runtime)
    assert decision.verdict == PERMIT
    assert executed is False
    assert "runtime error" in outcome
    assert runtime.handler_entries == 1
    assert runtime.prohibited is True
    execution_record = kernel.chain.records[-1]
    assert execution_record.layer == "execution"
    assert execution_record.executed is True
    assert "outcome UNKNOWN" in execution_record.execution_result
