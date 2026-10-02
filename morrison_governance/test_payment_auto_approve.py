"""Payment auto-approval only applies to amounts the threshold can price.

`payment_auto_approve_max` is a bare number. Stress testing found it
auto-approved `amount: -500000` (which is <= 1000) and `amount: 999,
currency: BTC` (999 of a unit the threshold never priced).
"""
import uuid

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import GovernanceKernel, Principal, SecurityContext
from morrison_governance.kernel import capabilities as C


def _decide(args, **policy):
    ctx = SecurityContext(
        principal=Principal(id="pay-" + uuid.uuid4().hex[:8], tenant="acme"),
        tool_manifest={"send_payment": [C.CAP_PAYMENT]},
        policy_values={"payment_auto_approve_max": 1000, **policy})
    layer = GovernanceLayer(domains=[OmegaDomain.FRAUD], log_all=False)
    return GovernanceKernel(layer, ctx, session_id=uuid.uuid4().hex).authorize(
        {"tool": "send_payment", "args": {"to_account": "acct-1", **args}})


@pytest.mark.parametrize("args", [
    {"amount": 500},
    {"amount": 500, "currency": "USD"},
    {"amount": 500, "currency": "usd"},
])
def test_small_default_currency_payment_auto_approves(args):
    assert _decide(args).verdict == "PERMIT"


@pytest.mark.parametrize("args", [
    {"amount": -500000},
    {"amount": 0},
    {"amount": "nan"},
    {"amount": "-inf"},
    {"amount": 999, "currency": "BTC"},
    {"amount": 999, "ccy": "JPY"},
    {"amount": 999, "currency": "USD", "asset": "ETH"},
])
def test_unpriceable_amount_keeps_approval_requirement(args):
    d = _decide(args)
    assert d.verdict != "PERMIT", d.reason
    assert d.requirement == "approval"


def test_configured_currency_is_honoured():
    assert _decide({"amount": 500, "currency": "GBP"},
                   payment_auto_approve_currency="GBP").verdict == "PERMIT"
    assert _decide({"amount": 500, "currency": "USD"},
                   payment_auto_approve_currency="GBP").verdict != "PERMIT"
