"""Numeric rule inputs: no TypeError, no silent bypass, attributable refusals.

Found by the Independent Agent Exposure Audit (scenario L4): an amount sent as
the string "15000" made `excessive_amount` raise TypeError, so the kernel
refused the payment by fail-closed error handling rather than by a rule. The
same comparison pattern was in `structuring_pattern`, `velocity_anomaly` and
`synthetic_identity`. A wider probe also found silent passes: NaN compares
False with everything and True compares as 1, and the kernel's payment
auto-approval accepted a negative amount (every negative number is below the
cap) and a boolean.
"""

from decimal import Decimal

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import GovernanceKernel
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.trust import Principal, SecurityContext
from morrison_governance.numeric import parse_number

MALFORMED = ["abc", "", "5,000", "1e3", "nan", "inf", None, True, False,
             float("nan"), float("inf"), float("-inf"), [5], {"v": 5}]


def _eval(domains, tool, args, facts=None):
    # trusted_facts is evaluate()'s second parameter. It is passed positionally
    # because pylint confuses this evaluate() with other evaluate(tool_call)
    # methods in the repository and reports a false E1123 for the keyword.
    r = GovernanceLayer(domains=domains, log_all=False).evaluate({"tool": tool, "args": args}, facts)
    return r.verdict.value, (r.metadata or {}).get("rule")


# ── the parser ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("value,expected", [
    (5000, 5000.0), (9500.5, 9500.5), (Decimal("12.5"), 12.5), ("5000", 5000.0),
    ("  9500 ", 9500.0), ("+5", 5.0), ("-5", -5.0), (".5", 0.5), ("0", 0.0)])
def test_well_formed_numbers_parse(value, expected):
    assert parse_number(value) == (expected, False)


@pytest.mark.parametrize("value", MALFORMED)
def test_malformed_values_are_never_read_as_numbers(value):
    assert parse_number(value) == (None, True)


# ── the original reproduction ──────────────────────────────────────────────
def test_string_amount_no_longer_raises_and_matches_the_number():
    as_string = _eval([OmegaDomain.FINANCE], "transfer", {"amount": "15000"}, {"authorized": True})
    as_number = _eval([OmegaDomain.FINANCE], "transfer", {"amount": 15000}, {"authorized": True})
    assert as_string == as_number


# ── malformed inputs: an explicit, named refusal for every rule ────────────
@pytest.mark.parametrize("value", MALFORMED)
def test_excessive_amount_input_refused_by_malformed_amount(value):
    assert _eval([OmegaDomain.FINANCE], "transfer", {"amount": value, "threshold": 100_000},
                 {"authorized": True}) == ("BLOCK", "malformed_amount")


@pytest.mark.parametrize("value", MALFORMED)
def test_malformed_threshold_is_refused(value):
    assert _eval([OmegaDomain.FINANCE], "transfer", {"amount": 5, "threshold": value},
                 {"authorized": True}) == ("BLOCK", "malformed_amount")


@pytest.mark.parametrize("field,tool", [("amount", "withdraw"), ("transactions_last_hour", "transfer"),
                                        ("identity_score", "create_account")])
@pytest.mark.parametrize("value", MALFORMED)
def test_fraud_signals_refused_by_malformed_fraud_signal(field, tool, value):
    args = {field: value} if field != "transactions_last_hour" else {"amount": 10, field: value}
    assert _eval([OmegaDomain.FRAUD], tool, args, {"authorized": True}) == ("BLOCK", "malformed_fraud_signal")


# ── well-formed strings are judged exactly like numbers ────────────────────
@pytest.mark.parametrize("domain,tool,field,value,rule", [
    (OmegaDomain.FINANCE, "transfer", "amount", "5000000", "excessive_amount"),
    (OmegaDomain.FRAUD, "withdraw", "amount", " 9500 ", "structuring_pattern"),
    (OmegaDomain.FRAUD, "transfer", "transactions_last_hour", "11", "velocity_anomaly"),
    (OmegaDomain.FRAUD, "create_account", "identity_score", "0.4", "synthetic_identity"),
])
def test_numeric_strings_trigger_the_same_rule_as_numbers(domain, tool, field, value, rule):
    args = {field: value}
    if domain is OmegaDomain.FINANCE:
        args["threshold"] = 100_000
    if field == "transactions_last_hour":
        args["amount"] = 10
    assert _eval([domain], tool, args, {"authorized": True}) == ("BLOCK", rule)


def test_values_inside_the_limits_still_pass():
    assert _eval([OmegaDomain.FINANCE], "transfer", {"amount": "9500", "threshold": 100_000},
                 {"authorized": True})[0] == "PERMIT"
    assert _eval([OmegaDomain.FRAUD], "withdraw", {"amount": "8999"}, {"authorized": True})[0] == "PERMIT"


# ── negative amounts: magnitude, not sign ──────────────────────────────────
def test_negative_payment_amount_is_refused():
    assert _eval([OmegaDomain.FINANCE], "transfer", {"amount": -5_000_000, "threshold": 100_000},
                 {"authorized": True})[0] == "BLOCK"
    assert _eval([OmegaDomain.FRAUD], "withdraw", {"amount": -9500}, {"authorized": True}) == \
        ("BLOCK", "malformed_fraud_signal")


def test_excessive_amount_compares_magnitude():
    # a non-payment tool carrying a threshold: magnitude decides, not sign
    assert _eval([OmegaDomain.FINANCE], "adjust_ledger", {"amount": -500_000, "threshold": 100_000},
                 {"authorized": True}) == ("BLOCK", "excessive_amount")


# ── no false positives where no number is compared ─────────────────────────
def test_absent_or_irrelevant_fields_do_not_trigger_malformed_rules():
    assert _eval([OmegaDomain.FINANCE], "read_file", {"path": "/data/report.csv"})[0] == "PERMIT"
    # free-text "amount" on a non-payment tool with no threshold is not compared
    assert _eval([OmegaDomain.FINANCE], "set_volume", {"amount": "loud"})[0] == "PERMIT"
    assert _eval([OmegaDomain.FRAUD], "transfer", {"amount": 10}, {"authorized": True})[0] == "PERMIT"
    assert _eval([OmegaDomain.FRAUD], "create_account", {"name": "x"})[0] == "PERMIT"


# ── kernel: payment auto-approval needs a well-formed positive amount ──────
def _kernel():
    ctx = SecurityContext(principal=Principal(id="agent", tenant="t"),
                          continuity_store=InMemoryContinuityStore(),
                          tool_manifest={"transfer": ["payment.move_funds"]},
                          policy_values={"payment_auto_approve_max": 10_000})
    return GovernanceKernel(GovernanceLayer(domains=[OmegaDomain.FINANCE], log_all=False), ctx)


@pytest.mark.parametrize("amount", [5_000, "5000", " 5000 "])
def test_kernel_auto_approves_well_formed_amounts_under_the_cap(amount):
    assert _kernel().authorize({"tool": "transfer", "args": {"amount": amount, "to": "acct-2"}}).verdict == "PERMIT"


@pytest.mark.parametrize("amount", [-5_000_000, "-5000000", True, 0, float("nan"), "abc", None, "1e3"])
def test_kernel_never_auto_approves_unreadable_or_non_positive_amounts(amount):
    d = _kernel().authorize({"tool": "transfer", "args": {"amount": amount, "to": "acct-2"}})
    assert d.verdict != "PERMIT"
    assert d.layer != "fail_closed"          # decided by policy, not by an exception


def test_kernel_does_not_fall_through_from_a_malformed_amount_to_another_key():
    d = _kernel().authorize({"tool": "transfer", "args": {"amount": "abc", "value": 5, "to": "acct-2"}})
    assert d.verdict != "PERMIT"


def test_kernel_attributes_malformed_amounts_to_the_named_rule():
    d = _kernel().authorize({"tool": "transfer", "args": {"amount": float("nan"), "to": "acct-2"}})
    assert (d.verdict, d.rule) == ("BLOCK", "malformed_amount")
