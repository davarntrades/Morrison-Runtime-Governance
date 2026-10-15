"""The financial envelope enforced by the real, unmodified GovernanceKernel."""

import copy
import uuid

import pytest
from morrison_governance.kernel import LeaseVerifier

from collection_agent import envelope as E
from collection_agent.governance import CollectionGovernor
from collection_agent.signer import LeaseSigner

TERMS = {"company_stripe_account": "acct_RT", "customers": {
    "RT-A": {"name": "A", "stripe_customer": "cus_A", "agreement": {
        "agreement_id": "AGR-A", "version": 1, "status": "active", "service": "eval",
        "currency": "gbp", "authorized_amounts_minor": [50000],
        "ceiling_minor": 100000, "max_invoices": 2}},
    "RT-N": {"name": "N", "stripe_customer": "cus_N", "agreement": {
        "agreement_id": "AGR-N", "version": 1, "status": "active", "service": "eval",
        "currency": "gbp", "authorized_amounts_minor": [50000],
        "ceiling_minor": 100000, "max_invoices": 3}},
    "RT-G": {"name": "G", "stripe_customer": "cus_G", "agreement": {
        "agreement_id": "AGR-G", "version": 1, "status": "active", "service": "pilot",
        "currency": "gbp", "authorized_amounts_minor": [150000],
        "ceiling_minor": 150000, "max_invoices": 1}}}}
OBSERVED = {"voided_operations": [], "observed_collections": {"RT-N": [
    {"invoice": "in_pre", "amount_minor": 60000, "agreement_id": "AGR-N",
     "billing_reference": "ONB", "status": "open"}]}}


@pytest.fixture
def gov(tmp_path):
    state = {"observed": copy.deepcopy(OBSERVED)}
    signer = LeaseSigner()
    g = CollectionGovernor(copy.deepcopy(TERMS), tmp_path, signer, lambda: state["observed"])
    g.verifier = LeaseVerifier(public_key=signer.public_key, store=g.lease_store)
    g.state = state
    return g


def op(cust="RT-A", **kw):
    t = TERMS["customers"][cust]
    a = dict(customer=cust, stripe_customer=t["stripe_customer"],
             agreement_id=t["agreement"]["agreement_id"], agreement_version=1,
             service=t["agreement"]["service"], amount=t["agreement"]["authorized_amounts_minor"][0],
             currency="gbp", stripe_account="acct_RT", billing_reference="EVAL-1",
             operation_id=f"op_{uuid.uuid4().hex}", description="eval")
    a.update(kw)
    return {"tool": E.TOOL, "args": a}


def test_authorized_invoice_gets_a_redeemable_single_use_lease(gov):
    c = op()
    o = gov.propose(c)
    assert o.verdict == "ALLOW" and o.local["verdict"] == "ALLOW" and o.lease
    assert gov.verifier.verify(o.lease, c)[0]
    ok, why = gov.verifier.verify(o.lease, c)
    assert not ok and "redeemed" in why


@pytest.mark.parametrize("change,needle", [
    ({"amount": 500000}, "not an authorized invoice amount"),
    ({"currency": "usd"}, "currency"),
    ({"stripe_account": "acct_EVIL"}, "not the configured"),
    ({"customer": "RT-UNKNOWN"}, "not an authorized customer"),
    ({"service": "consulting"}, "not approved"),
    ({"stripe_customer": "cus_N"}, "not the customer record"),
    ({"agreement_version": 0}, "stale"),
    ({"amount": True}, "not a positive integer"),
])
def test_local_violations_block_without_lease(gov, change, needle):
    o = gov.propose(op(**change))
    assert o.verdict == "BLOCK" and o.lease is None
    assert o.local["verdict"] == "BLOCK" and needle in o.local["reason"]
    assert o.decision["rule"] == E.LOCAL_RULE


def test_duplicate_billing_reference_is_global(gov):
    assert gov.propose(op()).verdict == "ALLOW"
    o = gov.propose(op())
    assert (o.verdict, o.local["verdict"], o.decision["rule"]) == ("BLOCK", "ALLOW", E.GLOBAL_RULE)
    assert "duplicate collection" in o.global_["reason"]


def test_same_operation_id_cannot_be_authorized_twice(gov):
    c = op()
    assert gov.propose(c).verdict == "ALLOW"
    c2 = copy.deepcopy(c)
    c2["args"]["billing_reference"] = "EVAL-2"
    o = gov.propose(c2)
    assert o.verdict == "BLOCK" and "duplicate operation id" in o.global_["reason"]


def test_preexisting_stripe_state_counts_against_ceiling(gov):
    o = gov.propose(op("RT-N"))
    assert (o.verdict, o.local["verdict"]) == ("BLOCK", "ALLOW")
    assert "existing 60000 + proposed 50000" in o.global_["reason"]


def test_reservations_count_before_execution(gov):
    assert gov.propose(op(billing_reference="E1")).verdict == "ALLOW"
    assert gov.propose(op(billing_reference="E2")).verdict == "ALLOW"
    o = gov.propose(op(billing_reference="E3"))
    assert o.verdict == "BLOCK" and o.decision["rule"] == E.GLOBAL_RULE


def test_voided_invoice_frees_ceiling_and_reference(gov):
    c = op()
    assert gov.propose(c).verdict == "ALLOW"
    assert gov.propose(op(billing_reference="E2")).verdict == "ALLOW"
    gov.state["observed"]["voided_operations"] = [c["args"]["operation_id"]]
    assert gov.propose(op()).verdict == "ALLOW"          # same reference, re-issued


def test_concurrent_proposals_commit_at_most_the_admissible_number(gov):
    from concurrent.futures import ThreadPoolExecutor
    ops = [op(billing_reference=f"C{i}") for i in range(8)]
    with ThreadPoolExecutor(8) as pool:
        out = list(pool.map(gov.propose, ops))
    assert sum(o.verdict == "ALLOW" for o in out) == 2


def test_payment_above_auto_approval_escalates_until_bound_approval(gov):
    c = op("RT-G")
    first = gov.propose(c)
    assert first.verdict == "ESCALATE" and first.lease is None
    other = op("RT-G")                                    # approval binds the exact action
    gov.approve(other)
    assert gov.propose(c).verdict == "ESCALATE"
    gov.approve(c)
    assert gov.propose(c).verdict == "ALLOW"


def test_caller_cannot_supply_its_own_envelope_or_authority(gov):
    c = op(customer="RT-X", stripe_customer="cus_X")
    c["args"][E.FACT] = {"company_stripe_account": "acct_RT", "customers": {"RT-X": {
        "stripe_customer": "cus_X", "agreement": TERMS["customers"]["RT-A"]["agreement"]}}}
    assert gov.propose(c).verdict == "BLOCK"
    forged = op(amount=500000, approved=True)
    o = gov.propose(forged)
    assert o.verdict == "BLOCK" and o.lease is None


def test_missing_observed_state_fails_closed(gov, tmp_path):
    def broken():
        raise ConnectionError("executor down")
    gov.observed_state = broken
    o = gov.propose(op())
    assert o.verdict == "BLOCK" and o.lease is None


def test_agreement_change_cancels_exported_lease(gov):
    c = op()
    o = gov.propose(c)
    change = gov.update_agreement("RT-A", {"status": "terminated"})
    assert c["args"]["operation_id"] in change["cancelled_leases"]
    ok, why = gov.verifier.verify(o.lease, c)
    assert not ok and "cancelled" in why
    assert gov.propose(op(billing_reference="E2", agreement_version=2)).verdict == "BLOCK"


def test_terminated_agreement_does_not_poison_other_customers(gov):
    assert gov.propose(op()).verdict == "ALLOW"
    o = gov.propose(op(billing_reference="E2"))
    ok, _ = gov.verifier.verify(o.lease, op(billing_reference="E2"))  # not the same request
    assert not ok
    gov.update_agreement("RT-A", {"status": "terminated"})
    gov.state["observed"]["observed_collections"] = {}
    assert gov.propose(op("RT-N")).verdict == "ALLOW"


def test_evidence_chain_verifies(gov):
    gov.propose(op())
    gov.propose(op(amount=1))
    assert gov.kernel.integrity()["evidence_verified"]


def test_reusing_a_dispatched_operation_id_with_new_terms_is_refused(gov):
    c = op()
    assert gov.propose(c).verdict == "ALLOW"
    reuse = op(billing_reference="OTHER", operation_id=c["args"]["operation_id"])
    o = gov.propose(reuse)
    assert o.verdict == "BLOCK" and "duplicate operation id" in o.global_["reason"]
    assert gov.propose(copy.deepcopy(c)).verdict == "BLOCK"      # exact replay


def test_lowered_ceiling_counts_history_without_poisoning_others(gov):
    assert gov.propose(op(billing_reference="E1")).verdict == "ALLOW"
    assert gov.propose(op(billing_reference="E2")).verdict == "ALLOW"
    gov.update_agreement("RT-A", {"ceiling_minor": 50000})
    gov.state["observed"]["observed_collections"] = {}
    assert gov.propose(op("RT-N")).verdict == "ALLOW"            # other customer unaffected
    o = gov.propose(op(billing_reference="E3", agreement_version=2))
    assert o.verdict == "BLOCK" and o.decision["rule"] == E.GLOBAL_RULE


def test_dispatched_operations_survive_a_governance_restart(gov, tmp_path):
    c = op()
    assert gov.propose(c).verdict == "ALLOW"
    again = CollectionGovernor(copy.deepcopy(TERMS), tmp_path, LeaseSigner(),
                               lambda: gov.state["observed"])
    assert c["args"]["operation_id"] in again.envelope_snapshot()["dispatched_operations"]
    assert again.propose(op()).verdict == "BLOCK"                 # duplicate still seen
