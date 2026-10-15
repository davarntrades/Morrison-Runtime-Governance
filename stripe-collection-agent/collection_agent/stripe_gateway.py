"""Stripe API access. Imported only by trusted server-side processes.

The collection agent never imports this module and never receives a key. The
executor is the only process that performs Stripe writes, and it does so only
after Morrison's `LeaseVerifier` has redeemed a valid execution lease.

Test mode only: a live-mode key is refused at construction.
"""

from __future__ import annotations

import json
import os
from typing import Optional

import stripe

TEST_KEY_PREFIXES = ("sk_test_", "rk_test_")
METADATA_OPERATION = "morrison_operation_id"


class StripeModeError(RuntimeError):
    pass


def _plain(obj) -> dict:
    """StripeObject -> plain dict, recursively (its str() is its JSON)."""
    return json.loads(str(obj))


class StripeGateway:
    def __init__(self, api_key: Optional[str] = None,
                 api_base: Optional[str] = None):
        key = api_key or os.environ.get("STRIPE_SECRET_KEY", "")
        if not key.startswith(TEST_KEY_PREFIXES):
            raise StripeModeError(
                "a Stripe TEST-mode secret key (sk_test_… / rk_test_…) is "
                "required; live keys and missing keys are refused")
        base = api_base or os.environ.get("STRIPE_API_BASE") or None
        kwargs = {"base_addresses": {"api": base}} if base else {}
        self.client = stripe.StripeClient(key, **kwargs)
        self.api_base = base or "https://api.stripe.com"
        self.backend = "stripe-test-mode" if not base else f"override:{base}"

    # ── reads ────────────────────────────────────────────────
    def account_id(self) -> str:
        return self.client.v1.accounts.retrieve_current().id

    def retrieve_invoice(self, invoice_id: str) -> dict:
        return _plain(self.client.v1.invoices.retrieve(invoice_id))

    def list_invoices(self, customer: str) -> list[dict]:
        out, params = [], {"customer": customer, "limit": 100}
        page = self.client.v1.invoices.list(params)
        for inv in page.auto_paging_iter():
            out.append(_plain(inv))
        return out

    # ── writes (executor only, after lease redemption) ──────
    def create_collection_invoice(self, args: dict, binding: dict) -> dict:
        """customer -> invoice -> invoice item -> finalize -> hosted URL.

        Every write carries an idempotency key derived from the Morrison
        operation id, so a network retry cannot create a second invoice. The
        idempotency key is retry safety only: authorization was already
        consumed by the single-use lease before this method was called.
        """
        op = args["operation_id"]
        metadata = {METADATA_OPERATION: op,
                    "agreement_id": args["agreement_id"],
                    "agreement_version": str(args["agreement_version"]),
                    "billing_reference": args["billing_reference"],
                    "customer_ref": args["customer"],
                    "morrison_decision_id": binding.get("decision_id", ""),
                    "morrison_action_hash": binding.get("action_hash", ""),
                    "morrison_lease_id": binding.get("lease_id", "")}
        inv = self.client.v1.invoices.create(
            {"customer": args["stripe_customer"], "currency": args["currency"],
             "collection_method": "send_invoice", "days_until_due": 14,
             "auto_advance": False, "pending_invoice_items_behavior": "exclude",
             "description": args["description"], "metadata": metadata},
            {"idempotency_key": f"{op}:invoice"})
        self.client.v1.invoice_items.create(
            {"customer": args["stripe_customer"], "invoice": inv.id,
             "amount": args["amount"], "currency": args["currency"],
             "description": args["description"], "metadata": metadata},
            {"idempotency_key": f"{op}:item"})
        fin = self.client.v1.invoices.finalize_invoice(
            inv.id, {}, {"idempotency_key": f"{op}:finalize"})
        sent = None
        if os.environ.get("STRIPE_SEND_INVOICE", "0") == "1":
            sent = self.client.v1.invoices.send_invoice(
                inv.id, {}, {"idempotency_key": f"{op}:send"}).status
        return {"invoice_id": fin.id, "number": fin.number,
                "status": fin.status, "amount_due": fin.amount_due,
                "currency": fin.currency, "customer": fin.customer,
                "hosted_invoice_url": fin.hosted_invoice_url,
                "livemode": fin.livemode, "sent": sent,
                "metadata": dict(fin.metadata or {})}

    # ── operator / test-customer actions (never reachable by the agent) ──
    def create_customer(self, name: str, email: str, ref: str) -> str:
        return self.client.v1.customers.create(
            {"name": name, "email": email,
             "metadata": {"customer_ref": ref}}).id

    def create_manual_invoice(self, customer: str, amount: int, desc: str,
                              metadata: dict) -> dict:
        """Operator-issued invoice created OUTSIDE the agent (pre-existing
        collection state). Carries no Morrison operation id."""
        inv = self.client.v1.invoices.create(
            {"customer": customer, "currency": "gbp",
             "collection_method": "send_invoice", "days_until_due": 30,
             "auto_advance": False, "pending_invoice_items_behavior": "exclude",
             "description": desc, "metadata": metadata})
        self.client.v1.invoice_items.create(
            {"customer": customer, "invoice": inv.id, "amount": amount,
             "currency": "gbp", "description": desc})
        return _plain(self.client.v1.invoices.finalize_invoice(inv.id))

    def pay_as_test_customer(self, invoice_id: str, customer: str) -> dict:
        """Simulate the customer paying with Stripe's test card PaymentMethod.
        This is the customer's action, run by the test harness."""
        pm = self.client.v1.payment_methods.attach(
            "pm_card_visa", {"customer": customer})
        return _plain(self.client.v1.invoices.pay(
            invoice_id, {"payment_method": pm.id}))

    def void_invoice(self, invoice_id: str) -> dict:
        return _plain(self.client.v1.invoices.void_invoice(invoice_id))


def accounting(invoices: list[dict]) -> dict:
    """Issued / outstanding / paid from Stripe's own invoice states.

    issued       finalised and not void (open, paid, uncollectible)
    outstanding  amount_remaining on open invoices
    paid         amount_paid on paid invoices
    Drafts and voided invoices are not issued. Creating an invoice is never
    counted as receipt of funds.
    """
    issued = [i for i in invoices if i.get("status") in ("open", "paid", "uncollectible")]
    return {
        "issued_minor": sum(int(i.get("total") or i.get("amount_due") or 0) for i in issued),
        "outstanding_minor": sum(int(i.get("amount_remaining") or 0)
                                 for i in invoices if i.get("status") == "open"),
        "paid_minor": sum(int(i.get("amount_paid") or 0)
                          for i in invoices if i.get("status") == "paid"),
        "void_count": sum(1 for i in invoices if i.get("status") == "void"),
        "invoice_count": len(issued),
    }
