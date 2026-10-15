"""Protected Stripe executor (trusted process; the only holder of the key).

Every Stripe write is reached through Morrison's resource-side enforcement
point, `morrison_governance.kernel.LeaseVerifier.execute`:

    request + lease ──▶ Ed25519 signature (public key only)
                        expiry / not-before
                        canonical action hash of THIS request == lease hash
                        single-use redemption in the shared SQLiteLeaseStore
                     ──▶ Stripe (only if every check passed)

A request without a lease, with a forged, expired, cancelled or already
redeemed lease, or whose arguments differ in any way from what Morrison
authorised, is refused before Stripe is called. Each attempt is sealed in a
Morrison `EvidenceChain` held by this process.

    python -m collection_agent.executor_service
"""

from __future__ import annotations

import json
import os
import threading
import time
from copy import deepcopy
from pathlib import Path

from morrison_governance.kernel import (
    EvidenceChain, EvidenceRecord, LeaseVerifier, SQLiteLeaseStore,
)
from morrison_governance.kernel.canonical import action_hash
from morrison_governance.kernel.mediation import ExecutionLease

from collection_agent import envelope as E
from collection_agent.stripe_gateway import (
    METADATA_OPERATION, StripeGateway, accounting,
)
from collection_agent.web import bearer_ok, make_server

ISSUED = ("open", "paid", "uncollectible")


class Executor:
    def __init__(self, gateway: StripeGateway, public_key: bytes,
                 lease_store_path: str, terms_file: str, service_token: str):
        self.gateway = gateway
        self.verifier = LeaseVerifier(public_key=public_key,
                                      store=SQLiteLeaseStore(lease_store_path))
        self.terms_file = terms_file
        self.service_token = service_token
        self.account_id = gateway.account_id()
        self.chain = EvidenceChain()
        self._lock = threading.Lock()

    def _seal(self, request: dict, ok: bool, layer: str, reason: str,
              result: dict | None = None, lease_id: str = "") -> dict:
        with self._lock:
            rec = self.chain.append(EvidenceRecord(
                seq=0, timestamp=time.time(), actor="stripe-executor",
                tenant="resurrection-tech",
                action_hash=action_hash(request) if isinstance(request, dict)
                and isinstance(request.get("tool"), str) else "",
                proposed=request if isinstance(request, dict) else {},
                decision="PERMIT" if ok else "BLOCK", layer=layer,
                rule="lease_redeemed" if ok else "execution_refused",
                reason=reason, executed=ok,
                authorization={"lease_id": lease_id,
                               "stripe_result": result or {}}))
        return {"seq": rec.seq, "record_hash": rec.record_hash}

    def execute(self, token: str, request: dict) -> tuple[int, dict]:
        lease_id = ""
        try:
            lease_id = ExecutionLease.decode(token).lease_id if token else ""
        except Exception:                            # noqa: BLE001
            lease_id = "undecodable"
        if not isinstance(request, dict) or request.get("tool") != E.TOOL:
            ev = self._seal(request, False, "executor",
                            "unsupported operation; only create_collection_invoice "
                            "is executable", lease_id=lease_id)
            return 403, {"executed": False, "reason": "unsupported operation",
                         "evidence": ev, "stripe_called": False}
        binding = {"lease_id": lease_id, "action_hash": action_hash(request)}
        try:
            binding["decision_id"] = ExecutionLease.decode(token).decision_id
        except Exception:                            # noqa: BLE001
            pass
        calls = []

        def run(snapshot: dict) -> dict:
            # Defence in depth, not the authorization: the key this process
            # holds must belong to the account the request names.
            if snapshot["args"].get("stripe_account") != self.account_id:
                raise PermissionError("request names a Stripe account other "
                                      "than the executor's own account")
            calls.append("stripe")
            return self.gateway.create_collection_invoice(
                deepcopy(snapshot["args"]), binding)

        ok, out = self.verifier.execute(token or "", request, run)
        if not ok:
            ev = self._seal(request, False, "lease", str(out), lease_id=lease_id)
            return 403, {"executed": False, "reason": str(out),
                         "stripe_called": bool(calls), "evidence": ev}
        ev = self._seal(request, True, "stripe", "lease verified and redeemed; "
                        "Stripe invoice finalised", out, lease_id=lease_id)
        return 200, {"executed": True, "stripe": out, "evidence": ev,
                     "backend": self.gateway.backend, "lease_id": lease_id}

    def invoice(self, invoice_id: str) -> dict:
        inv = self.gateway.retrieve_invoice(invoice_id)
        return {k: inv.get(k) for k in (
            "id", "number", "status", "amount_due", "amount_paid",
            "amount_remaining", "total", "currency", "customer",
            "hosted_invoice_url", "livemode", "metadata")} | {
            "verified_via": f"GET /v1/invoices/{invoice_id} ({self.gateway.backend})",
            "verified_at": time.time()}

    def collection_state(self) -> dict:
        """Authoritative observed collection state, read from Stripe."""
        terms = json.loads(Path(self.terms_file).read_text(encoding="utf-8"))
        observed, voided, books = {}, [], {}
        for ref, cust in terms["customers"].items():
            invoices = self.gateway.list_invoices(cust["stripe_customer"])
            books[ref] = accounting(invoices)
            for inv in invoices:
                md = inv.get("metadata") or {}
                op = md.get(METADATA_OPERATION)
                if op and inv.get("status") == "void":
                    voided.append(op)
                if not op and inv.get("status") in ISSUED:
                    observed.setdefault(ref, []).append({
                        "invoice": inv.get("id"),
                        "amount_minor": int(inv.get("total") or 0),
                        "agreement_id": md.get("agreement_id"),
                        "billing_reference": md.get("billing_reference"),
                        "status": inv.get("status")})
        return {"observed_collections": observed, "voided_operations": voided,
                "accounting": books, "read_at": time.time(),
                "backend": self.gateway.backend}

    def routes(self) -> dict:
        def execute(body, q, h):
            return self.execute(body.get("lease") or "", body.get("request"))

        def invoice(body, q, h):
            return 200, self.invoice(q["_rest"])

        def state(body, q, h):
            if not bearer_ok(h, self.service_token):
                return 401, {"error": "service token required"}
            return 200, self.collection_state()

        def evidence(body, q, h):
            ok, problems = self.chain.verify()
            return 200, {"verified": ok, "problems": problems,
                         "records": [json.loads(r.to_json()) for r in self.chain.records]}

        return {("POST", "/execute"): execute, ("GET", "/invoice/*"): invoice,
                ("GET", "/collection-state"): state,
                ("GET", "/evidence"): evidence,
                ("GET", "/health"): lambda b, q, h: (200, {
                    "ok": True, "account": self.account_id,
                    "backend": self.gateway.backend})}


def main() -> None:
    state = Path(os.environ["EXECUTOR_STATE_DIR"])
    pub_file = Path(os.environ["MORRISON_LEASE_PUBKEY_FILE"])
    pub = bytes.fromhex(pub_file.read_text(encoding="utf-8").strip())
    ex = Executor(StripeGateway(), pub, os.environ["MORRISON_LEASE_STORE"],
                  os.environ["TERMS_FILE"], os.environ["GOVERNANCE_SERVICE_TOKEN"])
    srv = make_server(ex.routes(), port=int(os.environ.get("EXECUTOR_PORT", "0")))
    (state / "executor.port").write_text(str(srv.server_address[1]), encoding="utf-8")
    srv.serve_forever()


if __name__ == "__main__":
    main()
