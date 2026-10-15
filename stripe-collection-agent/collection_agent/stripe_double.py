"""LOCAL STRIPE TEST DOUBLE. NOT STRIPE.

A small stateful HTTP server that speaks the subset of the Stripe REST API
this project uses, so that the governance boundary, the lease checks and the
executor can be tested offline through the REAL `stripe` Python SDK (pointed
here with `STRIPE_API_BASE`). Results produced against it are labelled
`backend: override:http://127.0.0.1:…` everywhere and must never be reported
as Stripe results. The live demonstration uses api.stripe.com in test mode.

It also records every write it receives, so tests can assert that a refused
operation produced no Stripe request at all.
"""

from __future__ import annotations

import itertools
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlparse

_ids = itertools.count(1)


def _id(prefix: str) -> str:
    return f"{prefix}_double{next(_ids):06d}"


def _form(body: str) -> dict:
    """Decode Stripe's bracketed form encoding (one nesting level + lists)."""
    out: dict = {}
    for k, v in parse_qsl(body, keep_blank_values=True):
        if "[" in k:
            head, rest = k.split("[", 1)
            sub = rest.rstrip("]")
            if sub == "":
                out.setdefault(head, []).append(v)
            else:
                out.setdefault(head, {})[sub] = v
        else:
            out[k] = v
    return out


class StripeDouble:
    def __init__(self):
        self.account = {"id": "acct_double_resurrection", "object": "account",
                        "business_profile": {"name": "Resurrection Tech Ltd (double)"}}
        self.customers: dict = {}
        self.invoices: dict = {}
        self.idem: dict = {}
        self.writes: list = []
        self.lock = threading.Lock()
        self.base = ""

    # ── operations ───────────────────────────────────────────
    def handle(self, method: str, path: str, query: dict, form: dict,
               idem_key: str) -> tuple[int, dict]:
        with self.lock:
            if method == "POST":
                cache = (path, idem_key)
                if idem_key and cache in self.idem:
                    return self.idem[cache]
                self.writes.append({"path": path, "form": form, "at": time.time()})
            res = self._route(method, path, query, form)
            if method == "POST" and idem_key:
                self.idem[(path, idem_key)] = res
            return res

    def _err(self, msg: str, code: int = 400) -> tuple[int, dict]:
        return code, {"error": {"type": "invalid_request_error", "message": msg}}

    def _route(self, method, path, query, form):
        parts = [p for p in path.split("/") if p][1:]           # drop "v1"
        if parts == ["account"] and method == "GET":
            return 200, self.account
        if parts == ["customers"] and method == "POST":
            c = {"id": _id("cus"), "object": "customer", "name": form.get("name"),
                 "email": form.get("email"), "metadata": form.get("metadata", {}),
                 "livemode": False}
            self.customers[c["id"]] = c
            return 200, c
        if parts == ["invoices"] and method == "POST":
            if form.get("customer") not in self.customers:
                return self._err(f"No such customer: '{form.get('customer')}'", 404)
            inv = {"id": _id("in"), "object": "invoice", "status": "draft",
                   "customer": form["customer"], "currency": form.get("currency", "gbp"),
                   "collection_method": form.get("collection_method"),
                   "description": form.get("description"), "number": None,
                   "metadata": form.get("metadata", {}), "total": 0,
                   "amount_due": 0, "amount_paid": 0, "amount_remaining": 0,
                   "hosted_invoice_url": None, "livemode": False,
                   "created": int(time.time())}
            self.invoices[inv["id"]] = inv
            return 200, inv
        if parts == ["invoices"] and method == "GET":
            data = [i for i in self.invoices.values()
                    if not query.get("customer") or i["customer"] == query["customer"]]
            return 200, {"object": "list", "data": data[::-1], "has_more": False,
                         "url": "/v1/invoices"}
        if parts == ["invoiceitems"] and method == "POST":
            inv = self.invoices.get(form.get("invoice"))
            if inv is None or inv["status"] != "draft":
                return self._err("invoice is not an editable draft")
            amt = int(form["amount"])
            inv["total"] += amt
            return 200, {"id": _id("ii"), "object": "invoiceitem", "amount": amt,
                         "invoice": inv["id"], "customer": form.get("customer"),
                         "currency": form.get("currency"), "livemode": False}
        if parts and parts[0] == "invoices" and len(parts) >= 2:
            inv = self.invoices.get(parts[1])
            if inv is None:
                return self._err(f"No such invoice: '{parts[1]}'", 404)
            action = parts[2] if len(parts) > 2 else ""
            if method == "GET" and not action:
                return 200, inv
            if action == "finalize":
                if inv["status"] != "draft":
                    return self._err("invoice is already finalized")
                inv.update(status="open", number=f"DBL-{len(self.invoices):04d}",
                           amount_due=inv["total"], amount_remaining=inv["total"],
                           hosted_invoice_url=f"{self.base}/hosted/{inv['id']}")
                return 200, inv
            if action == "send":
                return 200, inv
            if action == "pay":
                if inv["status"] != "open":
                    return self._err("invoice is not open")
                if not str(form.get("payment_method", "")).startswith("pm_"):
                    return self._err("payment_method required")
                inv.update(status="paid", amount_paid=inv["amount_due"],
                           amount_remaining=0)
                return 200, inv
            if action == "void":
                if inv["status"] != "open":
                    return self._err("only open invoices can be voided")
                inv["status"] = "void"
                inv["amount_remaining"] = 0
                return 200, inv
        if len(parts) == 3 and parts[0] == "payment_methods" and parts[2] == "attach":
            return 200, {"id": _id("pm"), "object": "payment_method",
                         "customer": form.get("customer"), "type": "card",
                         "livemode": False}
        return self._err(f"unsupported in double: {method} {path}", 404)

    # ── server ───────────────────────────────────────────────
    def serve(self, port: int = 0) -> ThreadingHTTPServer:
        double = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self, method):
                u = urlparse(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode() if n else ""
                form = _form(raw if method == "POST" else "")
                query = dict(parse_qsl(u.query))
                if not (self.headers.get("Authorization") or "").startswith("Bearer sk_test_"):
                    code, body = 401, {"error": {"message": "test key required"}}
                elif u.path.startswith("/hosted/"):
                    code, body = 200, {"double_hosted_invoice": u.path.split("/")[-1]}
                else:
                    code, body = double.handle(method, u.path, query, form,
                                               self.headers.get("Idempotency-Key") or "")
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Request-Id", _id("req"))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._go("GET")

            def do_POST(self):
                self._go("POST")

        srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        srv.daemon_threads = True
        self.base = f"http://127.0.0.1:{srv.server_address[1]}"
        return srv


def main() -> None:
    import os
    from pathlib import Path
    d = StripeDouble()
    srv = d.serve(int(os.environ.get("STRIPE_DOUBLE_PORT", "0")))
    out = os.environ.get("STRIPE_DOUBLE_URL_FILE")
    if out:
        Path(out).write_text(d.base, encoding="utf-8")
    print(d.base, flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
