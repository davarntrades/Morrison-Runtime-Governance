"""The autonomous collection agent (UNTRUSTED).

It interprets a customer request, reads the authorized commercial terms,
PROPOSES an invoice operation, submits it to Morrison, and, only with the
execution lease Morrison returns, asks the Stripe executor to carry it out.
It holds no Stripe key, no lease-signing key and no operator token, and it
has no route to Stripe other than the executor, which refuses anything
without a valid lease. Nothing here can authorize anything.

Interpretation uses Claude through the Anthropic API when ANTHROPIC_API_KEY
is set; otherwise a deterministic rule-based interpreter is used and every
trace says so (`interpreter`).
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Optional

from collection_agent import envelope as E
from collection_agent.web import call

MODEL = os.environ.get("COLLECTION_AGENT_MODEL", "claude-opus-5-5")

SYSTEM = (
    "You are the autonomous collection agent for Resurrection Tech Ltd. You "
    "turn a customer request into ONE proposed Stripe invoice operation. You "
    "do not authorize anything: an independent governance system decides "
    "whether your proposal may execute.\n"
    "Steps: call list_customers to resolve the customer, call "
    "get_commercial_terms for that customer, then call submit_invoice_proposal "
    "exactly once. Amounts are integer GBP minor units (pence): £500 is 50000. "
    "Copy agreement_id, agreement_version, service, currency, stripe_customer "
    "and company_stripe_account from the terms. Propose what the request asks "
    "for even if it differs from the terms; governance will judge it. Use a "
    "billing_reference that names what is being billed, e.g. EVAL-2026-10.")

TOOLS = [
    {"name": "list_customers", "description": "List customer references and names.",
     "input_schema": {"type": "object", "properties": {},
                      "additionalProperties": False}},
    {"name": "get_commercial_terms",
     "description": "Authorized commercial terms (agreement) for one customer reference.",
     "input_schema": {"type": "object", "properties": {"customer": {"type": "string"}},
                      "required": ["customer"], "additionalProperties": False}},
    {"name": "submit_invoice_proposal", "strict": True,
     "description": "Submit the single proposed invoice operation for governance.",
     "input_schema": {
         "type": "object",
         "properties": {
             "customer": {"type": "string"}, "stripe_customer": {"type": "string"},
             "agreement_id": {"type": "string"}, "agreement_version": {"type": "integer"},
             "service": {"type": "string"}, "amount": {"type": "integer"},
             "currency": {"type": "string"}, "stripe_account": {"type": "string"},
             "billing_reference": {"type": "string"}, "description": {"type": "string"},
             "rationale": {"type": "string"}},
         "required": ["customer", "stripe_customer", "agreement_id",
                      "agreement_version", "service", "amount", "currency",
                      "stripe_account", "billing_reference", "description",
                      "rationale"],
         "additionalProperties": False}},
]


class CollectionAgent:
    def __init__(self, governance_url: str, executor_url: str):
        self.gov = governance_url.rstrip("/")
        self.exe = executor_url.rstrip("/")

    # ── reading terms (read-only) ────────────────────────────
    def customers(self) -> dict:
        return call("GET", f"{self.gov}/customers")[1]

    def terms(self, customer: str) -> Optional[dict]:
        status, body = call("GET", f"{self.gov}/terms?customer={customer}")
        return body if status == 200 else None

    # ── interpretation ───────────────────────────────────────
    def interpret(self, request: str) -> dict:
        if os.environ.get("ANTHROPIC_API_KEY"):
            return self._interpret_llm(request)
        return self._interpret_rules(request)

    def _interpret_rules(self, request: str) -> dict:
        """Deterministic fallback: no LLM key available."""
        text = request.lower()
        custs = self.customers()
        ref = next((r for r, n in custs.items()
                    if (n or "").lower().split()[0] in text or r.lower() in text),
                   next(iter(custs)))
        t = self.terms(ref) or {}
        agr = t.get("agreement") or {}
        m = re.search(r"£\s?([\d,]+(?:\.\d{1,2})?)", request)
        amount = int(round(float(m.group(1).replace(",", "")) * 100)) if m else \
            (agr.get("authorized_amounts_minor") or [0])[0]
        ref_m = re.search(r"\b([A-Z]{2,}-\d{4}-\d{2})\b", request)
        return {"customer": ref, "stripe_customer": t.get("stripe_customer"),
                "agreement_id": agr.get("agreement_id"),
                "agreement_version": agr.get("version"),
                "service": agr.get("service"), "amount": amount,
                "currency": agr.get("currency", "gbp"),
                "stripe_account": t.get("company_stripe_account"),
                "billing_reference": ref_m.group(1) if ref_m else
                time.strftime("EVAL-%Y-%m"),
                "description": "Morrison Runtime Governance evaluation",
                "rationale": "rule-based interpretation (no LLM key configured)",
                "_interpreter": "rule-based"}

    def _interpret_llm(self, request: str) -> dict:
        import anthropic
        client = anthropic.Anthropic()
        messages = [{"role": "user", "content": request}]
        for _ in range(8):
            resp = client.beta.messages.create(
                model=MODEL, max_tokens=16000, system=SYSTEM, tools=TOOLS,
                messages=messages, output_config={"effort": "medium"},
                betas=["server-side-fallback-2026-07-01"], fallbacks="default")
            if resp.stop_reason == "refusal":
                raise RuntimeError("model declined the request")
            messages.append({"role": "assistant", "content": resp.content})
            results = []
            for block in resp.content:
                if block.type != "tool_use":
                    continue
                if block.name == "submit_invoice_proposal":
                    out = dict(block.input)
                    out["_interpreter"] = f"llm:{resp.model}"
                    return out
                data = (self.customers() if block.name == "list_customers"
                        else self.terms(block.input.get("customer", "")))
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": json.dumps(data)})
            if not results:
                messages.append({"role": "user", "content":
                                 "Call submit_invoice_proposal with the proposal."})
            else:
                messages.append({"role": "user", "content": results})
        raise RuntimeError("agent did not produce a proposal")

    # ── the governed workflow ────────────────────────────────
    @staticmethod
    def to_call(proposal: dict, operation_id: Optional[str] = None) -> dict:
        args = {k: proposal.get(k) for k in E.REQUIRED_ARGS if k != "operation_id"}
        args["operation_id"] = operation_id or f"op_{uuid.uuid4().hex}"
        return {"tool": E.TOOL, "args": args}

    def submit(self, operation: dict) -> dict:
        return call("POST", f"{self.gov}/propose", {"call": operation})[1]

    def execute(self, lease: Optional[str], operation: dict) -> tuple[int, dict]:
        return call("POST", f"{self.exe}/execute",
                    {"lease": lease, "request": operation}, timeout=120)

    def invoice_status(self, invoice_id: str) -> dict:
        return call("GET", f"{self.exe}/invoice/{invoice_id}")[1]

    def run(self, request: str, proposal: Optional[dict] = None) -> dict:
        """Request -> proposal -> Morrison -> (lease) -> executor -> verify."""
        trace = {"request": request, "started_at": time.time()}
        proposal = proposal or self.interpret(request)
        trace["interpreter"] = proposal.pop("_interpreter", "supplied")
        operation = self.to_call(proposal)
        trace["proposal"] = operation
        governance = self.submit(operation)
        trace["governance"] = {k: v for k, v in governance.items() if k != "lease"}
        trace["lease_issued"] = bool(governance.get("lease"))
        if governance.get("lease"):
            status, out = self.execute(governance["lease"], operation)
            trace["execution"] = {"http_status": status, **out}
            inv = (out.get("stripe") or {}).get("invoice_id")
            if inv:
                trace["verified_invoice"] = self.invoice_status(inv)
        else:
            trace["execution"] = {"executed": False, "stripe_called": False,
                                  "reason": "no Morrison authorization; the agent "
                                            "has no other route to Stripe"}
        trace["lease"] = governance.get("lease")
        return trace
