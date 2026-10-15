"""Neutral policy vocabulary (SPEC §5) and helpers adapters may use to translate it.

A scenario policy has these optional clauses:

  allow                 per-call allow entries: {"op", and any of "from", "to", "to_domain",
                        "max_amount", "subject", "entitlement"}; a mutating operation
                        matching no entry is not permitted
  approval_required     [{"op", "min_amount"}]: permitted only with an approval
  aggregate_limits      [{"account", "limit"}]: total outflow from the account, across ALL
                        principals and the whole episode, must not exceed the limit
  forbidden_flows       [{"src", "dst"}]: funds from src must not reach dst by any path
  separation_of_duties  [{"entitlements": [...]}]: no subject may hold all of them
  owners                {account: tenant}: a principal may debit only its own tenant's accounts
  confidential_docs     [doc ids]; internal_domain: content of a confidential document must
                        not be emailed outside the internal domain
  provenance            [{"op", "arg", "must_come_from": "request"}]: the argument must not
                        derive from untrusted data

Each adapter translates the clauses its SUT can express and lists the rest in
`untranslated` — those are reported next to the result, never silently dropped.
"""

from __future__ import annotations

CLAUSES = ("allow", "approval_required", "aggregate_limits", "forbidden_flows",
           "separation_of_duties", "owners", "confidential_docs", "provenance")


def present(policy: dict) -> list[str]:
    return [c for c in CLAUSES if policy.get(c)]


def allowed(policy: dict, op: dict) -> bool:
    """Per-call allow-list match. Reads are always allowed (no effect)."""
    kind, a = op["op"], op.get("args") or {}
    if kind == "read_doc":
        return True
    for e in policy.get("allow") or []:
        if e["op"] != kind:
            continue
        if "from" in e and a.get("from") not in e["from"]:
            continue
        if "to" in e and a.get("to") not in e["to"]:
            continue
        if "to_domain" in e and not any(str(a.get("to", "")).endswith("@" + d) for d in e["to_domain"]):
            continue
        if "max_amount" in e:
            amt = a.get("amount")
            if isinstance(amt, bool) or not isinstance(amt, (int, float)) or amt > e["max_amount"]:
                continue
        if "subject" in e and a.get("subject") not in e["subject"]:
            continue
        if "entitlement" in e and a.get("entitlement") not in e["entitlement"]:
            continue
        return True
    return False


def needs_approval(policy: dict, op: dict) -> bool:
    for r in policy.get("approval_required") or []:
        if r["op"] == op["op"]:
            amt = (op.get("args") or {}).get("amount", 0)
            if not isinstance(amt, (int, float)) or amt >= r.get("min_amount", 0):
                return True
    return False
