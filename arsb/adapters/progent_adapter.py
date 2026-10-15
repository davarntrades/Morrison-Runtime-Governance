"""Progent adapter — uses the ORIGINAL implementation (sunblaze-ucb/progent @ 5be7b63,
package `secagent`), unmodified, with hand-written policies (no policy LLM, no inference).

Enforcement is Progent's own: every operation is a Python tool wrapped by
`secagent.secure_tool_wrapper`, which calls `secagent.check_tool_call` before the
tool body runs. The adapter only translates the neutral policy into Progent's policy
format and answers Progent's interactive confirmation prompt on behalf of the
scenario's approver.

Translation (Progent policy: {tool: [(priority, effect 0=allow/1=forbid, {arg: restriction}, fallback)]},
fallback 0 = refuse, 2 = ask the user):
  allow               -> effect-0 rules with JSON-schema restrictions (enum, maximum, pattern)
  approval_required   -> effect-1 rule, fallback 2 (Progent's user confirmation), restricted to the
                         allowed accounts so a confirmation cannot widen the allowlist
  everything else     -> NOT TRANSLATABLE in Progent's static argument-restriction language
                         (aggregate limits, flows, separation of duties, tenancy, provenance,
                         confidentiality). Listed in `untranslated`.

Progent's confirmation is a prompt answered once per call; there is no approval artefact.
The adapter answers "y" only for the step the approver approved, so an approval cannot be
"replayed" — which is Progent's design, not something added here.

Progent keeps its policy in a module-global variable; all principals share it. This
adapter therefore runs episodes one at a time.
"""

from __future__ import annotations

import builtins
import re
import threading

import secagent
from secagent import tool as ptool

from arsb.core.adapter import Adapter, Outcome
from arsb.core.fixture import Refused
from arsb.core.policy import present

_ep = threading.local()
_current = {}


def _call(op_name: str, principal: str, args: dict) -> str:
    a = _current["adapter"]
    a.exec({"op": op_name, "args": args}, principal, "", None)
    return "ok"


def transfer(from_account: str, to: str, amount: int) -> str:
    """Move funds between accounts.

    :param from_account: account debited
    :param to: account credited
    :param amount: whole amount
    """
    return _call("transfer", _ep.principal, {"from": from_account, "to": to, "amount": amount})


def grant_role(subject: str, entitlement: str) -> str:
    """Grant an entitlement.

    :param subject: who receives it
    :param entitlement: the entitlement
    """
    return _call("grant_role", _ep.principal, {"subject": subject, "entitlement": entitlement})


def send_email(to: str, body: str) -> str:
    """Send an email.

    :param to: recipient address
    :param body: message body
    """
    return _call("send_email", _ep.principal, {"to": to, "body": body})


def set_password(password: str) -> str:
    """Change the account password.

    :param password: new password
    """
    return _call("set_password", _ep.principal, {"password": password})


def read_doc(id: str) -> str:  # noqa: A002 - tool argument name
    """Read a document.

    :param id: document id
    """
    a = _current["adapter"]
    return str(a.exec({"op": "read_doc", "args": {"id": id}}, _ep.principal, "", None))


_RAW = {"transfer": transfer, "grant_role": grant_role, "send_email": send_email,
        "set_password": set_password, "read_doc": read_doc}
_TOOLS = None


def _tools():
    global _TOOLS
    if _TOOLS is None:
        _TOOLS = {n: ptool.secure_tool_wrapper(f) for n, f in _RAW.items()}
    return _TOOLS


def _restrictions(entry: dict) -> dict:
    r = {}
    if "from" in entry:
        r["from_account"] = {"type": "string", "enum": list(entry["from"])}
    if "to" in entry:
        r["to"] = {"type": "string", "enum": list(entry["to"])}
    if "to_domain" in entry:
        r["to"] = {"type": "string",
                   "pattern": "@(" + "|".join(re.escape(d) for d in entry["to_domain"]) + ")$"}
    if "max_amount" in entry:
        r["amount"] = {"type": "number", "maximum": entry["max_amount"]}
    if "subject" in entry:
        r["subject"] = {"type": "string", "enum": list(entry["subject"])}
    if "entitlement" in entry:
        r["entitlement"] = {"type": "string", "enum": list(entry["entitlement"])}
    return r


def translate(policy: dict) -> tuple[dict, list]:
    rules = {"read_doc": [(1, 0, {}, 0)]}
    for e in policy.get("allow") or []:
        rules.setdefault(e["op"], []).append((2, 0, _restrictions(e), 0))
    for req in policy.get("approval_required") or []:
        for e in policy.get("allow") or []:
            if e["op"] == req["op"]:
                r = _restrictions(e)
                r["amount"] = {"type": "number", "minimum": req.get("min_amount", 0)}
                rules.setdefault(req["op"], []).append((1, 1, r, 2))
    untranslated = [c for c in present(policy) if c not in ("allow", "approval_required")]
    return rules, untranslated


class Progent(Adapter):
    name = "progent"
    mechanisms = frozenset({"pre_execution_veto", "per_call_policy", "human_confirmation"})

    def can_run(self, scenario):
        if scenario.get("evidence_checks"):
            return False, "Progent exports no decision evidence"
        if scenario.get("faults"):
            return False, "Progent has no injectable decision dependency"
        return True, ""

    def setup(self, scenario, executor, workdir):
        self.sc, self.exec = scenario, executor
        rules, self.untranslated = translate(scenario.get("policy") or {})
        _current["adapter"] = self
        _tools()
        ptool.update_security_policy(rules)
        self._input = builtins.input
        builtins.input = self._answer

    def _answer(self, *a, **kw):
        _ep.prompted = True
        return "y" if getattr(_ep, "confirm", False) else "N"

    def submit(self, principal, op, ctx):
        _ep.principal, _ep.prompted = principal, False
        _ep.confirm = bool(isinstance(ctx.approval, dict) and ctx.approval.get("step") == ctx.step_id)
        args = dict(op.get("args") or {})
        if op["op"] == "transfer":
            args = {"from_account": args.get("from"), "to": args.get("to"), "amount": args.get("amount")}
        try:
            _tools()[op["op"]](**args)
            return Outcome("executed")
        except Refused as exc:
            return Outcome("refused", f"resource: {exc}")
        except Exception as exc:                       # noqa: BLE001 - Progent refusal
            if _ep.prompted and not _ep.confirm:
                return Outcome("deferred", "Progent asked for user confirmation",
                               request={"step": ctx.step_id})
            return Outcome("refused", f"progent: {type(exc).__name__}: {exc}"[:200])

    def approve(self, request, principal, op):
        # The human at Progent's prompt says yes to THIS request only.
        return dict(request) if isinstance(request, dict) else None

    def teardown(self):
        builtins.input = self._input
        ptool.security_policy = None
        _current.pop("adapter", None)
