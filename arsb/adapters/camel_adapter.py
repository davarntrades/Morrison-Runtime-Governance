"""CaMeL adapter — uses the ORIGINAL implementation (google-research/camel-prompt-injection
@ f083b6b), unmodified: its interpreter, capability tracking, `is_trusted` and
`can_readers_read_value`, and its SecurityPolicyEngine protocol. No model is called.

How a scripted step becomes CaMeL input: CaMeL executes PROGRAMS written by its
privileged LLM, never single calls. Here the scripted proposer plays that role: each
step is compiled to a short program in a per-principal CaMeL session (namespace and
dependencies persist across steps). An argument the script declares as coming from a
document is obtained in the program by CALLING `read_doc_field` and passing the result
on, so CaMeL derives its provenance from real dataflow; the adapter never tells CaMeL
what is trusted. Literal arguments are, as in CaMeL, values from the user.

Tool-output labelling follows CaMeL's own convention for file contents (`read_file`):
document contents are untrusted and private. CaMeL decides; the adapter only reports.

Policy translation into CaMeL policies (Python functions over CaMeL values and, as
CaMeL's own workspace policies do, the current environment state via `observe`):
  allow                 per-call checks on raw argument values
  provenance            is_trusted(argument)                       (CaMeL-native)
  confidential_docs     recipient must be able to read the body   (CaMeL-native readers)
  approval_required     Denied: CaMeL's code has no confirmation path (§5.4 describes one;
                        the implementation raises and stops), so above-threshold calls are refused
  owners                per-principal check that the debited account is the principal's tenant's
  aggregate_limits,     checks over the CURRENT environment state at decision time. CaMeL's
  forbidden_flows,      policy language can read state; it has no reservation, so concurrent
  separation_of_duties  decisions are not serialised (expected to fail XAG-02 by design)
No evidence export, no fault hooks, no resource-side check: EVD/FCL UNSUPPORTED, RES by outcome.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping

from agentdojo.functions_runtime import FunctionsRuntime, TaskEnvironment, make_function
from camel.capabilities import can_readers_read_value, is_trusted
from camel.interpreter import interpreter
from camel.interpreter import namespace as ns
from camel.pipeline_elements.agentdojo_function import make_agentdojo_namespace
from camel.security_policy import (NO_SIDE_EFFECT_TOOLS, Allowed, Denied, SecurityPolicyDeniedError,
                                   SecurityPolicyEngine)

from arsb.core.adapter import Adapter, Outcome
from arsb.core.fixture import Refused
from arsb.core.policy import allowed, needs_approval, present

_ep = threading.local()
_current = {}


def _exec(op, args):
    return _current["adapter"].exec({"op": op, "args": args}, _ep.principal, "", None)


def transfer(from_account: str, to: str, amount: int) -> str:
    """Move funds between accounts.

    :param from_account: account debited
    :param to: account credited
    :param amount: whole amount
    """
    _exec("transfer", {"from": from_account, "to": to, "amount": amount})
    return "done"


def grant_role(subject: str, entitlement: str) -> str:
    """Grant an entitlement.

    :param subject: who receives it
    :param entitlement: the entitlement
    """
    _exec("grant_role", {"subject": subject, "entitlement": entitlement})
    return "done"


def send_email(to: str, body: str) -> str:
    """Send an email.

    :param to: recipient address
    :param body: message body
    """
    _exec("send_email", {"to": to, "body": body})
    return "done"


def set_password(password: str) -> str:
    """Change the password.

    :param password: new password
    """
    _exec("set_password", {"password": password})
    return "done"


def read_doc(id: str) -> str:  # noqa: A002
    """Read a document.

    :param id: document id
    """
    return _exec("read_doc", {"id": id})["read"]["content"]


def read_doc_field(id: str, field: str) -> str:  # noqa: A002
    """Read one field of a document.

    :param id: document id
    :param field: field name
    """
    return _exec("read_doc", {"id": id})["read"]["fields"][field]


RUNTIME = FunctionsRuntime([make_function(f) for f in
                            (transfer, grant_role, send_email, set_password, read_doc, read_doc_field)])
_ARGMAP = {"transfer": {"from": "from_account"}}


def _raw(v):
    return getattr(v, "raw", v)


class ArsbPolicyEngine(SecurityPolicyEngine):
    def __init__(self, adapter, principal):
        self.a, self.principal = adapter, principal
        self.policy = adapter.sc.get("policy") or {}
        self.no_side_effect_tools = NO_SIDE_EFFECT_TOOLS | {"read_doc", "read_doc_field"}
        self.policies = [(t, self.check) for t in ("transfer", "grant_role", "send_email", "set_password")]

    def check(self, tool: str, kwargs: Mapping):
        raw = {k: _raw(v) for k, v in kwargs.items()}
        op = {"op": tool, "args": {("from" if k == "from_account" else k): v for k, v in raw.items()}}
        p = self.policy
        if p.get("allow") and not allowed(p, op):
            return Denied("no allow entry matches")
        for rule in p.get("provenance") or []:
            arg = _ARGMAP.get(tool, {}).get(rule["arg"], rule["arg"])
            if rule["op"] == tool and arg in kwargs and not is_trusted(kwargs[arg]):
                return Denied(f"{rule['arg']} does not come from the user")
        if tool == "send_email" and p.get("confidential_docs"):
            if not can_readers_read_value({raw["to"]}, kwargs["body"]):
                return Denied("the recipient cannot read the body")
        if needs_approval(p, op):
            return Denied("requires user confirmation (not implemented in CaMeL's code; denied)")
        args = op["args"]
        if tool == "transfer":
            if p.get("owners"):
                tenant = next(x["tenant"] for x in self.a.sc["principals"] if x["id"] == self.principal)
                if p["owners"].get(args["from"]) != tenant:
                    return Denied("debited account belongs to another tenant")
            state = self.a.observe()
            for lim in p.get("aggregate_limits") or []:
                if args["from"] == lim["account"]:
                    out = sum(e["args"]["amount"] for e in state["effects"]
                              if e["kind"] == "transfer" and e["args"]["from"] == lim["account"])
                    if out + args["amount"] > lim["limit"]:
                        return Denied("aggregate limit")
            for fl in p.get("forbidden_flows") or []:
                if args["to"] == fl["dst"]:
                    tainted = {fl["src"]}
                    for e in state["effects"]:
                        if e["kind"] == "transfer" and e["args"]["from"] in tainted:
                            tainted.add(e["args"]["to"])
                    if args["from"] in tainted:
                        return Denied("forbidden flow")
        if tool == "grant_role":
            roles = {(s, r) for s, r in self.a.observe()["roles"]}
            for sod in p.get("separation_of_duties") or []:
                held = {r for s, r in roles if s == args["subject"]} | {args["entitlement"]}
                if set(sod["entitlements"]) <= held:
                    return Denied("separation of duties")
        return Allowed()


class CaMeL(Adapter):
    name = "camel"
    mechanisms = frozenset({"pre_execution_veto", "per_call_policy", "argument_provenance",
                            "information_flow_readers", "environment_state_policies"})

    def can_run(self, scenario):
        if scenario.get("evidence_checks"):
            return False, "CaMeL exports no decision evidence"
        if scenario.get("faults"):
            return False, "CaMeL has no injectable decision dependency"
        return True, ""

    def setup(self, scenario, executor, workdir):
        self.sc, self.exec = scenario, executor
        self.untranslated = [c for c in present(scenario.get("policy") or {})
                             if c not in ("allow", "provenance", "confidential_docs", "approval_required",
                                          "owners", "aggregate_limits", "forbidden_flows",
                                          "separation_of_duties")]
        _current["adapter"] = self
        base = ns.Namespace.with_builtins()
        self.sessions = {}
        self._base = base.add_variables(make_agentdojo_namespace(base, RUNTIME, TaskEnvironment()))
        self._lock = threading.Lock()

    def _program(self, op, ctx):
        args = dict(op.get("args") or {})
        lines, call_args = [], []
        for k, v in args.items():
            name = _ARGMAP.get(op["op"], {}).get(k, k)
            src = ctx.arg_sources.get(k, "request")
            if ":" in src:                       # value obtained by a tool call, as an agent would
                var = f"v_{ctx.step_id}_{k}"
                lines.append(f"{var} = read_doc_field(id={json.dumps(src.split(':', 1)[1])}, field={json.dumps(k)})")
                call_args.append(f"{name}={var}")
            else:
                call_args.append(f"{name}={json.dumps(v)}")
        lines.append(f"{op['op']}({', '.join(call_args)})")
        return "```python\n" + "\n".join(lines) + "\n```"

    def submit(self, principal, op, ctx):
        _ep.principal = principal
        with self._lock:
            session = self.sessions.setdefault(principal, {"ns": self._base, "deps": []})
        eval_args = interpreter.EvalArgs(ArsbPolicyEngine(self, principal), interpreter.MetadataEvalMode.NORMAL)
        try:
            res, new_ns, _calls, deps = interpreter.parse_and_interpret_code(
                self._program(op, ctx), session["ns"], [], session["deps"], eval_args)
        except SecurityPolicyDeniedError as exc:
            return Outcome("refused", f"camel: {exc}"[:200])
        except Refused as exc:
            return Outcome("refused", f"resource: {exc}")
        session["ns"], session["deps"] = new_ns, list(deps)
        err = getattr(res, "error", None)
        if err is not None:
            inner = getattr(err, "exception", err)
            if isinstance(inner, Refused):
                return Outcome("refused", f"resource: {inner}")
            return Outcome("refused", f"camel: {type(inner).__name__}: {inner}"[:200])
        return Outcome("executed")

    def teardown(self):
        _current.pop("adapter", None)
