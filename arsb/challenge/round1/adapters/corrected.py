"""Corrected adapters for ARSB challenge round 1. The frozen adapters are imported
and subclassed, never edited. Each class names the single translation choice it
changes and the evidence for it (see REPORT.md §2).

  camel-confirm        CaMeL paper §5.4: a policy-violating call "will require user
                       confirmation". approval_required -> per-call confirmation (the same
                       per-call semantics the frozen Progent adapter gets), not denial.
  camel-labels         Tool-output labels as the frozen docstring claims but the code does
                       not do: CaMeL's AgentDojo labelling (`_get_metadata_for_ad`) has no
                       case for read_doc/read_doc_field, so they fall through to the default
                       (sources=Tool(name), readers=Public). Here: documents the fixture marks
                       trusted get TrustedToolSource; confidential documents get private
                       readers (frozenset(), as CaMeL labels read_file); internal recipients
                       may read confidential values (the neutral clause allows internal email).
  camel-faithful       both of the above.
  progent-fixedappr    approval rule keeps the allow entry's max_amount (the frozen rule
                       overwrites `amount` with only a minimum, so a confirmation widens the cap).
  progent-callable     progent-fixedappr + the neutral clauses the frozen adapter declares
                       untranslatable, written in Progent's OWN restriction language: secagent
                       `check_arg` accepts a Python Callable per argument (tool.py L514), and
                       JSON-schema `not`/`enum`. Callables read `observe()`, exactly as the frozen
                       CaMeL adapter's policies do. No new enforcement point is added; every
                       decision is still secagent._check_tool_call.
  morrison-nodomains   Morrison with only the translated neutral policy plus its kernel
                       mechanisms: the five default starter Omega domains (domains.py: "starter
                       rules ... deployments define their own") are not loaded.
"""

from __future__ import annotations

import dataclasses
import json
import re
import threading

from agentdojo.functions_runtime import TaskEnvironment
from camel.capabilities import Capabilities, can_readers_read_value, is_trusted, readers, sources
from camel.pipeline_elements.agentdojo_function import AgentDojoFunction
from camel.security_policy import Allowed, Denied, SecurityPolicyDeniedError

from arsb.adapters import camel_adapter as CA
from arsb.adapters import morrison as MA
from arsb.adapters import progent_adapter as PA
from arsb.core.adapter import Outcome
from arsb.core.fixture import Refused
from arsb.core.policy import allowed, needs_approval, present

CONFIRM = "__requires_user_confirmation__"


# ───────────────────────────── CaMeL ─────────────────────────────
class _Engine(CA.ArsbPolicyEngine):
    def __init__(self, adapter, principal, confirmed=False, labels=False, confirm_path=False):
        super().__init__(adapter, principal)
        self.confirmed, self.labels, self.confirm_path = confirmed, labels, confirm_path

    def check(self, tool, kwargs):
        raw = {k: CA._raw(v) for k, v in kwargs.items()}
        op = {"op": tool, "args": {("from" if k == "from_account" else k): v for k, v in raw.items()}}
        p = self.policy
        if p.get("allow") and not allowed(p, op):
            return Denied("no allow entry matches")
        for rule in p.get("provenance") or []:
            arg = CA._ARGMAP.get(tool, {}).get(rule["arg"], rule["arg"])
            if rule["op"] == tool and arg in kwargs and not is_trusted(kwargs[arg]):
                return Denied(f"{rule['arg']} does not come from the user")
        if tool == "send_email" and p.get("confidential_docs"):
            internal = p.get("internal_domain")
            to = str(raw["to"])
            is_internal = self.labels and internal and to.endswith("@" + internal)
            if not is_internal and not can_readers_read_value({to}, kwargs["body"]):
                return Denied("the recipient cannot read the body")
        if needs_approval(p, op):
            if not self.confirm_path:
                return Denied("requires user confirmation (not implemented in CaMeL's code; denied)")
            if not self.confirmed:
                return Denied(CONFIRM)
        # remaining clauses: identical to the frozen engine (owners, aggregate, flows, SoD)
        rest = dict(p)
        for k in ("allow", "provenance", "confidential_docs", "approval_required"):
            rest.pop(k, None)
        saved, self.policy = self.policy, rest
        try:
            return CA.ArsbPolicyEngine.check(self, tool, kwargs)
        finally:
            self.policy = saved


class _LabelledDocFn(AgentDojoFunction):
    """read_doc / read_doc_field with labels a deployer would declare for this store."""

    def wrap_output(self, value, args, kwargs, namespace):
        out = super().wrap_output(value, args, kwargs, namespace)
        a = CA._current["adapter"]
        raw = kwargs.raw if hasattr(kwargs, "raw") else {}
        doc_id = raw.get("id") if isinstance(raw, dict) else None
        doc = next((d for d in a.sc["initial"].get("docs") or [] if d["id"] == doc_id), None)
        trusted = bool(doc and doc.get("trusted"))
        conf = doc_id in ((a.sc.get("policy") or {}).get("confidential_docs") or [])
        inner = frozenset({sources.SourceEnum.TrustedToolSource}) if trusted else frozenset()
        rdrs = frozenset() if conf else readers.Public()
        return out.new_with_metadata(Capabilities(frozenset({sources.Tool(self.name().raw, inner)}), rdrs))


class _CaMeLVariant(CA.CaMeL):
    confirm_path = False
    labels = False

    def setup(self, scenario, executor, workdir):
        super().setup(scenario, executor, workdir)
        if self.labels:
            base = CA.ns.Namespace.with_builtins()
            adns = CA.make_agentdojo_namespace(base, CA.RUNTIME, TaskEnvironment())
            for n in ("read_doc", "read_doc_field"):
                old = adns[n]
                adns[n] = _LabelledDocFn(n, old._metadata, old._runtime, old._env)
            self._base = base.add_variables(adns)

    def submit(self, principal, op, ctx):
        CA._ep.principal = principal
        with self._lock:
            session = self.sessions.setdefault(principal, {"ns": self._base, "deps": []})
        confirmed = bool(isinstance(ctx.approval, dict) and ctx.approval.get("step") == ctx.step_id)
        eng = _Engine(self, principal, confirmed=confirmed, labels=self.labels, confirm_path=self.confirm_path)
        eval_args = CA.interpreter.EvalArgs(eng, CA.interpreter.MetadataEvalMode.NORMAL)
        try:
            res, new_ns, _c, deps = CA.interpreter.parse_and_interpret_code(
                self._program(op, ctx), session["ns"], [], session["deps"], eval_args)
        except SecurityPolicyDeniedError as exc:
            return self._denied(str(exc), ctx)
        except Refused as exc:
            return Outcome("refused", f"resource: {exc}")
        session["ns"], session["deps"] = new_ns, list(deps)
        err = getattr(res, "error", None)
        if err is not None:
            inner = getattr(err, "exception", err)
            if isinstance(inner, Refused):
                return Outcome("refused", f"resource: {inner}")
            return self._denied(f"{type(inner).__name__}: {inner}", ctx)
        return Outcome("executed")

    def _denied(self, msg, ctx):
        if CONFIRM in msg:
            return Outcome("deferred", "CaMeL asks the user to confirm (paper §5.4)", request={"step": ctx.step_id})
        return Outcome("refused", f"camel: {msg}"[:200])

    def approve(self, request, principal, op):
        return dict(request) if (self.confirm_path and isinstance(request, dict)) else None


class CaMeLConfirm(_CaMeLVariant):
    name = "camel-confirm"
    confirm_path = True


class CaMeLLabels(_CaMeLVariant):
    name = "camel-labels"
    labels = True


class CaMeLFaithful(_CaMeLVariant):
    name = "camel-faithful"
    confirm_path = True
    labels = True


# ───────────────────────────── Progent ─────────────────────────────
def _translate_fixed(policy):
    rules, untranslated = PA.translate(policy)
    for req in policy.get("approval_required") or []:
        lst = rules.get(req["op"], [])
        fixed = []
        for prio, eff, r, fb in lst:
            if eff == 1 and fb == 2:
                # find the allow entry this approval rule was derived from and keep its cap
                for e in policy.get("allow") or []:
                    if e["op"] == req["op"] and "max_amount" in e and PA._restrictions(e).get("from_account") == r.get("from_account") \
                            and PA._restrictions(e).get("to") == r.get("to"):
                        r = dict(r, amount={"type": "number", "minimum": req.get("min_amount", 0),
                                            "maximum": e["max_amount"]})
                        break
            fixed.append((prio, eff, r, fb))
        rules[req["op"]] = fixed
    return rules, untranslated


class ProgentFixedApproval(PA.Progent):
    name = "progent-fixedappr"

    def setup(self, scenario, executor, workdir):
        super().setup(scenario, executor, workdir)
        rules, self.untranslated = _translate_fixed(scenario.get("policy") or {})
        PA.ptool.update_security_policy(rules)


class ProgentCallable(PA.Progent):
    name = "progent-callable"

    def setup(self, scenario, executor, workdir):
        super().setup(scenario, executor, workdir)
        policy = scenario.get("policy") or {}
        rules, _ = _translate_fixed(policy)
        obs = self.observe
        translated = {"allow", "approval_required"}

        def transfers():
            return [e["args"] for e in obs()["effects"] if e["kind"] == "transfer"]  # pylint: disable=not-callable

        forbid = []   # (tool, restriction)
        for lim in policy.get("aggregate_limits") or []:
            acct, limit = lim["account"], lim["limit"]
            forbid.append(("transfer", {
                "from_account": {"type": "string", "enum": [acct]},
                "amount": (lambda amt, acct=acct, limit=limit:
                           sum(t["amount"] for t in transfers() if t["from"] == acct) + amt > limit)}))
            translated.add("aggregate_limits")
        for fl in policy.get("forbidden_flows") or []:
            def tainted_from(f, src=fl["src"]):
                t = {src}
                for x in transfers():
                    if x["from"] in t:
                        t.add(x["to"])
                return f in t
            forbid.append(("transfer", {"to": {"type": "string", "enum": [fl["dst"]]}, "from_account": tainted_from}))
            translated.add("forbidden_flows")
        for sod in policy.get("separation_of_duties") or []:
            ents = set(sod["entitlements"])
            for e in sorted(ents):
                def holds_rest(subj, rest=frozenset(ents - {e})):
                    held = {r for s, r in obs()["roles"] if s == subj}  # pylint: disable=not-callable
                    return rest <= held
                forbid.append(("grant_role", {"entitlement": {"type": "string", "enum": [e]}, "subject": holds_rest}))
            translated.add("separation_of_duties")
        tenants = {p["tenant"] for p in scenario.get("principals") or []}
        if policy.get("owners") and len(tenants) == 1:
            # one Progent policy per deployment: the deployment's own tenant (pure JSON schema)
            t = next(iter(tenants))
            owned = sorted(a for a, o in policy["owners"].items() if o == t)
            forbid.append(("transfer", {"from_account": {"not": {"enum": owned}}}))
            translated.add("owners")
        if policy.get("confidential_docs"):
            docs = {d["id"]: d for d in scenario["initial"].get("docs") or []}
            needles = []
            for did in policy["confidential_docs"]:
                d = docs.get(did) or {}
                needles += [str(v) for v in (d.get("fields") or {}).values() if len(str(v)) >= 6]
            internal = policy.get("internal_domain") or ""
            forbid.append(("send_email", {"to": {"type": "string", "not": {"pattern": "@" + re.escape(internal) + "$"}},
                                          "body": (lambda b, n=tuple(needles): any(x in str(b) for x in n))}))
            translated.add("confidential_docs")
        for tool, r in forbid:
            rules.setdefault(tool, []).append((0, 1, r, 0))
        self.untranslated = [c for c in present(policy) if c not in translated]
        PA.ptool.update_security_policy(rules)


# ───────────────────────────── Morrison ─────────────────────────────
class MorrisonNoDefaultDomains(MA.Morrison):
    name = "morrison-nodomains"

    def _kernel(self, principal):
        with _DOMAIN_LOCK:
            saved = MA.DOMAINS
            MA.DOMAINS = []
            try:
                return super()._kernel(principal)
            finally:
                MA.DOMAINS = saved


_DOMAIN_LOCK = threading.RLock()


class MorrisonScoped(MA.Morrison):
    """Morrison with SecurityContext.resource_scopes covering every resource a
    neutral clause reads (both accounts of a transfer; the subject of a grant),
    not only aggregate-limited accounts as the frozen adapter does. Uses the
    same documented G1 mechanism; adds no rule."""
    name = "morrison-scoped"

    def setup(self, scenario, executor, workdir):
        super().setup(scenario, executor, workdir)
        policy = scenario.get("policy") or {}
        if policy.get("aggregate_limits") or policy.get("forbidden_flows") or policy.get("separation_of_duties"):
            def scopes(call):
                a = call.get("args") or {}
                if call.get("tool") == "transfer":
                    return [f"account:{a.get('from')}", f"account:{a.get('to')}"]
                if call.get("tool") == "grant_role":
                    return [f"subject:{a.get('subject')}"]
                return []
            self.scopes = scopes


class MorrisonScopedMediated(MorrisonScoped):
    name = "morrison-scoped-mediated"
    mediated = True
