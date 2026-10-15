"""Morrison Runtime Governance adapter (uses the repository's kernel unmodified).

Two configurations, both documented Morrison deployments:

  morrison           GovernanceKernel.authorize -> execute in the agent's process. No
                     resource-side check: a route that bypasses the kernel is not stopped.
  morrison-mediated  Every PERMIT is exported as an Ed25519 execution lease
                     (kernel.mint_lease); the resource verifies the lease on EVERY
                     mutation (mediation.LeaseVerifier + a shared SQLite registry).

Policy translation (the full translation is in `translate`):
  allow                 -> custom Omega rule: BLOCK any mutating call matching no entry
  approval_required     -> payment_auto_approve_max = min_amount - 1 (Morrison's capability
                           policy escalates payments above it); approvals via issue_approval
  aggregate_limits      -> custom aggregate rule + SecurityContext.resource_scopes (G1 repair)
  forbidden_flows       -> custom flow-path rule over the governed trajectory
  separation_of_duties  -> custom rule over the governed trajectory PLUS entitlements already held,
                           supplied per request as SecurityContext.trusted_facts from resource state
                           (the documented remedy for T3b; without it the rule is blind to them)
  owners                -> owned_resource_args + resource_tenants (E12 repair)
  confidential_docs     -> internal_email_domains; Morrison's built-in egress-after-read rules
  provenance            -> SecurityContext.argument_provenance {op: (arg,)} with output_trust read
                           from the resource's own classification of what it returned (a document's
                           `trusted` flag). Value-level taint over recorded outputs (adapter revision r2,
                           after the Morrison repair; v0 frozen adapter listed it as untranslated).

Each principal gets its own kernel (its own identity and session); all kernels share one
continuity store, which is what Morrison's cross-agent guarantee requires.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import secrets
from pathlib import Path

from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule
from morrison_governance._ed25519_test_signer import public_key, sign
from morrison_governance.kernel import (GovernanceKernel, LeaseVerifier, SQLiteLeaseStore,
                                        issue_approval)
from morrison_governance.kernel.attestation import recompute_chain
from morrison_governance.kernel.canonical import canonicalize
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.trust import Principal, SecurityContext

from arsb.core.adapter import Adapter, Outcome
from arsb.core.fixture import Refused
from arsb.core.policy import allowed, present

DOMAINS = [OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY, OmegaDomain.DATA_PRIVACY,
           OmegaDomain.ENTERPRISE, OmegaDomain.COMPLIANCE]
MANIFEST = {"transfer": ["payment.move_funds"], "grant_role": ["iam.privileged"],
            "send_email": ["data.external_move"], "set_password": ["credential.change"],
            "read_doc": ["data.read"]}
ISSUER = "arsb-approver"
MUTATING = ("transfer", "grant_role", "send_email", "set_password")


def _call(op: dict) -> dict:
    return {"tool": op["op"], "args": dict(op.get("args") or {})}


def _op(call: dict) -> dict:
    return {"op": call["tool"], "args": dict(call.get("args") or {})}


def _state_args(state: dict) -> tuple:
    a = state.get("args")
    return state.get("tool"), (json.loads(a) if isinstance(a, str) else a or {})


def _prior(state: dict):
    for i in range(int(state.get("step", 0))):
        yield state.get(f"step_{i}_tool"), state.get(f"step_{i}_args") or {}


def _debit(v, limit):
    try:
        return max(0, math.ceil(v))
    except (TypeError, ValueError, OverflowError):
        return limit + 1


def _output_trust(call: dict, result) -> bool:
    """Whether an executed call's output is a trusted source: the resource's own
    classification of the document it returned (anything else is untrusted)."""
    read = (result or {}).get("read") if isinstance(result, dict) else None
    return bool(read and read.get("trusted"))


def translate(policy: dict) -> tuple[list, list]:
    rules, untranslated = [], []
    if policy.get("allow"):
        def allow_check(state, policy=policy):
            tool, args = _state_args(state)
            return tool in MUTATING and not allowed(policy, {"op": tool, "args": args})
        rules.append(OmegaRule(OmegaDomain.CUSTOM, "arsb_allowlist", "call matches no allow entry", allow_check))
    for lim in policy.get("aggregate_limits") or []:
        def agg(state, src=lim["account"], limit=lim["limit"]):
            tool, args = _state_args(state)
            if tool != "transfer" or args.get("from") != src:
                return False
            total = sum(_debit(a.get("amount"), limit) for t, a in _prior(state)
                        if t == "transfer" and a.get("from") == src)
            return total + _debit(args.get("amount"), limit) > limit
        rules.append(OmegaRule(OmegaDomain.CUSTOM, f"arsb_aggregate_{lim['account']}", "aggregate limit", agg))
    for fl in policy.get("forbidden_flows") or []:
        def flow(state, src=fl["src"], dst=fl["dst"]):
            tool, args = _state_args(state)
            if tool != "transfer" or args.get("to") != dst:
                return False
            tainted = {src}
            for t, a in _prior(state):
                if t == "transfer" and a.get("from") in tainted:
                    tainted.add(a.get("to"))
            return args.get("from") in tainted
        rules.append(OmegaRule(OmegaDomain.CUSTOM, f"arsb_flow_{fl['src']}_{fl['dst']}", "forbidden flow", flow))
    for sod in policy.get("separation_of_duties") or []:
        def sod_check(state, ents=frozenset(sod["entitlements"])):
            tool, args = _state_args(state)
            if tool != "grant_role":
                return False
            who = args.get("subject")
            held = {a.get("entitlement") for t, a in _prior(state)
                    if t == "grant_role" and a.get("subject") == who}
            # entitlements held before the governed trajectory, supplied by the
            # deployment as trusted facts (the documented remedy for T3b)
            held |= set((state.get("held_entitlements") or {}).get(who, []))
            return ents <= held | {args.get("entitlement")}
        rules.append(OmegaRule(OmegaDomain.CUSTOM, "arsb_sod", "separation of duties", sod_check))
    return rules, untranslated


class Morrison(Adapter):
    name = "morrison"
    mechanisms = frozenset({"pre_execution_veto", "per_call_policy", "trajectory_rules",
                            "cross_agent_shared_state", "single_use_approvals", "action_binding",
                            "decision_evidence", "tenant_registry", "approvals", "fail_closed"})
    mediated = False

    def setup(self, scenario, executor, workdir):
        self.sc, self.exec, self.workdir = scenario, executor, Path(workdir)
        policy = scenario.get("policy") or {}
        self.rules, self.untranslated = translate(policy)
        self.store = InMemoryContinuityStore()
        self.key = secrets.token_bytes(32)
        mins = [r.get("min_amount", 0) for r in policy.get("approval_required") or [] if r["op"] == "transfer"]
        self.auto_max = (min(mins) - 1) if mins else 10 ** 12
        self.owners = dict(policy["owners"]) if policy.get("owners") else None
        scoped = {lim["account"] for lim in policy.get("aggregate_limits") or []}
        self.scopes = ((lambda call: [f"account:{call['args']['from']}"]
                        if call.get("tool") == "transfer" and call.get("args", {}).get("from") in scoped else [])
                       if scoped else None)
        self.internal = (policy.get("internal_domain"),) if policy.get("internal_domain") else ()
        self.provenance = {}
        for rule in policy.get("provenance") or []:
            if rule.get("must_come_from", "request") == "request":
                self.provenance.setdefault(rule["op"], ())
                self.provenance[rule["op"]] += (rule["arg"],)
        self.kernels = {}
        self._fault = None
        if self.mediated:
            self._seed = secrets.token_bytes(32)
            self.leases = SQLiteLeaseStore(self.workdir / "leases.db")
            self.verifier = LeaseVerifier(public_key(self._seed), self.leases)

    def _kernel(self, principal):
        if principal not in self.kernels:
            tenant = next(p["tenant"] for p in self.sc["principals"] if p["id"] == principal)
            ctx = SecurityContext(
                principal=Principal(id=principal, tenant=tenant), continuity_store=self.store,
                tool_manifest={k: list(v) for k, v in MANIFEST.items()},
                policy_values={"payment_auto_approve_max": self.auto_max},
                signing_key=self.key, trusted_issuers=frozenset({ISSUER}),
                internal_email_domains=self.internal,
                resource_scopes=self.scopes,
                owned_resource_args={"transfer": ("from",)} if self.owners is not None else {},
                resource_tenants=self.owners,
                argument_provenance=self.provenance,
                output_trust=_output_trust,
                lease_signer=(lambda m: sign(self._seed, m)) if self.mediated else None,
                lease_store=self.leases if self.mediated else None)
            layer = GovernanceLayer(domains=DOMAINS, custom_rules=list(self.rules), log_all=False)
            k = GovernanceKernel(layer, ctx)
            if self._fault:
                self._break(k, self._fault)
            self.kernels[principal] = k
        return self.kernels[principal]

    # ── proposer interface ───────────────────────────────────
    def submit(self, principal, op, ctx):
        k = self._kernel(principal)
        call = _call(op)
        facts = {}
        observe = self.observe
        if (self.sc.get("policy") or {}).get("separation_of_duties") and callable(observe):
            held = {}
            for subj, ent in observe()["roles"]:  # pylint: disable=not-callable
                held.setdefault(subj, []).append(ent)
            facts = {"held_entitlements": held}
        k.ctx = dataclasses.replace(k.ctx, approvals=(ctx.approval,) if ctx.approval is not None else (),
                                    trusted_facts=facts)
        try:
            d = k.authorize(call)
        except Exception as exc:                       # noqa: BLE001 - fail-closed result
            return Outcome("refused", f"authorize raised {type(exc).__name__}")
        finally:
            k.ctx = dataclasses.replace(k.ctx, approvals=())
        if d.escalated:
            return Outcome("deferred", f"ESCALATE {d.layer}/{d.rule}", request=d.decision_id,
                           decision_ref=d.decision_id)
        if not d.permitted:
            return Outcome("refused", f"{d.verdict} {d.layer}/{d.rule}", decision_ref=d.decision_id)
        if self.mediated:
            try:
                lease = k.mint_lease(d)
            except Exception as exc:                   # noqa: BLE001
                return Outcome("refused", f"lease not issued: {exc}"[:200])
            token = lease.encode()
            try:
                result = self.exec(_op(d.action), principal, lease.lease_id, token)
                k.record_output(d.action, result)     # a remote execution reports its output
                return Outcome("executed", decision_ref=lease.lease_id, token=token)
            except Refused as exc:
                return Outcome("refused", f"resource: {exc}", token=token)
        box = {}

        def run(target):
            box["effect"] = self.exec(_op(target), principal, d.decision_id, None)
            return box["effect"]
        try:
            ok, out = k.execute(d, run)
        except Refused as exc:                         # pragma: no cover - execute catches
            return Outcome("refused", f"resource: {exc}")
        if ok and "effect" in box:
            return Outcome("executed", decision_ref=d.decision_id)
        return Outcome("refused", str(out)[:200], decision_ref=d.decision_id)

    def approve(self, request, principal, op):
        return issue_approval(canonicalize(_call(op)), ISSUER, self.key, ttl_s=120.0,
                              nonce=secrets.token_hex(12))

    def forge_approval(self, principal, op):
        return issue_approval(canonicalize(_call(op)), ISSUER, secrets.token_bytes(32),
                              ttl_s=120.0, nonce=secrets.token_hex(12))

    # ── resource side ────────────────────────────────────────
    def resource_guard(self):
        if not self.mediated:
            return None

        def guard(op, token):
            if not isinstance(token, str):
                return False, "no execution lease"
            call = _call(op)
            if canonicalize(call) != call:
                return False, "request not in canonical form"
            return self.verifier.verify(token, call)
        return guard

    # ── faults ───────────────────────────────────────────────
    def _break(self, k, kind):
        def boom(*a, **kw):
            raise RuntimeError(f"{kind} unavailable")
        if kind == "decision_store":
            for m in ("consume", "consumed", "entries", "append", "set_state"):
                setattr(k.store, m, boom)
        elif kind == "evidence":
            k.chain.append = boom
        elif kind == "approval_verifier":
            k.ctx = dataclasses.replace(k.ctx, signing_key=b"")

    def inject_fault(self, kind):
        if kind not in ("decision_store", "evidence", "approval_verifier"):
            return False
        self._fault = kind
        if kind == "decision_store":
            # the store is shared: break it once for every kernel, present and future
            def boom(*a, **kw):
                raise RuntimeError("decision store unavailable")
            for m in ("consume", "consumed", "entries", "append", "set_state"):
                setattr(self.store, m, boom)
            self._fault = None
        for k in self.kernels.values():
            if self._fault:
                self._break(k, self._fault)
        return True

    # ── evidence ─────────────────────────────────────────────
    def export_evidence(self):
        blocks = {p: k.chain.to_jsonl() for p, k in sorted(self.kernels.items())}
        return json.dumps(blocks, sort_keys=True).encode()

    def verify_evidence(self, blob):
        try:
            blocks = json.loads(blob)
            return all(recompute_chain(v).ok for v in blocks.values())
        except Exception:                              # noqa: BLE001 - unreadable = not verified
            return False

    def evidence_refs(self, blob):
        refs = set()
        for jsonl in json.loads(blob).values():
            for line in jsonl.splitlines():
                rec = json.loads(line)
                if rec.get("layer") == "execution_intent":
                    refs.add((rec.get("authorization") or {}).get("decision_id"))
                if rec.get("rule") == "execution_authority_exported":
                    lease_id = rec.get("reason", "").split()[2] if rec.get("reason") else ""
                    refs.add(lease_id)
        return refs


class MorrisonMediated(Morrison):
    name = "morrison-mediated"
    mechanisms = Morrison.mechanisms | {"resource_side_enforcement"}
    mediated = True
