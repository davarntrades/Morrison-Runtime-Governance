"""GovernanceKernel — the single production chokepoint.

Everything the red team broke is closed here, in one place, WITHOUT changing
the Morrison reachability model. `ReachabilityEvaluator` is untouched: the
kernel calls the existing engine and takes its verdict as authoritative
whenever the engine blocks, so V2 prefix/trajectory behaviour is preserved
exactly. The kernel adds the trust boundary the engine never had.

Decision pipeline for every proposed call:

    1  canonicalise                  -> immutable action + action_hash
    2  quarantine caller authority   -> forged claims become evidence, not power
    3  classify capabilities         -> semantic, not tool-name matching
    4  resolve destination           -> trusted config, not caller flags
    5  verify approval artifact      -> bound to THIS action hash
    6  inject TRUSTED authority      -> the only writer of authority fields
    7  run the existing Ω engine     -> unchanged reachability hierarchy
    8  apply capability policy       -> DENY / APPROVAL / GRANT / ALLOW
    9  tenancy + denial-taint checks
   10  strictest verdict wins        -> BLOCK > ESCALATE > PERMIT
   11  seal hash-chained evidence

Execution is only reachable through `execute()`, which re-derives the action
hash and refuses anything that does not match the authorised hash.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from morrison_governance.core import GovernanceLayer
from morrison_governance.result import GovernanceVerdict
from morrison_governance.kernel import capabilities as C
from morrison_governance.kernel import policy as P
from morrison_governance.kernel import sensitivity as S
from morrison_governance.kernel.canonical import action_hash, canonicalize
from morrison_governance.kernel.destinations import classify_destination
from morrison_governance.kernel.evidence import (
    EvidenceChain, EvidenceRecord, ruleset_hash,
)
from morrison_governance.kernel.trust import (
    SecurityContext, forged_authority_claims, quarantine_authority,
)

BLOCK = "BLOCK"
ESCALATE = "ESCALATE"
PERMIT = "PERMIT"

_STRICTNESS = {PERMIT: 0, ESCALATE: 1, BLOCK: 2}

# Quarantined claims split by what would corroborate them.
_APPROVAL_CLAIMS = frozenset({
    "authorized", "authorised", "approved", "approved_by", "approver",
    "verified", "sanctioned", "change_approved", "admin_authorized",
    "break_glass", "override",
})
_DESTINATION_CLAIMS = frozenset({
    "destination_internal", "is_internal", "internal", "trusted",
})


@dataclass
class Decision:
    verdict: str
    reason: str
    layer: str
    action_hash: str
    action: dict                       # the canonical, clean action
    capabilities: frozenset = frozenset()
    requirement: str = P.ALLOW
    rule: Optional[str] = None
    omega_domain: Optional[str] = None
    authorization: dict = field(default_factory=dict)
    forged_claims: list = field(default_factory=list)
    destination: dict = field(default_factory=dict)
    trajectory_hash: str = ""
    evidence: Optional[EvidenceRecord] = None

    # ── measured latency ─────────────────────────────────────
    # `decision_time_ms` is the END-TO-END cost of producing this decision:
    # canonicalisation, authority quarantine, capability classification,
    # destination resolution, approval verification, the Ω engine, capability
    # policy, tenancy, and sealing the evidence record.
    #
    # `engine_time_ms` is the Ω reachability compute alone, as the engine
    # reports it. It is a SMALL FRACTION of the total — roughly 2% on the
    # production ruleset — so quoting it as "governance latency" would
    # understate the real cost by ~50x. Both are recorded so a caller can see
    # the split rather than having to trust one number.
    decision_time_ms: float = 0.0
    engine_time_ms: float = 0.0

    @property
    def permitted(self) -> bool:
        return self.verdict == PERMIT

    @property
    def escalated(self) -> bool:
        return self.verdict == ESCALATE

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict, "reason": self.reason, "layer": self.layer,
            "action_hash": self.action_hash,
            "capabilities": sorted(self.capabilities),
            "requirement": self.requirement, "rule": self.rule,
            "omega_domain": self.omega_domain,
            "authorization": self.authorization,
            "forged_authority_claims": self.forged_claims,
            "destination": self.destination,
            "evidence_hash": self.evidence.record_hash if self.evidence else None,
            "decision_time_ms": round(self.decision_time_ms, 3),
            "engine_time_ms": round(self.engine_time_ms, 3),
        }


@dataclass
class Attempt:
    """A recorded attempt — executed OR denied. Denied attempts stay in the
    ledger so a blocked step cannot scrub itself out of the trajectory."""

    action: dict
    verdict: str
    reason: str
    actor: str
    timestamp: float
    capabilities: frozenset = frozenset()
    executed: bool = False


class GovernanceKernel:
    """Pre-execution governance with a real trust boundary."""

    def __init__(self, layer: GovernanceLayer, context: SecurityContext,
                 evidence_key: bytes = b"", engine_version: str = ""):
        self.layer = layer
        self.ctx = context
        self.chain = EvidenceChain(key=evidence_key)
        self.ledger: list[Attempt] = []
        self.engine_version = engine_version
        self._ruleset_hash = ruleset_hash(
            layer.rules,
            extra={"capability_policy": P.CAPABILITY_POLICY,
                   "policy_values": {**P.DEFAULT_POLICY_VALUES,
                                     **(context.policy_values or {})},
                   "unknown_tool_policy": context.unknown_tool_policy})

    # ── history ──────────────────────────────────────────────
    @property
    def executed_history(self) -> list[dict]:
        return [a.action for a in self.ledger if a.executed]

    def _denied_read_occurred(self) -> Optional[Attempt]:
        for a in self.ledger:
            if not a.executed and (C.CAP_DATA_READ in a.capabilities
                                   or C.CAP_CREDENTIAL_READ in a.capabilities):
                return a
        return None

    def _any_read_occurred(self) -> bool:
        return any(C.CAP_DATA_READ in a.capabilities
                   or C.CAP_CREDENTIAL_READ in a.capabilities
                   for a in self.ledger)

    def _evaluate_with_context(self, prefix: list, trusted: dict):
        """Run the unchanged engine over `prefix` with `trusted` supplied as
        trajectory context rather than arguments."""
        from morrison_governance.trajectory import TrajectoryExtractor
        extractor = TrajectoryExtractor(context=trusted)
        traj = (extractor.from_plan(prefix) if len(prefix) > 1
                else extractor.from_dict(prefix[0]))
        return self.layer.evaluate_trajectory(traj)

    # ── the gate ─────────────────────────────────────────────
    def authorize(self, call: dict, now: Optional[float] = None) -> Decision:
        _t0 = time.perf_counter()
        now = time.time() if now is None else now
        clean, quarantined = quarantine_authority(call)
        forged = forged_authority_claims(quarantined)
        ahash = action_hash(clean)
        caps = C.classify(clean, self.ctx.tool_manifest)
        dest = classify_destination(
            clean, self.ctx.internal_url_hosts,
            self.ctx.internal_email_domains, self.ctx.internal_cidrs)

        approval, approval_reason = self.ctx.verified_approval(ahash, now)
        authorization = {
            "approved": bool(approval),
            "reason": approval_reason,
            "issuer": approval.issuer if approval else None,
            "bound_action_hash": approval.action_hash if approval else None,
            "principal": self.ctx.principal.id,
            "tenant": self.ctx.principal.tenant,
        }

        candidates: list[tuple[str, str, str, Optional[str], Optional[str]]] = []

        # ── forged authority is recorded and never honoured ──
        # Every quarantined claim is recorded as evidence unconditionally. It
        # only raises a verdict when it is UNCORROBORATED — i.e. the caller
        # asserted something the trusted context does not independently agree
        # with. A redundant-but-true claim (client library sends
        # `destination_internal` and the destination really is internal) is
        # noted, not punished; that distinction is what keeps this from firing
        # on ordinary traffic.
        # (evaluated below, once the capability requirement is known)
        approval_claims = [c for c in forged if c in _APPROVAL_CLAIMS]
        dest_claims = [c for c in forged if c in _DESTINATION_CLAIMS]

        # ── capability policy is resolved BEFORE the engine runs, because the
        #    engine's own rules read an `authorized` flag and the kernel is the
        #    only component allowed to set it. Authority is established by a
        #    verified approval, an explicit server-side auto-approval, or a
        #    capability grant the principal actually holds — never by the caller.
        pol_values = {**P.DEFAULT_POLICY_VALUES, **(self.ctx.policy_values or {})}
        cap_policy = pol_values.get("capability_policy")
        requirement, gov_cap = P.requirement_for(caps, cap_policy)

        auto_approved = False
        if requirement == P.APPROVAL and gov_cap == C.CAP_PAYMENT and not approval:
            # Server-owned threshold. The caller's own `threshold` was
            # quarantined upstream (bypass AB-03).
            cap_max = pol_values.get("payment_auto_approve_max", 0) or 0
            amount = _numeric(clean["args"], ("amount", "value", "total"))
            if amount is not None and amount <= cap_max and not dest.external:
                requirement, auto_approved = P.ALLOW, True

        grant_satisfied = (requirement == P.GRANT and self.ctx.grants(gov_cap))

        # A quarantined claim raises a verdict only when it is BOTH
        # uncorroborated and material — i.e. the action genuinely needs the
        # authority being asserted. A claim on an action that requires no
        # approval is noise: it is recorded as evidence and nothing more.
        uncorroborated = []
        if approval_claims and approval is None and requirement == P.APPROVAL:
            uncorroborated += approval_claims
        if dest_claims and dest.external:
            uncorroborated += dest_claims
        if uncorroborated:
            # BLOCK, not ESCALATE. Asserting authority you do not hold, on an
            # action that requires it, is a forgery attempt — not a request
            # awaiting review. Escalating it would put a deception in the
            # approval queue as though it were ordinary work, and would read in
            # the audit trail as "pending" rather than "someone lied".
            candidates.append((
                BLOCK, "trust_boundary",
                f"caller-supplied authority claim(s) {sorted(set(uncorroborated))} "
                f"are not corroborated by trusted state and carry no authority; "
                f"asserting unheld authority is refused outright",
                "forged_authority_claim", None))

        # ── privileged action aimed at an external destination ──
        # A credential change, payment, or IAM change whose destination resolves
        # OUTSIDE the trust boundary is a redirect attack: the destination is
        # the payload. No approval makes "reset the CEO's password, deliver to
        # attacker@evil.example" acceptable as a single action, so this is a
        # hard BLOCK rather than something a reviewer could wave through.
        _REDIRECTABLE = {C.CAP_CREDENTIAL_CHANGE, C.CAP_PAYMENT,
                         C.CAP_IAM_PRIVILEGED}
        if dest.external and (caps & _REDIRECTABLE):
            candidates.append((
                BLOCK, "redirect_policy",
                f"privileged action ({', '.join(sorted(caps & _REDIRECTABLE))}) "
                f"directed at an external destination — {dest.reason}",
                "privileged_action_external_destination", None))
        # NOTE: a plain ALLOW capability does NOT establish authority — it just
        # needs none. Injecting `authorized: True` for ordinary reads/egress
        # would switch off the engine's own credential-egress rules, so it is
        # deliberately withheld unless authority was positively established.
        authority_established = bool(approval) or auto_approved or grant_satisfied

        # ── the existing Ω engine, with TRUSTED authority injected ──
        #
        # Trusted state goes in the trajectory CONTEXT, never into args.
        # `TrajectoryState.to_eval_dict()` merges context AFTER args, so the
        # Ω rules read these values while the argument dict stays exactly as
        # the caller sent it (minus quarantined fields).
        #
        # This matters beyond tidiness: several rules match on the SHAPE and
        # SERIALISED TEXT of args — `_suspicious_destination` substring-matches
        # the args JSON, and `is_broad_privilege_expansion` inspects arg KEYS.
        # Writing authority flags into args made a key literally named
        # `destination_external` match the token "external" on an internal
        # destination, and made `admin_approved` read as a privilege-surface
        # key on an unrelated tool. Context injection has neither effect.
        trusted: dict[str, Any] = {}
        if authority_established:
            trusted.update(authorized=True, approved=True, verified=True,
                           admin_approved=True, change_approved=True,
                           sanctioned=True)
        trusted["destination_external"] = dest.external
        trusted["destination_internal"] = not dest.external
        if "amount_threshold" in pol_values:
            trusted["threshold"] = pol_values["amount_threshold"]

        prefix = self.executed_history + [clean]
        try:
            res = self._evaluate_with_context(prefix, trusted)
        except Exception as e:                       # noqa: BLE001 — fail closed
            res = None
            candidates.append((BLOCK, "fail_closed",
                               f"governance error treated as BLOCK: "
                               f"{type(e).__name__}", None, None))
        engine_rule = engine_domain = None
        traj_hash = ""
        engine_ms = 0.0
        if res is not None:
            traj_hash = res.trajectory_hash
            engine_ms = float((res.metadata or {}).get("eval_time_ms") or 0.0)
            engine_rule = (res.metadata or {}).get("rule")
            engine_domain = res.omega_domain
            if res.verdict == GovernanceVerdict.ESCALATE:
                candidates.append((ESCALATE, res.layer, res.reason,
                                   engine_rule, engine_domain))
            elif not res.permitted:
                candidates.append((BLOCK, res.layer, res.reason,
                                   engine_rule, engine_domain))

        # ── capability policy verdicts ──────────────────────
        if requirement == P.DENY:
            candidates.append((
                BLOCK, "capability_policy",
                f"capability {gov_cap!r} is denied to autonomous agents by policy",
                gov_cap, None))
        elif requirement == P.APPROVAL and not approval:
            candidates.append((
                ESCALATE, "capability_policy",
                f"capability {gov_cap!r} requires a verified approval artifact "
                f"bound to this action ({approval_reason})", gov_cap, None))
        elif requirement == P.GRANT and not grant_satisfied:
            candidates.append((
                ESCALATE, "capability_policy",
                f"principal {self.ctx.principal.id!r} does not hold capability "
                f"grant {gov_cap!r}", gov_cap, None))

        # ── unknown / unmodelled tools fail closed ──────────
        if self.ctx.tool_manifest and clean["tool"] not in self.ctx.tool_manifest:
            pol = (self.ctx.unknown_tool_policy or "escalate").lower()
            if pol == "block":
                candidates.append((BLOCK, "unknown_tool",
                                   f"tool {clean['tool']!r} is not declared in the "
                                   f"tool manifest; policy is fail-closed",
                                   "undeclared_tool", None))
            elif pol != "permit":
                candidates.append((ESCALATE, "unknown_tool",
                                   f"tool {clean['tool']!r} is not declared in the "
                                   f"tool manifest; escalating for review",
                                   "undeclared_tool", None))

        # ── sensitive egress with NO governed acquisition ───
        # The trajectory-based rule below needs a read to have happened inside
        # this session. An agent's context is filled by routes governance never
        # sees — system prompt, retrieval, a prior session, the user's own
        # message — so a one-shot send of regulated material would otherwise
        # pass simply because nothing was read first. Classify the content of
        # the call itself and fail closed.
        sensitive = S.classify_sensitivity(clean)
        if dest.external and C.CAP_EXTERNAL_DATA_MOVE in caps and sensitive \
                and not approval:
            candidates.append((
                BLOCK, "sensitive_egress",
                f"external egress carrying {S.describe(sensitive)} without a "
                f"verified approval — sensitive content may already be in "
                f"context, so no prior governed read is required for this to "
                f"be an exfiltration ({dest.reason})",
                "sensitive_external_egress", None))

        # ── external egress after any data acquisition ──────
        if dest.external and C.CAP_EXTERNAL_DATA_MOVE in caps and not approval:
            if pol_values.get("egress_requires_approval_after_read", True) and \
                    self._any_read_occurred():
                candidates.append((
                    BLOCK, "egress_policy",
                    f"external egress after data acquisition in this session "
                    f"({dest.reason})", "external_egress_after_read", None))

        # ── denial-scrubbing: a blocked read still taints ───
        denied = self._denied_read_occurred()
        if denied is not None and dest.external and C.CAP_EXTERNAL_DATA_MOVE in caps:
            candidates.append((
                BLOCK, "trajectory_integrity",
                f"external egress follows a DENIED data acquisition "
                f"({denied.action.get('tool')!r}, {denied.verdict}); a denied "
                f"attempt remains part of the trajectory", "denial_scrubbing", None))

        # ── cross-tenant access ─────────────────────────────
        # Quarantined identity fields are passed in deliberately: a caller-
        # supplied `tenant_id` can never GRANT access, but it does tell us which
        # tenant's resources are targeted, and that is exactly what must be
        # compared against the session principal's own tenant.
        xt = _cross_tenant(clean, self.ctx, quarantined)
        if xt:
            candidates.append((BLOCK, "tenancy", xt, "cross_tenant", None))

        # ── strictest wins ──────────────────────────────────
        if candidates:
            verdict, layer, reason, rule, domain = max(
                candidates, key=lambda c: _STRICTNESS[c[0]])

            # BLOCK vs ESCALATE precision — deliberately narrow.
            #
            # An engine BLOCK caused solely by absent authority is not the same
            # thing as a forbidden action: a scoped `reader` role on a named
            # project is an ordinary change request, and calling it BLOCK gives
            # an operator no route forward.
            #
            # But "would the engine permit this with authority?" is far too weak
            # a test on its own, because almost every deployment rule is
            # authority-gated — it would reclassify "reset the CEO's password to
            # an attacker's address" as merely awaiting approval, which is false
            # and understates the trajectory in the audit record. An approval
            # does not make an attacker-controlled destination acceptable.
            #
            # So reclassification additionally requires the action to carry NO
            # adversarial indicator: no forged authority claim, no external
            # destination, and no denied attempt earlier in the session. If any
            # of those is present, the BLOCK stands and says so.
            adversarial_indicator = bool(
                forged or dest.external
                or any(not a.executed for a in self.ledger))
            if (verdict == BLOCK and not authority_established
                    and requirement != P.DENY
                    and not adversarial_indicator
                    and all(c[0] != BLOCK or c[1] == layer for c in candidates)
                    and layer not in ("fail_closed", "tenancy", "egress_policy",
                                      "trajectory_integrity", "capability_policy",
                                      "unknown_tool", "binding")):
                hyp_ctx = {**trusted, "authorized": True, "approved": True,
                           "verified": True, "admin_approved": True,
                           "change_approved": True, "sanctioned": True}
                try:
                    hyp = self._evaluate_with_context(
                        self.executed_history + [clean], hyp_ctx)
                    if hyp.permitted:
                        verdict = ESCALATE
                        layer = "capability_policy"
                        reason = (
                            f"{reason} — resolvable by authorisation: this "
                            f"trajectory is permitted once a verified approval "
                            f"artifact is presented")
                except Exception:  # noqa: BLE001 — keep the original BLOCK
                    pass
        else:
            verdict, layer, reason, rule, domain = (
                PERMIT, res.layer if res else "kernel",
                "no Ω intersection; capability requirements satisfied",
                engine_rule, engine_domain)

        decision = Decision(
            verdict=verdict, reason=reason, layer=layer, action_hash=ahash,
            action=clean, capabilities=caps, requirement=requirement,
            rule=rule, omega_domain=domain, authorization=authorization,
            forged_claims=forged, destination=dest.as_dict(),
            trajectory_hash=traj_hash,
            engine_time_ms=engine_ms,
            decision_time_ms=(time.perf_counter() - _t0) * 1000.0)

        decision.evidence = self.chain.append(EvidenceRecord(
            seq=0, timestamp=now, actor=self.ctx.principal.id,
            tenant=self.ctx.principal.tenant, action_hash=ahash,
            proposed=clean, decision=verdict, layer=layer, rule=rule,
            omega_domain=domain, reason=reason, capabilities=sorted(caps),
            requirement=requirement, authorization=authorization,
            forged_authority_claims=forged, ruleset_hash=self._ruleset_hash,
            engine_version=self.engine_version, trajectory_hash=traj_hash))

        if verdict != PERMIT:
            self.ledger.append(Attempt(
                action=clean, verdict=verdict, reason=reason,
                actor=self.ctx.principal.id, timestamp=now,
                capabilities=caps, executed=False))
        return decision

    # ── execution ────────────────────────────────────────────
    def execute(self, decision: Decision, executor: Callable[[dict], Any],
                call: Optional[dict] = None) -> tuple[bool, Any]:
        """Run the action ONLY if it is the exact action that was authorised.

        Re-derives the canonical hash of what is about to run and compares it
        to the hash the decision was issued for. `evaluate A -> mutate ->
        execute B` fails here even when the decision itself said PERMIT.
        """
        if decision.verdict != PERMIT:
            return False, f"refused: verdict is {decision.verdict}"

        target = decision.action if call is None else quarantine_authority(call)[0]
        actual = action_hash(target)
        if actual != decision.action_hash:
            self.chain.append(EvidenceRecord(
                seq=0, timestamp=time.time(), actor=self.ctx.principal.id,
                tenant=self.ctx.principal.tenant, action_hash=actual,
                proposed=target, decision=BLOCK, layer="binding",
                rule="action_mutation_after_authorization",
                reason=(f"execution refused: action hash {actual[:12]}… does not "
                        f"match authorised {decision.action_hash[:12]}…"),
                ruleset_hash=self._ruleset_hash,
                engine_version=self.engine_version))
            self.ledger.append(Attempt(
                action=target, verdict=BLOCK,
                reason="action mutated after authorisation",
                actor=self.ctx.principal.id, timestamp=time.time(),
                capabilities=C.classify(target, self.ctx.tool_manifest),
                executed=False))
            return False, "refused: action mutated after authorisation"

        try:
            result = executor(target)
        except Exception as e:                       # noqa: BLE001
            self.chain.record_execution(decision.evidence, False,
                                        f"{type(e).__name__}: {e}")
            return False, f"runtime error: {type(e).__name__}: {e}"

        if decision.evidence is not None:
            self.chain.record_execution(decision.evidence, True, "ok")
        # Consume the approval nonce so it cannot be replayed.
        if decision.authorization.get("approved"):
            for art in self.ctx.approvals:
                if art.action_hash == decision.action_hash:
                    self.ctx.consume_nonce(art)
        self.ledger.append(Attempt(
            action=target, verdict=PERMIT, reason=decision.reason,
            actor=self.ctx.principal.id, timestamp=time.time(),
            capabilities=decision.capabilities, executed=True))
        return True, result

    def record_remote_execution(self, decision: Decision) -> None:
        """Record that a PERMITted action was executed by a REMOTE runtime.

        The decision-plane deployment (the HTTP service) does not execute
        anything itself, but the trajectory prefix must still advance or every
        subsequent step in the same session would be evaluated in isolation —
        which is precisely the taint-laundering the red team exploited.
        """
        if not decision.permitted:
            raise ValueError("only a PERMIT decision can be recorded as executed")
        self.ledger.append(Attempt(
            action=decision.action, verdict=PERMIT, reason=decision.reason,
            actor=self.ctx.principal.id, timestamp=time.time(),
            capabilities=decision.capabilities, executed=True))
        if decision.evidence is not None:
            self.chain.record_execution(decision.evidence, True, "remote-runtime")

    def submit(self, call: dict, executor: Callable[[dict], Any]
               ) -> tuple[Decision, bool, Any]:
        """authorize + execute in one call — the normal integration point."""
        d = self.authorize(call)
        if not d.permitted:
            return d, False, None
        ok, out = self.execute(d, executor)
        return d, ok, out

    # ── reporting ────────────────────────────────────────────
    def integrity(self) -> dict:
        ok, problems = self.chain.verify()
        return {"evidence_verified": ok, "problems": problems,
                "records": len(self.chain.records),
                "ruleset_hash": self._ruleset_hash,
                "head": self.chain.head[:16]}


# ─────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────

def _numeric(args: dict, keys: tuple) -> Optional[float]:
    for k in keys:
        if k in args:
            try:
                return float(args[k])
            except (TypeError, ValueError):
                continue
    return None


_TENANT_KEYS = ("tenant", "tenant_id", "customer_id", "account_id", "org",
                "org_id", "organization_id", "workspace", "workspace_id")


def _cross_tenant(call: dict, ctx: SecurityContext,
                  quarantined: Optional[dict] = None) -> Optional[str]:
    """Compare any tenant-scoped identifier in the action against the
    principal's own tenant. Wildcards are always cross-tenant.

    `quarantined` carries identity fields that were stripped from the authority
    namespace — they confer nothing, but they still identify the target.
    """
    own = (ctx.principal.tenant or "").strip().lower()
    args = {**(call.get("args") or {}), **(quarantined or {})}

    # FAIL CLOSED when the principal has no tenant.
    #
    # Previously an empty tenant made every comparison below vacuous: `if own
    # and val != own` cannot fire, so an anonymous caller touching a
    # tenant-scoped resource passed the check entirely. That is precisely the
    # state a caller reaches by omitting gateway auth — the weakest identity
    # got the weakest enforcement. If we cannot establish whose data this is,
    # we cannot establish that it is theirs.
    if not own:
        for k, v in args.items():
            if str(k).strip().lower() in _TENANT_KEYS:
                return (f"principal has no verified tenant, so a tenant-scoped "
                        f"reference ({k}={v!r}) cannot be authorised")
        blob_anon = " ".join(str(v).lower() for v in args.values())
        import re as _re
        m = _re.search(r"(?:^|[\s/:\"'])((?:tenant|customer|org)[-_][a-z0-9]+)",
                       blob_anon)
        if m:
            return (f"principal has no verified tenant, so a tenant-scoped "
                    f"resource reference ({m.group(1)!r}) cannot be authorised")
        return None

    for k, v in args.items():
        if str(k).strip().lower() not in _TENANT_KEYS:
            continue
        val = str(v).strip().lower()
        if val in ("*", "all", "any"):
            return (f"wildcard tenant scope {k}={v!r} from principal in tenant "
                    f"{own or '(none)'!r}")
        if own and val and val != own:
            return (f"cross-tenant access: {k}={v!r} but principal belongs to "
                    f"tenant {own!r}")
    # Qualified resource references such as "tenant_b.customers" / "s3://tenant-b/…"
    if own:
        blob = " ".join(str(v).lower() for v in args.values())
        import re as _re
        for m in _re.finditer(r"(?:^|[\s/:\"'])((?:tenant|customer|org)[-_][a-z0-9]+)",
                              blob):
            ref = m.group(1).replace("-", "_")
            if ref != own.replace("-", "_"):
                return (f"resource reference {m.group(1)!r} is outside the "
                        f"principal's tenant {own!r}")
    return None
