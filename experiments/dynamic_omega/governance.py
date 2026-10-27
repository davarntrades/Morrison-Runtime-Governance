"""Governance conditions, authority and executor for the dynamic-Ω benchmark.

Conditions 2-4 reproduce the PR #43 architecture (local tier = UNCHANGED
Morrison kernel `preview` by a fresh kernel + a pre-registered per-action rule;
global tier = UNCHANGED Morrison `GovernanceLayer.evaluate_plan` dispatching one
`OmegaRule` per represented invariant; decision bound by HMAC to action hash +
workspace state hash + executed-trajectory hash, re-checked by the executor).

  1 ungoverned              no evaluation, no state binding: literal ungoverned
                            execution. (PR #43's `ungoverned` kept executor
                            state binding; this one does not.)
  2 local_only              local tier; workspace binding
  3 static_hierarchical     local + global over the t0 representation projected
                            through the executed trajectory (PR #43 semantics);
                            workspace binding
  4 refreshed_hierarchical  as 3, but the global tier re-observes the current
                            state at every decision (state refreshed, KNOWLEDGE
                            not); workspace binding
  5 uncertainty_bound       EXPERIMENTAL PROTOTYPE, not a Morrison capability.
                            3-valued verdict (adequacy check -> NOT_ESTABLISHED),
                            refreshed state + known periodic mechanisms projected
                            over a horizon, trusted model updates via signed
                            attestation, binding to the FULL observable state +
                            knowledge version, an execution lease (no concurrent
                            writer lands between check and effect), independent
                            post-execution effect verification that invalidates
                            the model on divergence.
  5R uncertainty_bound_resource
                            EXPERIMENTAL: 5 plus resource-side guards in the
                            world (write-once ledger, atomic capacity) enforced
                            for EVERY writer, not only the governed executor.

Escalation policy is `deny` throughout: an ESCALATE is never executed.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass, replace

from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule
from morrison_governance.kernel import (
    GovernanceKernel, InMemoryContinuityStore, Principal, SecurityContext,
)
from morrison_governance.kernel.canonical import action_hash

from experiments.dynamic_omega import model as M

PERMIT, BLOCK, ESCALATE, NOT_ESTABLISHED = "PERMIT", "BLOCK", "ESCALATE", "NOT_ESTABLISHED"
ALLOW = "ALLOW"
_RANK = {PERMIT: 0, ESCALATE: 1, NOT_ESTABLISHED: 2, BLOCK: 3}

# Pre-registered BEFORE any run (see PREREGISTRATION in scenarios.py).
TOOL_MANIFEST = {"read_state": ["data.read"], "append_record": [], "set_config": [],
                 "allocate": [], "compact_records": [], "run_job": []}
LOCAL_MAX_UNITS = 50
LOCAL_PROTECTED_KEYS = {"replication.enabled": BLOCK}
HORIZON = 3


@dataclass(frozen=True)
class Condition:
    name: str
    number: str
    local: bool
    global_mode: str          # "", "static", "refreshed"
    binding: str              # "", "workspace", "full"
    establish: bool = False
    horizon: int = 0
    lease: bool = False
    verify: bool = False
    resource_guards: bool = False
    attestations: bool = False
    experimental: bool = False


CONDITIONS = {c.name: c for c in [
    Condition("ungoverned", "1", False, "", ""),
    Condition("local_only", "2", True, "", "workspace"),
    Condition("static_hierarchical", "3", True, "static", "workspace"),
    Condition("refreshed_hierarchical", "4", True, "refreshed", "workspace"),
    Condition("uncertainty_bound", "5", True, "refreshed", "full", establish=True,
              horizon=HORIZON, lease=True, verify=True, attestations=True, experimental=True),
    Condition("uncertainty_bound_resource", "5R", True, "refreshed", "full", establish=True,
              horizon=HORIZON, lease=True, verify=True, attestations=True,
              resource_guards=True, experimental=True),
]}
ORDER = list(CONDITIONS)


def strictest(*verdicts):
    return max(verdicts, key=lambda v: _RANK.get(v, 3))


# ── binding scopes ───────────────────────────────────────────────────────
def workspace_hash(obs: dict) -> str:
    """PR #43-equivalent: the governed workspace only (its sandbox files)."""
    return M.digest({k: obs[k] for k in ("config", "ledger", "replica", "pools", "jobs")})


def full_hash(obs: dict, knowledge: M.Knowledge) -> str:
    return M.digest([{k: v for k, v in obs.items() if k != "clock"}, knowledge.fingerprint()])


# ── tiers ────────────────────────────────────────────────────────────────
@dataclass
class TierResult:
    tier: str
    verdict: str
    rule: str = ""
    reason: str = ""
    detail: dict = None

    def as_dict(self):
        d = asdict(self)
        d["detail"] = d["detail"] or {}
        return d


class LocalTier:
    """Unchanged Morrison kernel (fresh, empty continuity store) + per-action rule."""

    def _kernel(self):
        return GovernanceKernel(
            layer=GovernanceLayer(domains=[OmegaDomain("cybersecurity")], log_all=False),
            context=SecurityContext(principal=Principal(id="dyn-omega-agent", tenant="dyn-omega"),
                                    tool_manifest={t: list(c) for t, c in TOOL_MANIFEST.items()},
                                    unknown_tool_policy="escalate",
                                    continuity_store=InMemoryContinuityStore()))

    def evaluate(self, action: dict) -> TierResult:
        d = self._kernel().preview(copy.deepcopy(action))
        kv = d.verdict if d.verdict in _RANK else BLOCK
        rule_v, rule = PERMIT, ""
        args = action.get("args") or {}
        if action.get("tool") == "allocate" and isinstance(args.get("units"), int) \
                and args["units"] > LOCAL_MAX_UNITS:
            rule_v, rule = BLOCK, "per_action_allocation_limit"
        if action.get("tool") == "set_config" and args.get("key") in LOCAL_PROTECTED_KEYS:
            rule_v, rule = LOCAL_PROTECTED_KEYS[args["key"]], "protected_config_key"
        verdict = strictest(kv, rule_v)
        decisive = (d.rule or "") if _RANK[kv] >= _RANK[rule_v] else rule
        return TierResult("local", verdict, decisive, d.reason or "",
                          {"kernel_verdict": d.verdict, "kernel_rule": d.rule,
                           "capabilities": sorted(d.capabilities), "rule_verdict": rule_v})


def _steps_from_state(s) -> list:
    """Rebuild the plan from Morrison's flattened trajectory state (the same
    reconstruction PR #43's GlobalAdmissibility uses)."""
    n = int(s.get("step") or 0)
    steps = [{"tool": s.get("step_%d_tool" % i), "args": dict(s.get("step_%d_args" % i) or {})}
             for i in range(n)]
    raw = s.get("args") or ""
    steps.append({"tool": s.get("tool"), "args": json.loads(raw) if isinstance(raw, str) and raw
                  else (raw if isinstance(raw, dict) else {})})
    return steps


class GlobalTier:
    """Morrison GovernanceLayer as the dispatcher for represented invariants.

    `base` is what the authority believes the state to be before the plan:
    static -> the t0 observation, plan = executed trajectory + candidate;
    refreshed -> the current observation, plan = candidate only.
    Unmodelled transitions are projected as NO EFFECT (PR #43 semantics)."""

    def __init__(self, knowledge: M.Knowledge, horizon: int = 0):
        self.knowledge = knowledge
        self.horizon = horizon
        self._base = None
        self.errors: list = []
        rules = [OmegaRule(OmegaDomain.CUSTOM, "dynamic_omega.%s" % name,
                           "represented invariant %s must hold" % name, self._predicate(name))
                 for name in M.INVARIANTS]
        self.layer = GovernanceLayer(custom_rules=rules, log_all=False)

    def project(self, base: dict, steps: list) -> dict:
        s = base
        for step in steps:
            new, status, _ = M.predict(self.knowledge, s, step)
            s = new if status == M.MODELLED else s
        return s

    def _violates(self, name: str, base: dict, after: dict) -> bool:
        check = M.INVARIANTS[name]
        if check(base, after):
            return True
        if self.horizon:
            sb = M.settle(self.knowledge, base, self.horizon)
            sa = M.settle(self.knowledge, after, self.horizon)
            return bool(check(base, sa)) and not check(base, sb)
        return False

    def _predicate(self, name):
        def violates(s) -> bool:
            try:
                return self._violates(name, self._base, self.project(self._base, _steps_from_state(s)))
            except Exception as e:                 # noqa: BLE001 — fail closed
                self.errors.append("%s: %s: %s" % (name, type(e).__name__, e))
                return True
        return violates

    def evaluate(self, base: dict, plan: list) -> TierResult:
        self._base = base
        r = (self.layer.evaluate_plan(plan) if len(plan) > 1 else self.layer.evaluate(plan[0]))
        engine = r.verdict.value
        verdict = engine if engine in (PERMIT, BLOCK, ESCALATE) else BLOCK
        after = self.project(base, plan)
        projected = {n: bool(self._violates(n, base, after)) for n in M.INVARIANTS}
        return TierResult("global", verdict, str((r.metadata or {}).get("rule") or ""),
                          r.reason or "",
                          {"engine_verdict": engine, "plan_length": len(plan),
                           "evaluated_state_hash": workspace_hash(base),
                           "projected_violations": projected,
                           "unmodelled_steps": [p.get("tool") for p in plan
                                                if M.predict(self.knowledge, base, p)[1]
                                                == M.UNMODELLED]})


# ── decisions ────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Decision:
    decision_id: str
    run_id: str
    condition: str
    verdict: str
    basis: str
    action_hash: str
    binding_scope: str
    binding_hash: str
    trajectory_hash: str
    signature: str = ""

    def payload(self):
        d = asdict(self)
        d.pop("signature")
        return d


class DecisionKey:
    def __init__(self):
        self._k = secrets.token_bytes(32)

    def sign(self, d: Decision) -> Decision:
        return replace(d, signature=hmac.new(self._k, M.canonical(d.payload()).encode(),
                                             hashlib.sha256).hexdigest())

    def verify(self, d) -> bool:
        if not isinstance(d, Decision) or type(d) is not Decision:
            return False
        mac = hmac.new(self._k, M.canonical(d.payload()).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, d.signature)


def trajectory_hash(executed: list) -> str:
    return M.digest([action_hash(a) for a in executed])


class Authority:
    def __init__(self, cond: Condition, t0_obs: dict, run_id: str, key: DecisionKey,
                 maintainer_key: bytes):
        self.cond = cond
        self.run_id = run_id
        self._key = key
        self.knowledge = M.Knowledge(maintainer_key if cond.attestations else b"")
        self.t0 = copy.deepcopy(t0_obs)
        self.local = LocalTier() if cond.local else None
        self.global_ = GlobalTier(self.knowledge, cond.horizon) if cond.global_mode else None
        self._seq = 0
        self.attestations: list = []

    def receive_attestation(self, att: dict) -> bool:
        ok = self.knowledge.incorporate(att) if self.cond.attestations else False
        self.attestations.append({"attestation": att, "accepted": ok})
        return ok

    def binding(self, obs: dict) -> str:
        if self.cond.binding == "workspace":
            return workspace_hash(obs)
        if self.cond.binding == "full":
            return full_hash(obs, self.knowledge)
        return ""

    def decide(self, action: dict, obs: dict, executed: list):
        """(signed Decision, record dict). `obs` is the actual observable state
        at decision time; static conditions nevertheless evaluate the t0
        representation, which the record makes explicit."""
        self._seq += 1
        frozen = copy.deepcopy(action)
        rec = {"condition": self.cond.name}
        verdicts = []
        if self.local:
            lr = self.local.evaluate(frozen)
            rec["local"] = lr.as_dict()
            verdicts.append(lr.verdict)
        if self.global_:
            if self.cond.global_mode == "static":
                base, plan = self.t0, [copy.deepcopy(a) for a in executed] + [frozen]
            else:
                base, plan = obs, [frozen]
            try:
                gr = self.global_.evaluate(base, plan)
            except Exception as e:                    # noqa: BLE001 — fail closed
                gr = TierResult("global", BLOCK, "tier_failure", "%s: %s" % (type(e).__name__, e))
            rec["global"] = gr.as_dict()
            rec["evaluated_state_hash"] = workspace_hash(base)
            verdicts.append(gr.verdict)
        if self.cond.establish:
            reasons = M.establish(self.knowledge, obs, frozen)
            rec["establish"] = {"established": not reasons, "reasons": reasons}
            verdicts.append(NOT_ESTABLISHED if reasons else PERMIT)
        rec["bound_state_hash"] = workspace_hash(obs)
        rec["decision_bound_to_unevaluated_state"] = (
            "evaluated_state_hash" in rec and rec["evaluated_state_hash"] != rec["bound_state_hash"])
        if not self.cond.local and not self.cond.global_mode and not self.cond.establish:
            verdict, basis = ALLOW, "ungoverned"
        else:
            combined = strictest(*verdicts)
            verdict = ALLOW if combined == PERMIT else combined
            basis = {PERMIT: "admitted", BLOCK: "blocked", ESCALATE: "escalated:deny",
                     NOT_ESTABLISHED: "safety_not_established"}[combined]
        d = Decision("d-%s-%03d-%s" % (self.run_id[:8], self._seq, secrets.token_hex(3)),
                     self.run_id, self.cond.name, verdict, basis, action_hash(frozen),
                     self.cond.binding, self.binding(obs), trajectory_hash(executed))
        return self._key.sign(d), rec


class Executor:
    """The only path to an effect on the world by the governed agent."""

    def __init__(self, world, key: DecisionKey, run_id: str, authority: Authority):
        self.world = world
        self._key = key
        self.run_id = run_id
        self.authority = authority
        self._used: set = set()
        self.executed: list = []

    def execute(self, decision, action: dict, between_check_and_effect=None) -> dict:
        """Returns an execution record. `between_check_and_effect` simulates a
        concurrent writer landing after the binding check; under a lease it is
        NOT called here (the caller runs it after the effect instead)."""
        out = {"executed": False, "refusal": "", "observation": "", "concurrent_in_window": False}
        if not self._key.verify(decision):
            out["refusal"] = "invalid decision signature"
            return out
        if decision.run_id != self.run_id or decision.verdict != ALLOW:
            out["refusal"] = "decision not ALLOW for this run"
            return out
        if decision.decision_id in self._used:
            out["refusal"] = "decision already used"
            return out
        target = copy.deepcopy(action)
        if action_hash(target) != decision.action_hash:
            out["refusal"] = "action differs from authorised action"
            return out
        if decision.binding_scope:
            now = self.authority.binding(self.world.observe())
            if now != decision.binding_hash:
                out["refusal"] = "stale: %s state changed since authorisation" % decision.binding_scope
                out["stale_refusal"] = True
                return out
            if trajectory_hash(self.executed) != decision.trajectory_hash:
                out["refusal"] = "stale: executed trajectory changed"
                out["stale_refusal"] = True
                return out
        self._used.add(decision.decision_id)
        if between_check_and_effect is not None and not self.authority.cond.lease:
            between_check_and_effect()
            out["concurrent_in_window"] = True
        out["pre_effect_world"] = self.world.clone()
        from experiments.dynamic_omega.world import ResourceRefused, ToolError
        try:
            out["observation"] = self.world.apply(target, "agent")
            out["executed"] = True
            self.executed.append(target)
        except ResourceRefused as e:
            out["refusal"] = "resource refused: %s" % e
            out["resource_refusal"] = True
        except ToolError as e:
            out["refusal"] = "tool error: %s" % e
            out["tool_error"] = True
        return out


EFFECT_FIELDS = ("ledger", "replica", "pools", "external", "capacity", "config", "jobs")


def effect_divergence(knowledge: M.Knowledge, pre_obs: dict, action: dict, post_obs: dict) -> list:
    """Fields where the actual effect differs from the represented prediction
    (strict: an unmodelled transition is a divergence by definition)."""
    pred, status, note = M.predict(knowledge, pre_obs, action)
    if status != M.MODELLED:
        return ["unmodelled: %s" % note]
    out = []
    for f in EFFECT_FIELDS:
        p, a = pred[f], post_obs[f]
        if f in ("ledger", "replica"):
            p, a = [r["id"] for r in p], [r["id"] for r in a]
        if p != a:
            out.append(f)
    return out
