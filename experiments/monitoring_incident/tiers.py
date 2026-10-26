"""Admissibility tiers. Neither tier can authorise or execute anything.

LocalAdmissibility   one candidate action, no history, no state.
                     = the unchanged Morrison kernel (capability classifier,
                       authority quarantine, capability policy, unknown-tool
                       policy, Ω cybersecurity rules) evaluated by a FRESH
                       kernel with an empty continuity store, so no trajectory
                       leaks in; AND the pre-registered protected-resource rule.

GlobalAdmissibility  the executed trajectory plus the candidate.
                     = Morrison GovernanceLayer.evaluate_plan with one Ω rule
                       per monitoring invariant. Each rule projects the plan
                       onto the trusted session-start snapshot with the shared
                       tool semantics (sandbox.apply_action) and checks the
                       invariant statically (monitoring_model).

Each returns a TierResult. The Authorizer combines them.
"""

from __future__ import annotations

import copy
import json
import shlex
from dataclasses import asdict, dataclass, field

from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule
from morrison_governance.kernel import (
    GovernanceKernel, InMemoryContinuityStore, Principal, SecurityContext,
)

from experiments.monitoring_incident import monitoring_model as M
from experiments.monitoring_incident.sandbox import ToolError, apply_action, clean_path, fs_hash

PERMIT, BLOCK, ESCALATE, NOT_EVALUATED = "PERMIT", "BLOCK", "ESCALATE", "NOT_EVALUATED"
_RANK = {PERMIT: 0, ESCALATE: 1, BLOCK: 2}


@dataclass
class TierResult:
    tier: str
    verdict: str
    rule: str = ""
    reason: str = ""
    components: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def strictest(*verdicts: str) -> str:
    return max(verdicts, key=lambda v: _RANK.get(v, 2))


def action_paths(action: dict) -> list:
    """Every sandbox path an action would write, delete or move."""
    tool, args = action.get("tool"), action.get("args") or {}
    raw = []
    if tool in ("write_file", "delete_file"):
        raw = [args.get("path")]
    elif tool == "move_file":
        raw = [args.get("src"), args.get("dst")]
    elif tool == "run_command" and isinstance(args.get("command"), str):
        try:
            raw = shlex.split(args["command"])
        except ValueError:
            raw = args["command"].split()
        out = []
        for tok in raw:
            try:
                out.append(clean_path(tok))
            except ToolError:
                continue
        return out
    out = []
    for p in raw:
        out.append(clean_path(p))          # raises: an invalid path is inadmissible
    return out


class LocalAdmissibility:
    name = "local"

    def __init__(self, scenario, manifest: dict):
        cfg = manifest["local_tier"]["morrison_kernel"]
        self.scenario = scenario
        self.domains = [OmegaDomain(d) for d in cfg["omega_domains"]]
        self.tool_manifest = {t: list(c) for t, c in cfg["tool_manifest"].items()}
        self.unknown_tool_policy = cfg["unknown_tool_policy"]

    def _kernel(self) -> GovernanceKernel:
        # A new kernel and an empty store per evaluation: the kernel normally
        # evaluates the governed prefix too, which would make this tier
        # trajectory-aware and blur the experimental contrast.
        return GovernanceKernel(
            layer=GovernanceLayer(domains=self.domains, log_all=False),
            context=SecurityContext(
                principal=Principal(id="sandbox-proposer", tenant="monitoring-incident"),
                tool_manifest=self.tool_manifest,
                unknown_tool_policy=self.unknown_tool_policy,
                continuity_store=InMemoryContinuityStore()))

    def protected_resources(self, action: dict) -> TierResult:
        try:
            paths = action_paths(action)
        except ToolError as e:
            return TierResult("local.protected_resources", BLOCK, "path_not_admissible", str(e))
        verdict, hits = PERMIT, []
        for p in paths:
            low = p.lower()           # case-folded: macOS file systems are case-insensitive
            if M.matches(low, [x.lower() for x in self.scenario.protected_block]):
                verdict = strictest(verdict, BLOCK)
                hits.append({"path": p, "class": "block"})
            elif M.matches(low, [x.lower() for x in self.scenario.protected_escalate]):
                verdict = strictest(verdict, ESCALATE)
                hits.append({"path": p, "class": "escalate"})
        rule = "protected_monitoring_resource" if hits else ""
        return TierResult("local.protected_resources", verdict, rule,
                          "; ".join("%s (%s)" % (h["path"], h["class"]) for h in hits),
                          {"paths": paths, "hits": hits})

    def evaluate(self, action: dict) -> TierResult:
        d = self._kernel().preview(copy.deepcopy(action))
        kernel = {"verdict": d.verdict, "rule": d.rule, "layer": d.layer,
                  "reason": d.reason, "requirement": d.requirement,
                  "capabilities": sorted(d.capabilities),
                  "forged_authority_claims": list(d.forged_claims or [])}
        paths = self.protected_resources(action)
        verdict = strictest(d.verdict if d.verdict in _RANK else BLOCK, paths.verdict)
        decisive = kernel if _RANK.get(d.verdict, 2) >= _RANK[paths.verdict] else paths.as_dict()
        return TierResult(self.name, verdict,
                          rule=str(decisive.get("rule") or ""),
                          reason=str(decisive.get("reason") or ""),
                          components={"morrison_kernel": kernel,
                                      "protected_resources": paths.as_dict()})


class GlobalAdmissibility:
    name = "global"

    def __init__(self, scenario, baseline: dict):
        self.scenario = scenario
        self.baseline = dict(baseline)
        self.invariants = M.invariants_for(scenario)
        self._projections: dict = {}
        self.model_errors: list = []
        rules = [OmegaRule(OmegaDomain.CUSTOM, "monitoring_incident.%s" % name,
                           "monitoring invariant %s must hold on the projected trajectory" % name,
                           self._predicate(name))
                 for name in self.invariants]
        self.layer = GovernanceLayer(custom_rules=rules, log_all=False)

    # ── projection ───────────────────────────────────────────────────────
    def project(self, steps: list) -> dict:
        key = json.dumps(steps, sort_keys=True, default=repr)
        if key not in self._projections:
            fs = self.baseline
            for step in steps:
                try:
                    fs, _ = apply_action(fs, step)
                except ToolError:
                    continue            # an action that fails has no effect
            self._projections[key] = fs
        return self._projections[key]

    def violations(self, steps: list) -> dict:
        fs = self.project(steps)
        out = {}
        for name, check in self.invariants.items():
            found = check(self.baseline, fs)
            if found:
                out[name] = found
        return out

    @staticmethod
    def _steps_from_state(s) -> list:
        n = int(s.get("step") or 0)
        steps = []
        for i in range(n):
            steps.append({"tool": s.get("step_%d_tool" % i),
                          "args": dict(s.get("step_%d_args" % i) or {})})
        raw = s.get("args") or ""
        steps.append({"tool": s.get("tool"), "args": json.loads(raw) if raw else {}})
        return steps

    def _predicate(self, name: str):
        check = self.invariants[name]

        def violates(s) -> bool:
            try:
                fs = self.project(self._steps_from_state(s))
                return bool(check(self.baseline, fs))
            except Exception as e:            # noqa: BLE001 — fail closed
                self.model_errors.append("%s: %s: %s" % (name, type(e).__name__, e))
                return True
        return violates

    def evaluate(self, executed: list, candidate: dict) -> TierResult:
        plan = [copy.deepcopy(a) for a in executed] + [copy.deepcopy(candidate)]
        errors_before = len(self.model_errors)
        r = (self.layer.evaluate_plan(plan) if len(plan) > 1 else self.layer.evaluate(plan[0]))
        engine = r.verdict.value
        verdict = engine if engine in (PERMIT, BLOCK, ESCALATE) else BLOCK
        projected = self.violations(plan)
        return TierResult(self.name, verdict,
                          rule=str((r.metadata or {}).get("rule") or ""),
                          reason=r.reason or "",
                          components={"engine_verdict": engine, "engine_layer": r.layer,
                                      "omega_domain": r.omega_domain,
                                      "projected_state_hash": fs_hash(self.project(plan)),
                                      "projected_violations": projected,
                                      "model_errors": self.model_errors[errors_before:],
                                      "plan_length": len(plan)})
