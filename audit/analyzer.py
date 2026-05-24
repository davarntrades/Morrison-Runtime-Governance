"""Audit analyzer — runs each client trajectory through the governance
engine and produces a Finding.

Reuses the runtime_eval middleware (prefix-aware, fail-closed, optional
hardening) so the per-step partition matches production behaviour, plus
GovernanceLayer.evaluate_all_plan for full layer attribution (which
layers would object, without short-circuit). No execution side effects —
the sandbox is the inert simulator. Deterministic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from runtime_eval.governance.omega_registry import OmegaRegistry
from runtime_eval.governance.middleware import RuntimeGovernanceMiddleware
from runtime_eval.governance.hardening import HardeningPipeline
from runtime_eval.planners.deterministic import ScriptedPlanner
from runtime_eval.sandbox.executor import SandboxExecutor
from runtime_eval.sandbox.tool_simulator import ToolSimulator
from runtime_eval.evaluators.risk_propagation import propagate_risk

from audit.intake import AuditPackage
from audit.risk import severity_of


@dataclass
class Finding:
    trajectory_id: str
    n_steps: int
    verdict: str                       # PERMIT | BLOCK | ...
    blocked: bool
    layer: Optional[str]               # first blocking layer (None if permitted)
    rule: Optional[str]
    omega_domain: Optional[str]
    reason: str
    reachability_distance: Optional[float]
    trajectory_hash: str
    layers_that_would_object: list     # from evaluate_all_plan
    cumulative_risk: float
    severity: float
    severity_band: str
    per_step: list = field(default_factory=list)   # blocked-vs-permitted partition
    expected: Optional[str] = None
    expectation_met: Optional[bool] = None

    def as_dict(self) -> dict:
        return {
            "trajectory_id": self.trajectory_id, "n_steps": self.n_steps,
            "verdict": self.verdict, "blocked": self.blocked,
            "layer": self.layer, "rule": self.rule,
            "omega_domain": self.omega_domain, "reason": self.reason,
            "reachability_distance": self.reachability_distance,
            "trajectory_hash": self.trajectory_hash,
            "layers_that_would_object": list(self.layers_that_would_object),
            "cumulative_risk": self.cumulative_risk,
            "severity": self.severity, "severity_band": self.severity_band,
            "per_step": self.per_step,
            "expected": self.expected, "expectation_met": self.expectation_met,
        }


@dataclass
class AuditResult:
    org: str
    domains: list
    use_hardening: bool
    findings: list = field(default_factory=list)
    tool_names: list = field(default_factory=list)

    def summary(self) -> dict:
        blocked = [f for f in self.findings if f.blocked]
        permitted = [f for f in self.findings if not f.blocked]
        bands = {b: 0 for b in ("critical", "high", "medium", "low", "none")}
        for f in self.findings:
            bands[f.severity_band] += 1
        reachable = sorted({(f.omega_domain, f.rule) for f in blocked
                            if f.rule},
                           key=lambda x: (str(x[0]), str(x[1])))
        return {
            "org": self.org, "domains": self.domains,
            "trajectories": len(self.findings),
            "blocked": len(blocked), "permitted": len(permitted),
            "severity_bands": bands,
            "reachable_omega_states": [{"omega_domain": d, "rule": r}
                                       for d, r in reachable],
            "hardening": self.use_hardening,
        }


def _build_layer(package: AuditPackage):
    return OmegaRegistry(
        domains=package.domains,
        internal_url_hosts=package.internal_url_hosts,
        internal_email_domains=package.internal_email_domains,
    ).build()


def analyze(package: AuditPackage) -> AuditResult:
    governance = _build_layer(package)
    hardening = HardeningPipeline() if package.use_hardening else None
    findings: list = []

    for traj in package.trajectories:
        calls = traj.calls()

        # 1. prefix-aware per-step partition (production-faithful)
        sandbox = SandboxExecutor(simulator=ToolSimulator())
        mw = RuntimeGovernanceMiddleware(governance, sandbox,
                                         hardening=hardening)
        run = mw.run(ScriptedPlanner([calls]), max_steps=len(calls) + 2)
        per_step = [{"step": r.step, "tool": r.proposed.get("tool"),
                     "verdict": r.verdict, "layer": r.layer, "rule": r.rule,
                     "executed": r.executed} for r in run.trace.records]
        first_block = next((r for r in run.trace.records
                            if r.verdict != "PERMIT"), None)

        # 2. whole-trajectory verdict + full layer attribution
        whole = (governance.evaluate_plan(calls) if len(calls) > 1
                 else governance.evaluate(calls[0]))
        allrep = (governance.evaluate_all_plan(calls) if len(calls) > 1
                  else governance.evaluate_all(calls[0]))
        layers_obj = sorted(k for k, v in allrep.get("layers", {}).items()
                            if v.get("fired"))

        # 3. structural risk over the trajectory
        _g, risk = propagate_risk(calls)
        cum_risk = round(risk.max_cumulative, 4)

        blocked = whole.verdict.value != "PERMIT"
        layer = (first_block.layer if first_block else whole.layer
                 if blocked else None)
        if blocked:
            if first_block is not None:
                rule = (first_block.rule
                        or (first_block.metadata or {}).get("v2_mechanism"))
            else:
                md = whole.metadata or {}
                rule = md.get("rule") or md.get("v2_mechanism")
        else:
            rule = None
        omega_domain = whole.omega_domain if blocked else None
        sev, band = severity_of(
            blocked=blocked, layer=layer, rule=rule,
            omega_domain=omega_domain, cumulative_risk=cum_risk)

        exp = traj.expected
        exp_met = None
        if exp is not None:
            exp_met = (exp == "BLOCK") == blocked

        findings.append(Finding(
            trajectory_id=traj.id, n_steps=len(calls),
            verdict=whole.verdict.value, blocked=blocked, layer=layer,
            rule=rule, omega_domain=omega_domain, reason=whole.reason,
            reachability_distance=whole.reachability_distance,
            trajectory_hash=whole.trajectory_hash,
            layers_that_would_object=layers_obj,
            cumulative_risk=cum_risk, severity=sev, severity_band=band,
            per_step=per_step, expected=exp, expectation_met=exp_met))

    return AuditResult(
        org=package.org, domains=package.domains,
        use_hardening=package.use_hardening, findings=findings,
        tool_names=package.tool_names())
