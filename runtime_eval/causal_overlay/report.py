"""Causal report construction and presentation-safe view model."""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace

from .causal_templates import build_template
from .contribution_trace import build_contribution_trace
from .counterfactual_replay import GovernedTrajectory, full_replay
from .intervention_engine import apply_intervention, generate_interventions
from .models import (
    CausalAnalysisReport, CounterfactualResult, LatencyMetrics,
    ShadowAnalysisResult,
)
from .variable_extractor import extract_variables


def _changes(factual: tuple[int, ...], counterfactual: tuple[int, ...]
             ) -> tuple[str, ...]:
    left, right = set(factual), set(counterfactual)
    return tuple([f"removed:step:{n}" for n in sorted(left - right)] +
                 [f"added:step:{n}" for n in sorted(right - left)])


def _constraint_changes(factual: tuple[str, ...],
                        counterfactual: tuple[str, ...]) -> tuple[str, ...]:
    left, right = set(factual), set(counterfactual)
    return tuple([f"removed:{v}" for v in sorted(left - right)] +
                 [f"added:{v}" for v in sorted(right - left)])


def _counterfactual(case, extraction, intervention):
    outcome = full_replay(
        apply_intervention(case, intervention),
        scenario_hint=case.scenario_hint or extraction.scenario)
    factual = case.factual
    target = intervention.target_step
    factual_target_executed = any(
        s.original_step == target and s.executed for s in factual.steps)
    cf_target_executed = any(
        s.original_step == target and s.executed for s in outcome.steps)
    prevented = bool(
        (factual.omega_reachable and not outcome.omega_reachable)
        or (target is not None and factual_target_executed
            and not cf_target_executed))
    return CounterfactualResult(
        intervention=intervention,
        factual_verdict=factual.verdict,
        counterfactual_verdict=outcome.verdict,
        factual_omega=factual.omega,
        counterfactual_omega=outcome.omega,
        factual_omega_reachable=factual.omega_reachable,
        counterfactual_omega_reachable=outcome.omega_reachable,
        prevented=prevented,
        verdict_changed=factual.verdict != outcome.verdict,
        omega_reachability_changed=(
            factual.omega_reachable != outcome.omega_reachable),
        first_blocked_step_factual=factual.first_blocked_step,
        first_blocked_step_counterfactual=outcome.first_blocked_step,
        responsible_layer_factual=factual.responsible_layer,
        responsible_layer_counterfactual=outcome.responsible_layer,
        reachable_state_changes=_changes(
            factual.reachable_steps, outcome.reachable_steps),
        constraint_changes=_constraint_changes(
            factual.constraint_layers, outcome.constraint_layers),
        evidence_refs=(case.source_evidence_hash,),
        replay_latency_ms=outcome.replay_latency_ms,
    )


def _replay_all(case, extraction, interventions, mode, max_workers):
    started = time.perf_counter()
    if mode == "sequential" or len(interventions) < 2:
        results = tuple(_counterfactual(case, extraction, item)
                        for item in interventions)
    elif mode == "parallel":
        workers = max(1, min(max_workers, len(interventions)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="morrison-causal") as pool:
            results = tuple(pool.map(
                lambda item: _counterfactual(case, extraction, item),
                interventions))
    else:
        raise ValueError("replay mode must be 'sequential' or 'parallel'")
    return results, (time.perf_counter() - started) * 1000.0


def analyze(case: GovernedTrajectory, *, enabled: bool = True,
            replay_mode: str = "parallel", max_workers: int = 4,
            intervention_limit: int | None = None,
            compare_replay_modes: bool = False) -> CausalAnalysisReport | None:
    """Run post-decision causal analysis; never called by canonical authorize."""
    if not enabled:
        return None
    total_started = time.perf_counter()

    t0 = time.perf_counter()
    extraction = extract_variables(case)
    extraction_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    edges = build_template(extraction)
    template_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    interventions = generate_interventions(
        case, extraction, limit=intervention_limit)
    generation_ms = (time.perf_counter() - t0) * 1000.0

    results, selected_wall = _replay_all(
        case, extraction, interventions, replay_mode, max_workers)
    sequential_ms = selected_wall if replay_mode == "sequential" else 0.0
    parallel_ms = selected_wall if replay_mode == "parallel" else 0.0
    if compare_replay_modes and interventions:
        other = "parallel" if replay_mode == "sequential" else "sequential"
        alternate, alternate_wall = _replay_all(
            case, extraction, interventions, other, max_workers)
        if results != alternate:
            raise AssertionError(
                "parallel and sequential causal replay produced different results")
        if other == "parallel":
            parallel_ms = alternate_wall
        else:
            sequential_ms = alternate_wall

    t0 = time.perf_counter()
    trace = build_contribution_trace(results)
    contribution_ms = (time.perf_counter() - t0) * 1000.0
    necessary = tuple(dict.fromkeys(
        row.variable for row in trace if row.necessary_contributor))
    sufficient = tuple(
        row.intervention_id for row in trace
        if row.sufficient_to_break_trajectory)
    score = (len(results) / len(interventions)) if interventions else 0.0

    t0 = time.perf_counter()
    latency = LatencyMetrics(
        canonical_governance_ms=case.factual.replay_latency_ms,
        variable_extraction_ms=extraction_ms,
        template_construction_ms=template_ms,
        intervention_generation_ms=generation_ms,
        individual_replay_ms=tuple(
            item.replay_latency_ms for item in results),
        sequential_replay_wall_ms=sequential_ms,
        parallel_replay_wall_ms=parallel_ms,
        contribution_trace_ms=contribution_ms,
        async_canonical_governance_ms=case.factual.replay_latency_ms,
    )
    report = CausalAnalysisReport(
        trajectory_id=case.trajectory_id,
        source_evidence_hash=case.source_evidence_hash,
        factual_verdict=case.factual.verdict,
        factual_omega=case.factual.omega,
        causal_variables=extraction.variables,
        causal_edges=edges,
        interventions=results,
        necessary_contributors=necessary,
        sufficient_interventions=sufficient,
        contribution_trace=trace,
        causal_resolution_score=score,
        latency_metrics=latency,
    )
    report_ms = (time.perf_counter() - t0) * 1000.0
    t0 = time.perf_counter()
    report = report.with_seal()
    seal_ms = (time.perf_counter() - t0) * 1000.0
    total_ms = (time.perf_counter() - total_started) * 1000.0
    latency = replace(
        report.latency_metrics,
        report_construction_ms=report_ms,
        evidence_sealing_ms=seal_ms,
        total_overlay_ms=total_ms,
        synchronous_end_to_end_ms=(
            case.factual.replay_latency_ms + total_ms))
    return replace(report, latency_metrics=latency).with_seal()


def run_shadow(case: GovernedTrajectory, *, enabled: bool = True,
               analyzer=analyze, **kwargs) -> ShadowAnalysisResult:
    """Failure-isolated synchronous wrapper; canonical outcome is immutable."""
    if not enabled:
        return ShadowAnalysisResult(
            canonical_outcome=case.factual, report=None,
            overlay_enabled=False)
    try:
        return ShadowAnalysisResult(
            canonical_outcome=case.factual,
            report=analyzer(case, enabled=True, **kwargs))
    except Exception as exc:  # noqa: BLE001 - overlay must be non-authoritative
        return ShadowAnalysisResult(
            canonical_outcome=case.factual, report=None,
            overlay_error=f"{type(exc).__name__}: {exc}")


_ASYNC_POOL = ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="morrison-causal-shadow")


def submit_shadow(case: GovernedTrajectory, *, enabled: bool = True,
                  **kwargs) -> tuple[object, Future]:
    """Return the canonical outcome immediately and analyze on another thread."""
    if enabled:
        future = _ASYNC_POOL.submit(run_shadow, case, enabled=True, **kwargs)
    else:
        future = Future()
        future.set_result(run_shadow(case, enabled=False))
    return case.factual, future


def causal_view(report: CausalAnalysisReport) -> dict:
    """Return a UI-ready view that keeps epistemic categories explicit."""
    observed = [
        {"label": var.name, "value": var.value,
         "provenance": list(var.provenance)}
        for var in report.causal_variables
        if var.observation_type == "OBSERVED"
    ]
    derived = [
        {"parent": edge.parent, "child": edge.child,
         "relation": edge.relation, "provenance": list(edge.provenance)}
        for edge in report.causal_edges
    ]
    counterfactual = [
        {"intervention": item.intervention.intervention_id,
         "question": item.intervention.question,
         "result": ("forbidden trajectory broken" if item.prevented
                    else "no material preventive change"),
         "verdict": item.counterfactual_verdict,
         "omega_reachable": item.counterfactual_omega_reachable,
         "first_blocked_step": item.first_blocked_step_counterfactual}
        for item in report.interventions
    ]
    return {
        "title": "Causal Analysis",
        "status": "NON-AUTHORITATIVE SHADOW ANALYSIS",
        "canonical_morrison_verdict": {
            "label": "CANONICAL MORRISON VERDICT",
            "verdict": report.factual_verdict,
            "omega": list(report.factual_omega),
            "source_evidence_hash": report.source_evidence_hash,
        },
        "observed": {"label": "OBSERVED", "items": observed},
        "derived": {"label": "DERIVED", "items": derived},
        "counterfactual": {
            "label": "COUNTERFACTUAL", "items": counterfactual},
        "necessary_contributors": list(report.necessary_contributors),
        "sufficient_preventive_interventions":
            list(report.sufficient_interventions),
        "causal_resolution": report.causal_resolution_score,
        "latency": report.latency_metrics.as_dict(),
    }
