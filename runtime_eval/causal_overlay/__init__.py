"""Additive, non-authoritative Dynamical + SCM causal-analysis overlay."""

from .counterfactual_replay import (
    GovernedTrajectory, ReplayConfig, capture_governed_trajectory,
    case_from_frontier_record, full_replay,
)
from .models import (
    CausalAnalysisReport, CausalEdge, CausalIntervention, CausalVariable,
    CounterfactualResult, LatencyMetrics, OVERLAY_VERSION,
    ShadowAnalysisResult,
)
from .report import analyze, causal_view, run_shadow, submit_shadow

__all__ = [
    "GovernedTrajectory", "ReplayConfig", "capture_governed_trajectory",
    "case_from_frontier_record", "full_replay", "CausalAnalysisReport", "CausalEdge",
    "CausalIntervention", "CausalVariable", "CounterfactualResult",
    "LatencyMetrics", "OVERLAY_VERSION", "ShadowAnalysisResult", "analyze",
    "causal_view", "run_shadow", "submit_shadow",
]
