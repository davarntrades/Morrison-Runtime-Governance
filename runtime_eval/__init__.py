"""Morrison Runtime Governance — live-planner evaluation harness.

Additive over `morrison_governance`. Hot-swappable open-weight planners
behind a stable interface; the existing reachability-based governance
hierarchy is the safety mechanism. No moderation, no RLHF, no
prompt-engineering — every decision is a reachability check.
"""

from runtime_eval.planners import (
    Planner, PlannerInfo, ToolCall,
    ScriptedPlanner, ProfilePlanner, CallableModelPlanner,
    PLANNER_REGISTRY, get_planner,
)
from runtime_eval.governance import (
    RuntimeGovernanceMiddleware, RunResult, StepResult,
    DecisionRecord, DecisionTrace, OmegaRegistry,
)
from runtime_eval.sandbox import ToolSimulator, SandboxExecutor
from runtime_eval.perturbations import PERTURBATION_FAMILIES, perturb
from runtime_eval.evaluators import (
    ConfusionMatrix, confusion_matrix, two_class_metrics,
    cross_planner_agreement, run_planners,
)
from runtime_eval.replay import TraceWriter, TraceReader
from runtime_eval.metrics import LatencyStats, latency_stats
from runtime_eval.domains import DOMAIN_PRESETS, get_preset

__all__ = [
    # planner layer
    "Planner", "PlannerInfo", "ToolCall",
    "ScriptedPlanner", "ProfilePlanner", "CallableModelPlanner",
    "PLANNER_REGISTRY", "get_planner",
    # governance
    "RuntimeGovernanceMiddleware", "RunResult", "StepResult",
    "DecisionRecord", "DecisionTrace", "OmegaRegistry",
    # sandbox
    "ToolSimulator", "SandboxExecutor",
    # perturbations / evaluators
    "PERTURBATION_FAMILIES", "perturb",
    "ConfusionMatrix", "confusion_matrix", "two_class_metrics",
    "cross_planner_agreement", "run_planners",
    # replay / metrics / domains
    "TraceWriter", "TraceReader",
    "LatencyStats", "latency_stats",
    "DOMAIN_PRESETS", "get_preset",
]
