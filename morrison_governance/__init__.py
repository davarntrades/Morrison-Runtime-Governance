"""
Morrison Runtime Governance

Pre-execution control layer for tool-using AI systems.
Intercepts executable trajectories and evaluates reachability
into forbidden states (Ω) before any action occurs.

    from morrison_governance import GovernanceLayer, OmegaDomain

    governance = GovernanceLayer(
        domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY]
    )

    result = governance.evaluate(tool_call)

    if result.permitted:
        execute(tool_call)
    else:
        log(result.reason)

UK Patents: GB2600765.8 · GB2602013.1 · GB2602072.7 · GB2602332.5
© 2026 Davarn Morrison — Resurrection Tech Ltd
"""

from morrison_governance.core import GovernanceLayer
from morrison_governance.domains import OmegaDomain, OmegaRule
from morrison_governance.trajectory import TrajectoryExtractor
from morrison_governance.reachability import ReachabilityEvaluator
from morrison_governance.result import GovernanceResult, GovernanceVerdict
from morrison_governance.admissibility import (
    AdmissibilityCheck,
    AdmissibilityEvaluator,
    default_admissibility_checks,
    role_required,
    resource_scope,
    required_fields,
    quota_limit,
    schema_required,
)
from morrison_governance.feasibility import (
    FeasibilityEvaluator,
    FeasibilityReport,
    goal_uses_tool,
    goal_visits_state,
    goal_terminates_with,
    goal_all,
)
from morrison_governance.stability import (
    StabilityEvaluator,
    StabilityReport,
    prompt_drift,
    permission_drift,
    memory_corruption,
    context_mutation,
    tool_schema_drift,
    planner_variation,
)
from morrison_governance.adversarial import (
    AdversarialReport,
    AttackVariant,
    run_attack_suite,
)
from morrison_governance.integrations import (
    GovernanceGuard,
    GovernanceError,
    openai_partition_tool_calls,
    openai_guarded_dispatch,
    claude_filter_tool_use,
    govern_langchain_tool,
    GovernanceCallbackHandler,
    autogen_guard_function_call,
    register_autogen_guard,
    browser_action_guard,
    mcp_guard_call_tool,
    wrap_mcp_call_tool,
    governed_run,
    WorkflowGovernor,
)

__version__ = "0.2.0"
__author__ = "Davarn Morrison"
__license__ = "Commercial — see LICENSE"

__all__ = [
    "GovernanceLayer",
    "OmegaDomain",
    "OmegaRule",
    "TrajectoryExtractor",
    "ReachabilityEvaluator",
    "GovernanceResult",
    "GovernanceVerdict",
    # V4 — state-space admissibility
    "AdmissibilityCheck",
    "AdmissibilityEvaluator",
    "default_admissibility_checks",
    "role_required",
    "resource_scope",
    "required_fields",
    "quota_limit",
    "schema_required",
    # V4+ — feasibility
    "FeasibilityEvaluator",
    "FeasibilityReport",
    "goal_uses_tool",
    "goal_visits_state",
    "goal_terminates_with",
    "goal_all",
    # V5 — environment-wide stability
    "StabilityEvaluator",
    "StabilityReport",
    "prompt_drift",
    "permission_drift",
    "memory_corruption",
    "context_mutation",
    "tool_schema_drift",
    "planner_variation",
    # V5+ — hard adversarial framework
    "AdversarialReport",
    "AttackVariant",
    "run_attack_suite",
    # Deployment adapters
    "GovernanceGuard",
    "GovernanceError",
    "openai_partition_tool_calls",
    "openai_guarded_dispatch",
    "claude_filter_tool_use",
    "govern_langchain_tool",
    "GovernanceCallbackHandler",
    "autogen_guard_function_call",
    "register_autogen_guard",
    "browser_action_guard",
    "mcp_guard_call_tool",
    "wrap_mcp_call_tool",
    "governed_run",
    "WorkflowGovernor",
]
