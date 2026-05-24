"""
Morrison Multi-Agent Evaluation harness.

Tests whether multiple autonomous agents — each individually appearing
safe — can collectively create a forbidden reachable trajectory:

    JointReach(A₁, A₂, A₃, Env, t) ∩ Ω = ∅ ?

Not "does any single agent output look unsafe?". Every governance
decision is delegated to the existing morrison_governance.GovernanceLayer
(the reachability hierarchy A_safe → V2 → V3 → V4 → V4+ → V5 → V5+).
Nothing here reimplements or weakens that core; this package only
changes how *per-agent* trajectories COMPOSE into a joint trajectory and
which composition the governance layer sees.

Bounded: this is mechanism-level testing on a deterministic suite, not a
proof of global safety.
"""

from multi_agent_eval.agents import Agent, CallableAgent, ToolCall
from multi_agent_eval.environment import SharedEnvironment
from multi_agent_eval.joint_trajectory import (
    JointTrajectory, JointStep, run_scenario, RunResult,
)
from multi_agent_eval.governance_modes import (
    Decision, GovernanceMode, LocalOnlyGovernance, SharedGlobalGovernance,
    HierarchicalGovernance, QuorumGovernance,
)
from multi_agent_eval.scenarios import SCENARIOS, get_scenario, Scenario
from multi_agent_eval.replay import TraceWriter, TraceReader
from multi_agent_eval.metrics import (
    joint_confusion, collusion_detection_rate, local_vs_global,
    cross_agent_depth, shared_state_risk,
)

__all__ = [
    "Agent", "CallableAgent", "ToolCall",
    "SharedEnvironment",
    "JointTrajectory", "JointStep", "run_scenario", "RunResult",
    "Decision", "GovernanceMode", "LocalOnlyGovernance",
    "SharedGlobalGovernance", "HierarchicalGovernance", "QuorumGovernance",
    "SCENARIOS", "get_scenario", "Scenario",
    "TraceWriter", "TraceReader",
    "joint_confusion", "collusion_detection_rate", "local_vs_global",
    "cross_agent_depth", "shared_state_risk",
]
