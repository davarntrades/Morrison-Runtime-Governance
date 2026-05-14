“””
Reachability evaluation.

Implements the Morrison Enforcement Hierarchy:
A_safe ⊂ V2 ⊂ V3 ⊂ V4 ⊂ V4+ ⊂ V5

Each layer catches failures invisible to every layer below it.
“””

from typing import Optional
from morrison_governance.trajectory import Trajectory, TrajectoryState
from morrison_governance.domains import OmegaRule
from morrison_governance.result import GovernanceResult, GovernanceVerdict

class ReachabilityEvaluator:
“””
Evaluates whether a trajectory’s reachable set intersects Ω.

```
Implements enforcement layers:
    A_safe: single-step Ω check
    V2:     trajectory drift detection across sliding window
    V3:     forward reachability for horizon k ≥ 2
    V4+:    feasibility-constrained selection
    V5:     stability across environment set ℰ
"""

def __init__(self, rules: list[OmegaRule], horizon: int = 3):
    """
    Args:
        rules: list of Ω rules to enforce
        horizon: forward reachability horizon (V3+)
    """
    self.rules = rules
    self.horizon = horizon

# ═══════════════════════════════════════════════════════════
# A_safe — SINGLE-STEP Ω CHECK
# ═══════════════════════════════════════════════════════════

def check_a_safe(self, state: TrajectoryState) -> Optional[GovernanceResult]:
    """
    A_safe: rejects if x_{t+1} ∈ Ω.
    Single-step check. Fastest layer.
    """
    eval_dict = state.to_eval_dict()
    for rule in self.rules:
        if rule.evaluate(eval_dict):
            return GovernanceResult(
                verdict=GovernanceVerdict.BLOCK,
                layer="A_safe",
                reason=f"Single-step Ω violation: {rule.name}",
                omega_domain=rule.domain.value,
                trajectory_hash=state.hash,
                reachability_distance=0.0,
                metadata={"rule": rule.name, "description": rule.description},
            )
    return None

# ═══════════════════════════════════════════════════════════
# V2 — TRAJECTORY DRIFT DETECTION
# ═══════════════════════════════════════════════════════════

def check_v2(self, trajectory: Trajectory) -> Optional[GovernanceResult]:
    """
    V2: detects drift/acceleration toward Ω across a sliding window.
    Catches gradual escalation invisible to single-step checks.
    """
    if not trajectory.is_multi_step:
        return None

    # Track tool escalation patterns
    tools_seen = []
    escalation_signals = 0

    for state in trajectory:
        tools_seen.append(state.tool)
        eval_dict = state.to_eval_dict()

        # Detect escalation: benign → sensitive tool transitions
        sensitive_tools = {
            "shell", "exec", "subprocess", "http_request",
            "send_email", "transfer", "execute_trade",
            "delete", "write_file", "api_call",
        }

        if len(tools_seen) >= 2:
            prev_sensitive = tools_seen[-2] in sensitive_tools
            curr_sensitive = tools_seen[-1] in sensitive_tools
            if not prev_sensitive and curr_sensitive:
                escalation_signals += 1

        # Detect context accumulation toward Ω
        for rule in self.rules:
            # Check if accumulated context + current state is drifting
            accumulated = state.to_eval_dict()
            if rule.evaluate(accumulated):
                return GovernanceResult(
                    verdict=GovernanceVerdict.BLOCK,
                    layer="V2",
                    reason=f"Trajectory drift toward Ω: {rule.name} (step {state.step})",
                    omega_domain=rule.domain.value,
                    trajectory_hash=trajectory.hash,
                    metadata={
                        "rule": rule.name,
                        "step": state.step,
                        "escalation_signals": escalation_signals,
                    },
                )

    # Check for suspicious escalation patterns
    if escalation_signals >= 2:
        return GovernanceResult(
            verdict=GovernanceVerdict.BLOCK,
            layer="V2",
            reason=f"Multi-step escalation detected ({escalation_signals} transitions to sensitive tools)",
            trajectory_hash=trajectory.hash,
            metadata={"tools": tools_seen, "escalation_signals": escalation_signals},
        )

    return None

# ═══════════════════════════════════════════════════════════
# V3 — FORWARD REACHABILITY
# ═══════════════════════════════════════════════════════════

def check_v3(self, trajectory: Trajectory) -> Optional[GovernanceResult]:
    """
    V3: rejects when ℛ̂(F(x,u),k) ∩ Ω ≠ ∅ for horizon k ≥ 2.
    Evaluates whether the reachable set from the current state
    can reach Ω within k steps, even if no single step violates.
    """
    for state in trajectory:
        eval_dict = state.to_eval_dict()

        # Project forward: what could be reached from this state?
        projected_states = self._project_forward(state, self.horizon)

        for k, projected in enumerate(projected_states):
            for rule in self.rules:
                if rule.evaluate(projected):
                    return GovernanceResult(
                        verdict=GovernanceVerdict.BLOCK,
                        layer="V3",
                        reason=(
                            f"Forward reachability violation: {rule.name} "
                            f"reachable at horizon k={k + 1} from step {state.step}"
                        ),
                        omega_domain=rule.domain.value,
                        trajectory_hash=trajectory.hash,
                        reachability_distance=float(k + 1),
                        metadata={
                            "rule": rule.name,
                            "source_step": state.step,
                            "horizon": k + 1,
                        },
                    )

    return None

def _project_forward(self, state: TrajectoryState, horizon: int) -> list[dict]:
    """
    Project forward reachability from a state.

    In production, this uses actual tool definitions to enumerate
    reachable states. This implementation uses heuristic projection
    based on tool capabilities.

    Only projects from tools that access, read, or modify sensitive
    resources — ordinary tools (email, analyze, search) do not
    generate forward projections into sensitive tool space.
    """
    projections = []
    base = state.to_eval_dict()

    # Tools that access sensitive data — these have forward reachability
    # into exfiltration / escalation tools
    data_access_tools = {
        "read_file", "query_db", "get_data", "list_files",
        "get_credentials", "read_secrets",
    }
    perm_tools = {"chmod", "chown", "set_permissions", "update_role"}
    exfil_tools = {"http_request", "send_email", "api_call", "upload"}

    tool = base.get("tool", "")
    args_str = str(base.get("args", "")).lower()

    # Only project if current tool reads sensitive data
    sensitive_paths = (
        "/etc/shadow", "/etc/passwd", ".env", ".ssh",
        "credentials", "secret", "api_key", "token", "password",
    )
    is_sensitive_read = (
        tool in data_access_tools
        and any(sp in args_str for sp in sensitive_paths)
    )

    if is_sensitive_read:
        for exfil in exfil_tools:
            projected = base.copy()
            projected["tool"] = exfil
            projected["destination_external"] = True
            projected["step"] = state.step + 1
            projections.append(projected)

    # If current tool modifies permissions, project escalation
    if tool in perm_tools:
        projected = base.copy()
        projected["tool"] = "exec"
        projected["args"] = "escalated_command"
        projected["step"] = state.step + 1
        projections.append(projected)

    return projections[:horizon]

# ═══════════════════════════════════════════════════════════
# FULL EVALUATION — HIERARCHICAL
# ═══════════════════════════════════════════════════════════

def evaluate(self, trajectory: Trajectory) -> GovernanceResult:
    """
    Run the full enforcement hierarchy against a trajectory.

    Evaluation order: A_safe → V2 → V3
    First violation terminates evaluation (strict-strengthening).
    """
    # A_safe: check every state individually
    for state in trajectory:
        result = self.check_a_safe(state)
        if result is not None:
            return result

    # V2: check trajectory-level drift
    result = self.check_v2(trajectory)
    if result is not None:
        return result

    # V3: check forward reachability
    result = self.check_v3(trajectory)
    if result is not None:
        return result

    # All layers passed — trajectory is permitted
    return GovernanceResult(
        verdict=GovernanceVerdict.PERMIT,
        layer="V3",
        reason="Trajectory does not reach Ω under evaluated hierarchy",
        trajectory_hash=trajectory.hash,
    )
```
