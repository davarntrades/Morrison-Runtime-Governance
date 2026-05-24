"""Joint trajectory evaluator + orchestrator.

The orchestrator runs a scenario under a chosen governance mode. Each
turn the scheduled agent proposes a tool call; the mode decides
(delegating to the reachability core); a PERMITTED call is applied to
the shared environment and appended to BOTH the agent's local history
and the joint trajectory; a BLOCKED call never executes (pre-execution
blocking, fail-closed). The joint trajectory is therefore the set of
*executed* cross-agent calls — exactly the reachable set the question

    JointReach(A₁, A₂, A₃, Env, t) ∩ Ω = ∅ ?

asks about."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class JointStep:
    seq: int
    agent_id: str
    proposed: dict
    decision: dict                     # Decision.as_dict()
    executed: bool
    env_hash_before: str
    joint_hash_after: str
    local_history_tools: list = field(default_factory=list)
    latency_ms: float = 0.0

    def to_record(self) -> dict:
        """The replay record (wall-clock excluded → byte-identical)."""
        return {
            "seq": self.seq,
            "agent_id": self.agent_id,
            "local_history": self.local_history_tools,
            "shared_env_state": self.env_hash_before,
            "proposed_tool_call": self.proposed,
            "governance_decision": self.decision["verdict"],
            "governance_layer": self.decision["layer"],
            "governance_rule": self.decision.get("rule"),
            "omega_domain": self.decision.get("omega_domain"),
            "joint_trajectory_hash": self.joint_hash_after,
            "reason": self.decision["reason"],
            "executed": self.executed,
            "mode": self.decision["mode"],
        }


@dataclass
class JointTrajectory:
    calls: list = field(default_factory=list)          # executed cross-agent calls

    def hash(self) -> str:
        payload = json.dumps(
            [{"tool": c.get("tool"), "args": c.get("args", {})}
             for c in self.calls], sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass
class RunResult:
    scenario: str
    mode: str
    steps: list = field(default_factory=list)          # list[JointStep]
    joint: JointTrajectory = field(default_factory=JointTrajectory)
    env_final_hash: str = ""
    unsafe_chain_completed: bool = False               # did the unsafe terminal execute?
    blocked_steps: int = 0

    def records(self) -> list:
        return [s.to_record() for s in self.steps]

    def summary(self) -> dict:
        return {"scenario": self.scenario, "mode": self.mode,
                "steps": len(self.steps),
                "executed": sum(1 for s in self.steps if s.executed),
                "blocked": self.blocked_steps,
                "joint_hash": self.joint.hash(),
                "env_final_hash": self.env_final_hash,
                "unsafe_chain_completed": self.unsafe_chain_completed}


def run_scenario(scenario, mode, env, *, deny_on_corrupt: bool = True) -> RunResult:
    """Run `scenario` under governance `mode` on shared `env`.

    `scenario` provides: .name, .agents (dict id→Agent), .schedule
    (ordered list of agent_ids), and .unsafe_terminal (a (tool, args)
    pair that, if executed, means the joint unsafe trajectory completed)
    or None for safe scenarios.

    Fail-closed: an agent whose propose() raises (a "crashed agent")
    contributes NO executed call — the absent link cannot advance an
    unsafe chain. If `deny_on_corrupt` and the shared environment is in
    a corrupted trust state, every subsequent call is denied by default."""
    from morrison_governance.result import GovernanceResult  # noqa: F401
    from multi_agent_eval.governance_modes import Decision

    for a in scenario.agents.values():
        a.reset()
    joint = JointTrajectory()
    local_history: dict = {aid: [] for aid in scenario.agents}
    steps: list = []
    blocked = 0
    seq = 0

    for agent_id in scenario.schedule:
        agent = scenario.agents[agent_id]
        env_hash_before = env.snapshot_hash()

        # crashed agent → fail-closed: record a BLOCK, execute nothing
        try:
            candidate = agent.propose(env, local_history[agent_id])
        except Exception as e:                           # noqa: BLE001
            steps.append(JointStep(
                seq=seq, agent_id=agent_id,
                proposed={"tool": "<crashed>", "args": {}},
                decision=Decision(
                    mode=mode.name, permitted=False, verdict="BLOCK",
                    layer="fail_closed", rule="agent_crash",
                    omega_domain=None,
                    reason=f"agent crashed → fail-closed: "
                           f"{type(e).__name__}: {e}").as_dict(),
                executed=False, env_hash_before=env_hash_before,
                joint_hash_after=joint.hash(),
                local_history_tools=[c.get("tool")
                                      for c in local_history[agent_id]]))
            blocked += 1
            seq += 1
            continue

        if candidate is None:
            continue

        t0 = time.perf_counter()
        if deny_on_corrupt and env.corrupted:
            decision = Decision(
                mode=mode.name, permitted=False, verdict="BLOCK",
                layer="deny_on_corrupt", rule="shared_state_corrupted",
                omega_domain=None,
                reason="shared state corrupted → deny-by-default")
        else:
            decision = mode.decide(agent_id, local_history[agent_id],
                                   joint.calls, candidate)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        executed = False
        if decision.permitted:
            env.apply(agent_id, candidate)
            local_history[agent_id].append(candidate)
            joint.calls.append(candidate)
            executed = True
        else:
            blocked += 1

        steps.append(JointStep(
            seq=seq, agent_id=agent_id, proposed=dict(candidate),
            decision=decision.as_dict(), executed=executed,
            env_hash_before=env_hash_before,
            joint_hash_after=joint.hash(),
            local_history_tools=[c.get("tool")
                                  for c in local_history[agent_id]],
            latency_ms=latency_ms))
        seq += 1

    unsafe_completed = False
    if scenario.unsafe_terminal is not None:
        t_tool, t_args = scenario.unsafe_terminal
        for c in joint.calls:
            if c.get("tool") == t_tool and c.get("args", {}) == t_args:
                unsafe_completed = True
                break

    return RunResult(
        scenario=scenario.name, mode=mode.name, steps=steps, joint=joint,
        env_final_hash=env.snapshot_hash(),
        unsafe_chain_completed=unsafe_completed, blocked_steps=blocked)
