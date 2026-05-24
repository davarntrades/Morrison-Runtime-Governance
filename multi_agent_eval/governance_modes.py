"""Governance modes — how per-agent trajectories compose into the
trajectory the reachability core evaluates.

Every mode delegates the actual safety decision to
morrison_governance.GovernanceLayer. The modes differ ONLY in what
trajectory they hand it:

  local_only     — the proposing agent's own local history + candidate
  shared_global  — the joint executed trajectory + candidate
  hierarchical   — local AND global; deny if either blocks
  quorum         — N replicas evaluate the joint trajectory; deny-by-
                   default (any block / crash → BLOCK)

Fail-closed: any governance exception is converted to BLOCK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from morrison_governance import GovernanceLayer


@dataclass
class Decision:
    mode: str
    permitted: bool
    verdict: str
    layer: str
    rule: Optional[str]
    omega_domain: Optional[str]
    reason: str

    def as_dict(self) -> dict:
        return {"mode": self.mode, "permitted": self.permitted,
                "verdict": self.verdict, "layer": self.layer,
                "rule": self.rule, "omega_domain": self.omega_domain,
                "reason": self.reason}


def _evaluate(gov: GovernanceLayer, plan: list):
    if not plan:
        return None, None
    try:
        r = (gov.evaluate_plan(plan) if len(plan) > 1
             else gov.evaluate(plan[0]))
        return r, None
    except Exception as e:                               # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def _decision(mode: str, r, err) -> Decision:
    if err is not None:
        return Decision(mode=mode, permitted=False, verdict="BLOCK",
                        layer="fail_closed", rule="governance_error",
                        omega_domain=None,
                        reason=f"governance error → BLOCK: {err}")
    return Decision(
        mode=mode, permitted=r.permitted, verdict=r.verdict.value,
        layer=r.layer, rule=(r.metadata or {}).get("rule"),
        omega_domain=r.omega_domain, reason=r.reason)


class GovernanceMode:
    name = "base"

    def decide(self, agent_id: str, local_history: list,
               joint_calls: list, candidate: dict) -> Decision:
        raise NotImplementedError


class LocalOnlyGovernance(GovernanceMode):
    """Each agent is governed against ITS OWN local history only — the
    realistic 'every service guards itself' baseline that misses
    cross-agent composition."""
    name = "local_only"

    def __init__(self, make_layer: Callable[[], GovernanceLayer]):
        self.make_layer = make_layer
        self._layers: dict = {}

    def decide(self, agent_id, local_history, joint_calls, candidate):
        gov = self._layers.setdefault(agent_id, self.make_layer())
        r, err = _evaluate(gov, list(local_history) + [candidate])
        return _decision(self.name, r, err)


class SharedGlobalGovernance(GovernanceMode):
    """The candidate is governed against the JOINT executed trajectory
    across all agents — so an acquire by one agent and an egress by
    another are one reachable set."""
    name = "shared_global"

    def __init__(self, make_layer: Callable[[], GovernanceLayer]):
        self.gov = make_layer()

    def decide(self, agent_id, local_history, joint_calls, candidate):
        r, err = _evaluate(self.gov, list(joint_calls) + [candidate])
        return _decision(self.name, r, err)


class HierarchicalGovernance(GovernanceMode):
    """Local AND global must both permit (deny-by-default)."""
    name = "hierarchical"

    def __init__(self, make_local: Callable[[], GovernanceLayer],
                 make_global: Callable[[], GovernanceLayer]):
        self.local = LocalOnlyGovernance(make_local)
        self.global_ = SharedGlobalGovernance(make_global)

    def decide(self, agent_id, local_history, joint_calls, candidate):
        dl = self.local.decide(agent_id, local_history, joint_calls,
                               candidate)
        dg = self.global_.decide(agent_id, local_history, joint_calls,
                                candidate)
        if dl.permitted and dg.permitted:
            return Decision(self.name, True, "PERMIT", "local+global",
                            None, None, "cleared local and global tiers")
        blocking = dl if not dl.permitted else dg
        return Decision(self.name, False, "BLOCK",
                        f"{'local' if not dl.permitted else 'global'}"
                        f":{blocking.layer}",
                        blocking.rule, blocking.omega_domain,
                        f"blocked at {'local' if not dl.permitted else 'global'} "
                        f"tier: {blocking.reason}")


class QuorumGovernance(GovernanceMode):
    """N replicas (diverse configs) evaluate the joint trajectory.
    Deny-by-default: permitted only if EVERY replica permits; any block
    or crash → BLOCK. No single point of failure."""
    name = "quorum"

    def __init__(self, make_layers: list):
        self.replicas = [f() for f in make_layers]

    def decide(self, agent_id, local_history, joint_calls, candidate):
        plan = list(joint_calls) + [candidate]
        n_block = n_err = 0
        first_block = None
        for gov in self.replicas:
            r, err = _evaluate(gov, plan)
            if err is not None:
                n_err += 1
                if first_block is None:
                    first_block = _decision(self.name, None, err)
            elif not r.permitted:
                n_block += 1
                if first_block is None:
                    first_block = _decision(self.name, r, None)
        if n_block == 0 and n_err == 0:
            return Decision(self.name, True, "PERMIT", "quorum",
                            None, None,
                            f"all {len(self.replicas)} replicas permit")
        d = first_block
        return Decision(self.name, False, "BLOCK", f"quorum:{d.layer}",
                        d.rule, d.omega_domain,
                        f"deny-by-default quorum: {n_block} block / "
                        f"{n_err} error of {len(self.replicas)} replicas")
