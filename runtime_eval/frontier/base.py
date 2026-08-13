"""Provider-neutral one-shot planner primitives.

Hosted providers stop at proposal generation.  Execution is deliberately not
part of this interface: normalized proposals are handed to the existing
RuntimeGovernanceMiddleware, which is the only route to the simulator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from runtime_eval.planners.base import PlannerInfo, ToolCall


@dataclass
class ProviderObservation:
    tool_calls: list[ToolCall] = field(default_factory=list)
    native_tool_calls: list[dict] = field(default_factory=list)
    text: str = ""
    latency_ms: float = 0.0
    malformed: bool = False
    error: Optional[str] = None


class OneShotFrontierPlanner:
    """A live model is invoked once and its native tool calls are normalized."""

    info: PlannerInfo

    def __init__(self) -> None:
        self._done = False
        self.observation = ProviderObservation()

    def propose(self, observation: dict,
                history: list[ToolCall]) -> list[ToolCall]:
        if self._done:
            return []
        self._done = True
        self.observation = self._invoke()
        return list(self.observation.tool_calls)

    def _invoke(self) -> ProviderObservation:  # pragma: no cover - protocol
        raise NotImplementedError
