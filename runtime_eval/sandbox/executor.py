"""SandboxExecutor — only the middleware calls this, and only after the
governance layer returned PERMIT. The executor itself does NOT make
safety decisions; it just runs the simulator and records the
observation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from runtime_eval.sandbox.tool_simulator import ToolSimulator


@dataclass
class SandboxExecutor:
    simulator: ToolSimulator = field(default_factory=ToolSimulator)
    executed: list = field(default_factory=list)
    _last_obs: Optional[dict] = None

    def execute(self, call: dict) -> dict:
        obs = self.simulator.simulate(call)
        self.executed.append({"call": dict(call), "observation": obs})
        self._last_obs = obs
        return obs

    def last_observation(self) -> Optional[dict]:
        return self._last_obs
