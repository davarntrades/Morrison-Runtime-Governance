"""Multi-agent planner abstraction.

Each agent has an id, a role, its own memory, its own local
observation, and a deterministic plan (a script of tool calls). Agents
propose one tool call per turn. Deterministic stand-ins are primary; a
CallableAgent seam allows a live planner (e.g. a runtime_eval HF
planner) to be plugged in later without changing the harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


ToolCall = dict   # {"tool": str, "args": dict}


@dataclass
class Agent:
    """Deterministic scripted agent. `script` is an ordered list of tool
    calls (optionally a callable `fn(env, local_history) -> ToolCall|None`
    for dynamic agents, e.g. one whose next action depends on shared
    state written by another agent)."""

    agent_id: str
    role: str
    script: list = field(default_factory=list)
    memory: dict = field(default_factory=dict)
    deterministic: bool = True
    _i: int = 0

    def reset(self) -> None:
        self._i = 0

    def propose(self, env, local_history: list) -> Optional[ToolCall]:
        if callable(self.script):
            # Guarded by callable() on the line above; pylint cannot narrow
            # the union type through it.
            return self.script(env, local_history)  # pylint: disable=not-callable
        if self._i >= len(self.script):
            return None
        call = self.script[self._i]
        self._i += 1
        if callable(call):
            return call(env, local_history)
        return {"tool": call["tool"], "args": dict(call.get("args", {}))}


@dataclass
class CallableAgent:
    """Live-planner seam: `fn(env, local_history) -> ToolCall | None`.
    Set `deterministic=False` when the callable involves model sampling
    (replay byte-identity is then not guaranteed for that agent)."""

    agent_id: str
    role: str
    fn: Callable
    deterministic: bool = False
    memory: dict = field(default_factory=dict)

    def reset(self) -> None:
        pass

    def propose(self, env, local_history: list) -> Optional[ToolCall]:
        return self.fn(env, local_history)
