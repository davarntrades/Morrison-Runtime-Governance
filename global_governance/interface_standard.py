"""Formal interface standard — shared execution geometry.

For local + regional + global governance to compose, every component
must speak the same contract. This module pins that contract as a
versioned spec and provides a conformance checker so heterogeneous
governance components can be verified interoperable before composition.

The contract:
  - a ToolCall is {"tool": str, "args": dict}
  - a Trajectory is an ordered list[ToolCall]
  - a governance component exposes evaluate(call) and evaluate_plan(plan)
  - each returns an object with: verdict (enum w/ .value), permitted
    (bool), layer (str), metadata (dict), trajectory_hash (str)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


INTERFACE_VERSION = "1.0"

REQUIRED_METHODS = ("evaluate", "evaluate_plan")
REQUIRED_RESULT_ATTRS = ("verdict", "permitted", "layer", "metadata",
                          "trajectory_hash")


@dataclass
class ConformanceReport:
    version: str
    conformant: bool
    missing_methods: list = field(default_factory=list)
    missing_result_attrs: list = field(default_factory=list)
    notes: str = ""

    def as_dict(self) -> dict:
        return {"version": self.version, "conformant": self.conformant,
                "missing_methods": list(self.missing_methods),
                "missing_result_attrs": list(self.missing_result_attrs),
                "notes": self.notes}


def is_tool_call(obj: Any) -> bool:
    return (isinstance(obj, dict) and "tool" in obj
            and isinstance(obj.get("args", {}), dict))


def is_trajectory(obj: Any) -> bool:
    return isinstance(obj, (list, tuple)) and all(is_tool_call(o) for o in obj)


def check_conformance(component: Any,
                      probe_call: dict = None) -> ConformanceReport:
    """Verify a governance component conforms to the interface standard.

    Static check: required methods exist. Dynamic check (if a probe call
    is supplied): the result object exposes the required attributes."""
    missing_methods = [m for m in REQUIRED_METHODS
                       if not callable(getattr(component, m, None))]
    missing_attrs: list = []
    notes = "static-only"
    if not missing_methods and probe_call is not None:
        notes = "static+dynamic"
        try:
            result = component.evaluate(probe_call)
            for a in REQUIRED_RESULT_ATTRS:
                if not hasattr(result, a):
                    missing_attrs.append(a)
            # verdict must expose `.value`
            if hasattr(result, "verdict") and not hasattr(
                    result.verdict, "value"):
                missing_attrs.append("verdict.value")
        except Exception as e:                           # noqa: BLE001
            notes = f"probe raised {type(e).__name__}: {e}"
            missing_attrs.append("<probe-failed>")
    conformant = not missing_methods and not missing_attrs
    return ConformanceReport(
        version=INTERFACE_VERSION, conformant=conformant,
        missing_methods=missing_methods,
        missing_result_attrs=missing_attrs, notes=notes)
