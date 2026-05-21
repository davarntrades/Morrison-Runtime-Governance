"""Strict structural schema validation for tool calls.

Per-domain schemas declare required arg keys, allowed types, and
forbidden value shapes. A malformed call is rejected at the harness
boundary BEFORE the reachability hierarchy runs — fail-closed by
construction. No pydantic dependency: a tiny pure-Python validator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class FieldSpec:
    required: bool = False
    type_: Optional[type] = None
    one_of: Optional[tuple] = None
    forbidden_substrings: tuple = ()           # in the str() of the value
    predicate: Optional[Callable[[Any], bool]] = None
    notes: str = ""


@dataclass
class Schema:
    tool: str
    fields: dict = field(default_factory=dict)         # name → FieldSpec
    forbidden_extra_keys: tuple = ()                   # explicit deny


@dataclass
class ValidationReport:
    ok: bool
    violations: list = field(default_factory=list)     # list[str]

    def as_dict(self) -> dict:
        return {"ok": self.ok, "violations": list(self.violations)}


# A handful of starter schemas — extend per domain.
SCHEMAS: dict[str, Schema] = {
    "transfer": Schema(
        tool="transfer",
        fields={
            "amount":   FieldSpec(required=True, type_=(int, float),
                                   predicate=lambda v: float(v) >= 0,
                                   notes="amount must be a non-negative number"),
            "to":       FieldSpec(required=True, type_=str),
            "authorized": FieldSpec(type_=bool),
        }),
    "http_request": Schema(
        tool="http_request",
        fields={
            "url":    FieldSpec(required=True, type_=str),
            "method": FieldSpec(type_=str,
                                 one_of=("GET", "POST", "PUT", "DELETE",
                                          "PATCH", "HEAD", "OPTIONS")),
            "body":   FieldSpec(type_=(str, dict, bytes)),
        }),
    "read_file": Schema(
        tool="read_file",
        fields={"path": FieldSpec(required=True, type_=str)},
    ),
    "shell": Schema(
        tool="shell",
        fields={"args": FieldSpec(type_=(str, list))},
        forbidden_extra_keys=("eval", "exec_inline"),
    ),
}


def _type_ok(value: Any, t) -> bool:
    if isinstance(t, tuple):
        return any(_type_ok(value, x) for x in t)
    return isinstance(value, t)


def validate(call: dict, schemas: dict = SCHEMAS) -> ValidationReport:
    """Validate a tool call against the registered schemas. Tools not
    in the schema table pass through (no constraint). Validation
    failures are deterministic, ordered messages."""

    tool = str(call.get("tool", "")).strip()
    if tool not in schemas:
        return ValidationReport(ok=True)
    schema = schemas[tool]
    args = call.get("args")
    if not isinstance(args, dict):
        return ValidationReport(ok=False, violations=[
            f"{tool}: args must be a dict, got {type(args).__name__}"])

    v: list = []
    for name, spec in schema.fields.items():
        if spec.required and name not in args:
            v.append(f"{tool}.{name}: required field missing")
            continue
        if name not in args:
            continue
        val = args[name]
        if spec.type_ is not None and not _type_ok(val, spec.type_):
            v.append(f"{tool}.{name}: type mismatch "
                      f"(expected {spec.type_}, got {type(val).__name__})")
        if spec.one_of is not None and val not in spec.one_of:
            v.append(f"{tool}.{name}: value {val!r} not in "
                      f"{spec.one_of}")
        if spec.forbidden_substrings:
            s = str(val).lower()
            for sub in spec.forbidden_substrings:
                if sub in s:
                    v.append(f"{tool}.{name}: forbidden substring "
                              f"{sub!r}")
        if spec.predicate is not None:
            try:
                if not spec.predicate(val):
                    v.append(f"{tool}.{name}: predicate failed"
                              + (f" ({spec.notes})" if spec.notes else ""))
            except Exception as e:                  # noqa: BLE001
                v.append(f"{tool}.{name}: predicate raised "
                          f"{type(e).__name__}: {e}")
    for k in schema.forbidden_extra_keys:
        if k in args:
            v.append(f"{tool}: forbidden key {k!r} present")

    return ValidationReport(ok=not v, violations=v)
