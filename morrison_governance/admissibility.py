"""
V4 — State-space admissibility layer.

Whereas A_safe asks "does this action enter a forbidden Ω state?", V4 asks
"is this caller, with this role, in this context, even allowed to attempt
this action?". V4 enforces structural preconditions: permissions, resource
scope, schema validity, required context, capability bounds, and quotas.

V4 sits between V3 and V4+ in the strict-strengthening hierarchy:

    A_safe ⊂ V2 ⊂ V3 ⊂ V4 ⊂ V4+ ⊂ V5

Determinism: every check is a pure function of the state dict. No I/O,
no clocks, no random. The result is fully reproducible from the input.
"""

# Builtin generic subscripts (dict[...], list[...]) appear in class-level
# annotations below, which are evaluated at class-creation time and require
# Python 3.9+. Deferring evaluation keeps the syntax and the module
# importable on older interpreters.
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


# A check returns None if the state is admissible, otherwise a reason string.
CheckFn = Callable[[dict], Optional[str]]


@dataclass
class AdmissibilityCheck:
    """A single admissibility check on a flattened trajectory state."""

    name: str
    description: str
    check: CheckFn
    severity: str = "structural"

    def evaluate(self, state: dict) -> Optional[str]:
        return self.check(state)


# ─────────────────────────────────────────────────────────────
# Default check builders
# ─────────────────────────────────────────────────────────────

def role_required(tool_names: tuple[str, ...], required_roles: tuple[str, ...],
                  role_field: str = "role") -> AdmissibilityCheck:
    """Caller's role (in `state[role_field]`) must be one of `required_roles`
    when the call targets one of `tool_names`."""
    tools = set(tool_names)
    roles = set(required_roles)
    return AdmissibilityCheck(
        name=f"role_required({'/'.join(tool_names)} → {'/'.join(required_roles)})",
        description=(
            f"calls to {sorted(tools)} require role in {sorted(roles)}"
        ),
        check=lambda s: (
            None if (s.get("tool") not in tools)
            else (None if s.get(role_field) in roles
                  else f"role={s.get(role_field)!r} not in {sorted(roles)}")
        ),
    )


def resource_scope(tool_names: tuple[str, ...], scope_field: str,
                   allowed_prefixes: tuple[str, ...]) -> AdmissibilityCheck:
    """For calls to `tool_names`, the value at `state[scope_field]` (typically
    a path or URL) must start with one of `allowed_prefixes`."""
    tools = set(tool_names)
    return AdmissibilityCheck(
        name=f"resource_scope({'/'.join(tool_names)} ↾ {scope_field})",
        description=(
            f"{scope_field} must start with one of {list(allowed_prefixes)} "
            f"for tools {sorted(tools)}"
        ),
        check=lambda s: (
            None if s.get("tool") not in tools
            else (None if any(str(s.get(scope_field, "")).startswith(p)
                              for p in allowed_prefixes)
                  else f"{scope_field}={s.get(scope_field)!r} outside "
                       f"allowed prefixes {list(allowed_prefixes)}")
        ),
    )


def required_fields(tool_names: tuple[str, ...],
                    required: tuple[str, ...]) -> AdmissibilityCheck:
    """Calls to `tool_names` must carry all `required` fields with truthy values."""
    tools = set(tool_names)
    req = tuple(required)
    return AdmissibilityCheck(
        name=f"required_fields({'/'.join(tool_names)})",
        description=f"{sorted(tools)} require fields {list(req)}",
        check=lambda s: (
            None if s.get("tool") not in tools
            else (None if all(s.get(f) not in (None, "", 0, False) for f in req)
                  else "missing/empty required field(s): "
                       + ", ".join(f for f in req if s.get(f) in (None, "", 0, False)))
        ),
    )


def quota_limit(actor_field: str, count_field: str,
                max_count: int) -> AdmissibilityCheck:
    """Reject when the per-actor count exceeds `max_count`."""
    return AdmissibilityCheck(
        name=f"quota_limit({actor_field}, {count_field} ≤ {max_count})",
        description=(
            f"each {actor_field} may not exceed {max_count} {count_field}"
        ),
        check=lambda s: (
            None if s.get(count_field, 0) <= max_count
            else f"{count_field}={s.get(count_field)} > {max_count} "
                 f"for {actor_field}={s.get(actor_field)!r}"
        ),
    )


def schema_required(tool_name: str,
                    arg_types: dict[str, type]) -> AdmissibilityCheck:
    """Tool args must contain each key in `arg_types` with the declared type."""
    return AdmissibilityCheck(
        name=f"schema_required({tool_name})",
        description=(
            f"{tool_name} args must include "
            + ", ".join(f"{k}: {v.__name__}" for k, v in arg_types.items())
        ),
        check=lambda s: (
            None if s.get("tool") != tool_name
            else _schema_violations(s, arg_types)
        ),
    )


def _schema_violations(state: dict, arg_types: dict[str, type]) -> Optional[str]:
    missing = [k for k in arg_types if k not in state]
    if missing:
        return f"missing arg(s): {missing}"
    bad = [k for k, t in arg_types.items() if not isinstance(state.get(k), t)]
    if bad:
        return ("type mismatch: "
                + ", ".join(f"{k}={state.get(k)!r} (expected {arg_types[k].__name__})"
                            for k in bad))
    return None


def default_admissibility_checks() -> list[AdmissibilityCheck]:
    """A starter pack of structural admissibility checks for common shapes."""
    return [
        role_required(
            tool_names=("transfer", "send_payment", "execute_trade", "withdraw"),
            required_roles=("treasury", "admin", "trader"),
        ),
        role_required(
            tool_names=("update_role", "grant_permission", "modify_acl",
                        "delete", "drop_table"),
            required_roles=("admin",),
        ),
        resource_scope(
            tool_names=("read_file", "write_file"),
            scope_field="path",
            allowed_prefixes=("/data/", "/reports/", "/tmp/", "/home/user/"),
        ),
        required_fields(
            tool_names=("send_email",),
            required=("to",),
        ),
        quota_limit(
            actor_field="actor_id",
            count_field="actions_today",
            max_count=10_000,
        ),
    ]


@dataclass
class AdmissibilityEvaluator:
    """Runs a set of AdmissibilityCheck functions against trajectory states."""

    checks: list[AdmissibilityCheck] = field(default_factory=list)

    def evaluate(self, state_dict: dict) -> Optional[tuple[str, str]]:
        """Returns (check_name, reason) for the first failing check, else None."""
        for chk in self.checks:
            reason = chk.evaluate(state_dict)
            if reason is not None:
                return (chk.name, reason)
        return None
