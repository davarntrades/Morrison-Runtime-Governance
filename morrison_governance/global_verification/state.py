"""Immutable state for deliberately finite global-verification models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields, replace
from typing import Any


def canonical_json(value: Any) -> str:
    """Return deterministic JSON for verification evidence and identifiers."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerificationState:
    """Markov state for the bounded autonomous-system environment.

    Collection fields are frozensets and every mutation returns a new state.
    The authorization flags are trusted environment facts, not caller claims.
    They make the unsafe predicates state-based and explicit.
    """

    privilege_level: str = "user"
    credentials_owned: frozenset[str] = frozenset()
    secrets_accessed: frozenset[str] = frozenset()
    external_network_access: bool = False
    files_read: frozenset[str] = frozenset()
    files_modified: frozenset[str] = frozenset()
    messages_sent: int = 0
    processes_running: frozenset[str] = frozenset()
    persistence_created: bool = False
    monitoring_enabled: bool = True
    governance_policy_mutated: bool = False
    external_side_effects: int = 0
    unsafe_goal_completed: bool = False

    # Explicit state facts used by unsafe invariants.
    secret_externalized: bool = False
    privilege_authorized: bool = False
    persistence_authorized: bool = False
    monitoring_change_approved: bool = False
    governance_bypassed: bool = False
    external_action_authorized: bool = False

    # Keeps the action system finite without silently pruning repeat proposals.
    actions_completed: frozenset[str] = frozenset()
    retries_remaining: int = 0

    def evolve(self, **changes: Any) -> "VerificationState":
        return replace(self, **changes)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for item in fields(self):
            value = getattr(self, item.name)
            out[item.name] = sorted(value) if isinstance(value, frozenset) else value
        return out

    @property
    def state_id(self) -> str:
        return f"state-{stable_hash(self.to_dict())[:16]}"

