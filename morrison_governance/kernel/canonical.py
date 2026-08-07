"""Canonical action representation + action hashing.

The governance decision is bound to a canonical, immutable representation of
the action. The runtime may only execute an action whose canonical hash equals
the hash the decision was issued for — this is what makes

    evaluate(A) -> mutate -> execute(B)

structurally impossible rather than merely discouraged.

Canonicalisation is deterministic: sorted keys, normalised scalars, no clock,
no RNG. The same action always produces the same hash in any process.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Keys that carry no semantic weight and must not perturb the hash.
_VOLATILE_KEYS = frozenset({
    "_trace_id", "_request_id", "_span_id", "_ts", "_timestamp",
    "_governance", "_evidence",
})


def _norm(value: Any) -> Any:
    """Normalise a scalar/container into its canonical form.

    Deterministic and total: unknown objects degrade to their repr rather than
    raising, so canonicalisation never fails open on an exotic payload.
    """
    if isinstance(value, dict):
        return {str(k): _norm(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
                if str(k) not in _VOLATILE_KEYS}
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        # 1 and 1.0 must not hash differently.
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value
    if isinstance(value, str):
        return value
    return repr(value)


def canonicalize(call: dict) -> dict:
    """Return the canonical form of a tool call: {"tool": str, "args": dict}.

    Any extra top-level keys are folded into args so that a caller cannot move
    a field between levels to change the hash while keeping the meaning.
    """
    tool = str(call.get("tool", "")).strip().lower()
    raw_args = call.get("args")
    args: dict = dict(raw_args) if isinstance(raw_args, dict) else {}
    if raw_args is not None and not isinstance(raw_args, dict):
        args["_positional"] = raw_args
    for k, v in call.items():
        if k in ("tool", "args"):
            continue
        args.setdefault(str(k), v)
    return {"tool": tool, "args": _norm(args)}


def canonical_json(call: dict) -> str:
    return json.dumps(canonicalize(call), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def action_hash(call: dict) -> str:
    """Stable sha256 over the canonical action. This is the identity that a
    governance decision, an approval artifact, and an execution all refer to."""
    return hashlib.sha256(canonical_json(call).encode("utf-8")).hexdigest()
