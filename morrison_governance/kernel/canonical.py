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

    THE ARGUMENT SPELLINGS

    Frameworks do not agree on where a call's arguments live. OpenAI emits
    `arguments` (as a JSON STRING), LangChain emits `tool_input`, MCP emits
    `input`, and `TrajectoryExtractor` has always accepted all of them. This
    function only understood `args`, so the others were folded in as an
    ORDINARY FIELD — `{"tool": "reply", "input": {...}}` canonicalised to
    `{"tool": "reply", "args": {"input": {...}}}`, one level too deep.

    The Ω evaluation namespace is a shallow view of `args`, so nothing in that
    payload was visible to a single-step rule: a crisis reply, a PII egress, a
    privileged role change all read as an action with no arguments and cleared
    every Ω rule. Capability and sensitivity classification still walked the
    nested structure, so the action was not ungoverned — but the Ω layer was
    blind to it, which is the layer a sector deployment writes its rules in.

    The aliases are now unwrapped to the same canonical place, and a JSON
    string is parsed, so one transition has one canonical form however the
    caller's framework spells it.
    """
    tool = str(call.get("tool", "")).strip().lower()

    raw_args = call.get("args")
    if raw_args is None:
        for alias in ("arguments", "input", "tool_input", "parameters"):
            if alias in call:
                raw_args = call[alias]
                break

    # A JSON object arriving as text is that object, not an opaque blob.
    if isinstance(raw_args, str):
        stripped = raw_args.strip()
        if stripped[:1] in ("{", "["):
            try:
                parsed = json.loads(stripped)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, dict):
                raw_args = parsed

    args: dict = dict(raw_args) if isinstance(raw_args, dict) else {}
    if raw_args is not None and not isinstance(raw_args, dict):
        args["_positional"] = raw_args
    for k, v in call.items():
        if k in ("tool", "args", "arguments", "input", "tool_input", "parameters"):
            continue
        args.setdefault(str(k), v)
    return {"tool": tool, "args": _norm(args)}


def canonical_json(call: dict) -> str:
    return json.dumps(canonicalize(call), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def action_hash(call: dict) -> str:
    """Stable sha256 over exact canonical bytes for execution binding."""
    return hashlib.sha256(canonical_json(call).encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────
# Authorization identity
# ─────────────────────────────────────────────────────────────

def authorization_equivalence_manifest(equivalences: dict | None) -> dict:
    """Canonical, validated representation of trusted alias equivalences.

    Input is ``{identity: iterable_of_tool_names}``. Membership is explicit:
    broad capability or semantic-family membership is never consulted. A tool
    may belong to at most one identity.
    """
    from morrison_governance.kernel.normalize import normalized_tool_name

    manifest: dict[str, list[str]] = {}
    owners: dict[str, str] = {}
    for identity, aliases in sorted(
            (equivalences or {}).items(), key=lambda item: str(item[0])):
        group = normalized_tool_name(identity)
        if not group:
            raise ValueError("authorization equivalence identity is empty")
        if isinstance(aliases, str):
            aliases = (aliases,)
        names = sorted({normalized_tool_name(alias) for alias in aliases})
        if not names or any(not name for name in names):
            raise ValueError(
                f"authorization equivalence {identity!r} has empty aliases")
        for name in names:
            prior = owners.setdefault(name, group)
            if prior != group:
                raise ValueError(
                    f"tool {name!r} appears in authorization equivalences "
                    f"{prior!r} and {group!r}")
        manifest[group] = names
    return manifest


def authorization_canonical(call: dict,
                            equivalences: dict | None = None) -> dict:
    """Exact authorization identity, with only explicitly trusted widening."""
    from morrison_governance.kernel.normalize import normalized_tool_name

    canon = canonicalize(call)
    tool = normalized_tool_name(canon["tool"])
    identity = f"tool:{tool}"
    for group, aliases in authorization_equivalence_manifest(
            equivalences).items():
        if tool in aliases:
            identity = f"equivalence:{group}"
            break
    return {"tool_identity": identity, "args": canon["args"]}


def authorization_action_hash(call: dict,
                              equivalences: dict | None = None) -> str:
    """Hash of the exact action semantics an approval authorizes."""
    payload = json.dumps(
        authorization_canonical(call, equivalences), sort_keys=True,
        separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────
# Semantic identity
# ─────────────────────────────────────────────────────────────
# `action_hash` above binds the BYTES of a proposal, which is what execution
# binding needs: `authorize A -> mutate -> execute B` must fail. It is the
# wrong identity for POLICY, because two spellings of one transition hash
# differently — `shell` and `run_shell` carrying the same command, or a
# collector written as `attacker.example` and as its percent-encoded form.
#
# `semantic_action_hash` binds the broad TRANSITION class instead: the
# canonical tool family and normalised, fully-traversed argument content.
# Classification and revocation use it. Approval authority deliberately uses
# `authorization_action_hash` above, because a broad family is not proof that
# two executors have equivalent effects.


def semantic_canonical(call: dict) -> dict:
    """The canonical SEMANTIC form of a call: tool family + normalised text."""
    from morrison_governance.kernel.normalize import normalize_action

    norm = normalize_action(call)
    return {
        "tool_family": norm.tool,
        "text": norm.semantic_text,
        "hosts": sorted(norm.hosts),
        "truncated": norm.truncated,
    }


def semantic_action_hash(call: dict) -> str:
    """Stable sha256 over the canonical semantic action.

    Two proposals that denote the same transition share this hash even when
    their bytes differ. A payload that could not be fully traversed is marked
    `truncated`, which changes the hash — a partially-read action is not the
    same action as a fully-read one, and must not inherit its authorisations.
    """
    payload = json.dumps(semantic_canonical(call), sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
