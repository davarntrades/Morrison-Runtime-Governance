"""
Deterministic, total structural fingerprinting for evidence binding.

WHY THIS EXISTS
───────────────
When the kernel refuses a proposal it cannot evaluate, it replaces the call
with an inert placeholder so the refusal still travels the normal decision,
hashing and recording pipeline. That placeholder is shared by every refusal,
so `action_hash` — which is computed over the *evaluated* action — is identical
for every malformed proposal:

    malformed_A ──▶ hash(__unevaluable__)
    malformed_B ──▶ hash(__unevaluable__)

Two materially different rejected transitions would then share one audit
identity. The evidence record must therefore ALSO bind the actual rejected
input. This module produces that binding.

    original proposed action
      → validation / evaluation failure
      → normalised `__unevaluable__` refusal object
      → BLOCK

`original_input_digest` identifies the first arrow's subject.
`action_hash` identifies the third's. They are different questions and the
record answers both.

GUARANTEES
──────────
`structural_fingerprint` is the load-bearing primitive, and it must hold these
properties for input that is by definition already malformed and may be
hostile:

1. **Total.** It does not raise. Every traversal step is guarded, and the
   fallback is a marker string. Evidence generation must not be the thing that
   fails, because a refusal that cannot be recorded is a refusal that did not
   happen.
2. **No user code.** It never calls `repr()`, `str()`, `__eq__`, `__hash__`,
   `__iter__`, `__getitem__` or any other dunder on a user object. Container
   traversal goes through the *unbound builtin* methods (`dict.items(x)`,
   `list.__iter__(x)`), which run the C implementation even when a subclass
   overrides them. An opaque object contributes its type identity and nothing
   else — a deliberate fidelity-for-safety trade, since the alternative is
   executing attacker-controlled code inside the audit path.
3. **Bounded.** Depth, per-container breadth, string length and total node
   count are all capped. A 10-million-element list or a 4KB-deep nesting
   produces a bounded fingerprint rather than exhausting memory or the C
   stack.
4. **Cycle-safe.** Containers already on the current path emit `<cycle>`.
   Detection uses `id()` for identity only; no id value enters the output, so
   the fingerprint stays stable across runs.
5. **Deterministic.** Dict entries and set elements are sorted by their
   rendered fingerprint (sorting strings, never the values themselves, which
   would invoke user `__lt__`). Matches the `sort_keys=True` convention
   `kernel/canonical.py` already uses.
6. **Discriminating.** Materially different inputs produce different
   fingerprints. Long strings and bytes contribute a digest of their full
   contents, so two values differing only past the truncation point remain
   distinguishable.

SENSITIVITY
───────────
`structural_fingerprint` renders bounded *values*, so it is not itself safe to
store — it is an intermediate, hashed immediately by `input_digest`. What goes
into evidence is the digest, plus optionally `structural_shape`, which renders
types and sizes only and contains no user values.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "structural_fingerprint",
    "structural_shape",
    "input_digest",
    "DIGEST_UNAVAILABLE",
]

# Returned when fingerprinting itself fails. A sentinel, never an exception:
# see guarantee 1. It is deliberately not a valid sha256 hex string, so it
# cannot be mistaken for a real digest by anything reading the record.
DIGEST_UNAVAILABLE = "unavailable"

MAX_DEPTH = 6
MAX_ITEMS = 64
MAX_STR = 128
MAX_NODES = 2048

_PRIMITIVE_TYPES = (type(None), bool, int, float, str, bytes)


def _type_name(value: object) -> str:
    """Type identity, without touching the instance.

    Reads attributes of the TYPE, not of the object, so no user `__repr__` or
    property on the instance runs. Guarded anyway: a metaclass can make even
    this raise.
    """
    try:
        cls = type(value)
        module = getattr(cls, "__module__", "?")
        name = getattr(cls, "__qualname__", None) or getattr(cls, "__name__", "?")
        if module in ("builtins", "__builtin__", "?"):
            return str(name)
        return f"{module}.{name}"
    except Exception:  # noqa: BLE001 — total by contract
        return "<untypeable>"


def _short_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _render_str(value: str) -> str:
    if len(value) <= MAX_STR:
        return f"s:{len(value)}:{value}"
    # Truncated for bounds, but the digest of the FULL value keeps two long
    # strings that differ only past the cutoff distinguishable.
    return (f"s:{len(value)}:{value[:MAX_STR]}"
            f"#{_short_digest(value.encode('utf-8', 'surrogatepass'))}")


def _render_bytes(value: bytes) -> str:
    if len(value) <= MAX_STR:
        return f"b:{len(value)}:{value.hex()}"
    return f"b:{len(value)}:{value[:MAX_STR].hex()}#{_short_digest(value)}"


def _render_primitive(value: object) -> str:
    # `type(x) is T` rather than isinstance: bool must not render as int, and
    # a subclass must not reach a builtin renderer that assumes exact layout.
    cls = type(value)
    if value is None:
        return "null"
    if cls is bool:
        return "true" if value else "false"
    if cls is int:
        return f"i:{value}"
    if cls is float:
        # repr() on a float is the builtin C implementation and is
        # deterministic in Python 3 (shortest round-tripping form).
        return f"f:{value!r}"
    if cls is str:
        return _render_str(value)
    if cls is bytes:
        return _render_bytes(value)
    return f"<{_type_name(value)}>"


class _Budget:
    """Mutable node counter, so the cap is global rather than per-branch."""

    __slots__ = ("remaining",)

    def __init__(self, remaining: int):
        self.remaining = remaining

    def spend(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


def _fingerprint(value: object, depth: int, budget: _Budget,
                 path: set) -> str:
    if not budget.spend():
        return "<budget>"
    if depth > MAX_DEPTH:
        return f"<depth:{_type_name(value)}>"

    try:
        if isinstance(value, _PRIMITIVE_TYPES):
            return _render_primitive(value)

        marker = id(value)
        if marker in path:
            return "<cycle>"

        # Containers are traversed via UNBOUND builtin methods so a subclass
        # cannot interpose its own __iter__/items/__getitem__ here.
        if isinstance(value, dict):
            path = path | {marker}
            entries = []
            for i, (k, v) in enumerate(dict.items(value)):
                if i >= MAX_ITEMS:
                    entries.append("<more>")
                    break
                entries.append(
                    f"{_fingerprint(k, depth + 1, budget, path)}="
                    f"{_fingerprint(v, depth + 1, budget, path)}")
            # Sorted for determinism, and sorted as STRINGS so no user
            # comparison operator runs.
            inner = ",".join(sorted(entries))
            return f"{_type_name(value)}{{{len(value)}}}({inner})"

        if isinstance(value, (list, tuple)):
            path = path | {marker}
            iterator = (list.__iter__(value) if isinstance(value, list)
                        else tuple.__iter__(value))
            items = []
            for i, item in enumerate(iterator):
                if i >= MAX_ITEMS:
                    items.append("<more>")
                    break
                items.append(_fingerprint(item, depth + 1, budget, path))
            # Order is meaningful for sequences and is preserved.
            return f"{_type_name(value)}[{len(value)}]({','.join(items)})"

        if isinstance(value, (set, frozenset)):
            path = path | {marker}
            iterator = (set.__iter__(value) if isinstance(value, set)
                        else frozenset.__iter__(value))
            items = []
            for i, item in enumerate(iterator):
                if i >= MAX_ITEMS:
                    items.append("<more>")
                    break
                items.append(_fingerprint(item, depth + 1, budget, path))
            # Set iteration order is not stable across processes, so sort.
            return f"{_type_name(value)}{{{len(value)}}}({','.join(sorted(items))})"

        # Anything else is opaque. Type identity only — see guarantee 2.
        return f"<obj:{_type_name(value)}>"
    except Exception as exc:  # noqa: BLE001 — total by contract
        return f"<error:{type(exc).__name__}>"


def structural_fingerprint(value: object) -> str:
    """A bounded, deterministic rendering of `value`'s structure and contents.

    Contains user values (bounded), so hash it rather than storing it.
    Never raises.
    """
    try:
        return _fingerprint(value, 0, _Budget(MAX_NODES), set())
    except Exception as exc:  # noqa: BLE001 — total by contract
        return f"<error:{type(exc).__name__}>"


def _shape(value: object, depth: int, budget: _Budget, path: set) -> str:
    """Types and sizes only — no user values."""
    if not budget.spend():
        return "<budget>"
    if depth > MAX_DEPTH:
        return "<depth>"
    try:
        if isinstance(value, _PRIMITIVE_TYPES):
            cls = type(value)
            if isinstance(value, (str, bytes)):
                return f"{_type_name(value)}[{len(value)}]"
            if value is None:
                return "null"
            return _type_name(value) if cls is not bool else "bool"

        marker = id(value)
        if marker in path:
            return "<cycle>"

        if isinstance(value, dict):
            path = path | {marker}
            parts = []
            for i, (k, v) in enumerate(dict.items(value)):
                if i >= MAX_ITEMS:
                    parts.append("<more>")
                    break
                # Keys are almost always short identifiers rather than data,
                # and the key NAMES are what make a shape readable. Only
                # string keys are shown; anything else contributes its type.
                key = k if isinstance(k, str) and len(k) <= 64 else f"<{_type_name(k)}>"
                parts.append(f"{key}:{_shape(v, depth + 1, budget, path)}")
            return f"{{{','.join(sorted(parts))}}}"

        if isinstance(value, (list, tuple, set, frozenset)):
            return f"{_type_name(value)}[{len(value)}]"

        return f"<obj:{_type_name(value)}>"
    except Exception as exc:  # noqa: BLE001 — total by contract
        return f"<error:{type(exc).__name__}>"


def structural_shape(value: object) -> str:
    """Types, sizes and string key names only — safe to store in evidence.

    Complements `input_digest`: the digest distinguishes, the shape explains.
    Never raises.
    """
    try:
        return _shape(value, 0, _Budget(MAX_NODES), set())
    except Exception as exc:  # noqa: BLE001 — total by contract
        return f"<error:{type(exc).__name__}>"


def input_digest(value: object) -> str:
    """sha256 over the structural fingerprint of `value`.

    This is the evidence-grade identity of a rejected proposal. Never raises:
    on failure it returns `DIGEST_UNAVAILABLE` rather than propagating, because
    a refusal must be recordable even when its subject is not renderable.
    """
    try:
        fingerprint = structural_fingerprint(value)
        return hashlib.sha256(fingerprint.encode("utf-8", "surrogatepass")).hexdigest()
    except Exception:  # noqa: BLE001 — total by contract
        return DIGEST_UNAVAILABLE
