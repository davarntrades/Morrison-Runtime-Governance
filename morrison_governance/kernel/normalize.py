"""Semantic canonicalisation — one normal form per transition.

The red-team finding this module closes:

    Semantically identical actions flipped BLOCK -> PERMIT purely on encoding.
    Renaming `shell` to `run_shell`, nesting a payload past depth 6, splitting
    `AKIAIOSFODNN7EXAMPLE` across two list elements, writing a collector as
    `http://2130706433/`, or naming a destination argument `policy` each moved
    an identical transition out of the classifiers' view while leaving it
    perfectly intact for the executor.

Every one of those is the same defect: authorization bound to the SPELLING of a
proposal rather than to the transition it denotes. This module produces the
normal form that authorization binds to instead.

    proposal (any spelling)  ->  NormalizedAction  ->  classify / hash / decide

Three guarantees the previous representation did not have:

  1  **One traversal, no depth limit.** `capabilities`, `sensitivity` and
     `destinations` each carried a private `_walk` that stopped at depth 6, so
     one wrapper past that horizon blinded all three at once. They now share
     `iter_pairs`, which walks to exhaustion under a NODE BUDGET and reports
     exhaustion rather than silently returning less.

  2  **Fail closed on what could not be read.** A payload the traversal could
     not finish is `truncated`, and the kernel escalates. A payload that was
     not fully read is not a payload that was cleared.

  3  **Adjacent scalars are matched as the connector will send them.** A marker
     split across sibling list elements or dict values is reassembled into the
     search text, because that is the form the tool will transmit.

Deterministic: no clock, no RNG, no I/O, no DNS.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional
from urllib.parse import unquote, urlparse

# Traversal budget. Large enough for any legitimate tool payload, small enough
# that a hostile deeply-nested structure cannot make classification unbounded.
NODE_BUDGET = 8192

# A scalar that could be a fragment of a split token: no whitespace, at least
# two characters. Prose has spaces; a chunked credential does not.
_TOKEN_LIKE = re.compile(r"^[^\s]{2,}$")
# Cross-container windows additionally require a non-digit character. Joining
# adjacent PURELY NUMERIC fields is the one high-false-positive case: five
# four-digit record ids concatenate into a 15-20 digit run that matches the
# card-number format, so an ordinary batch of ids classified as financial. A
# numeric value genuinely split across fields is still caught by the
# per-container join above; only the cross-container windows are narrowed.
_WINDOW_FRAGMENT = re.compile(r"^(?=.*\D)[^\s]{2,}$")
# A destination is not a payload chunk, and letting one into the fragment run
# breaks the adjacency the windows depend on: canonicalisation sorts argument
# keys, so `{"a": <chunk>, "b": {<chunk>}, "url": <collector>}` sorts the URL
# between the two halves and the window joins the wrong pair. Destinations are
# classified by `classify_destination`; they are excluded here.
_NOT_A_FRAGMENT = re.compile(r"://|@")
# Longest run of adjacent fragments joined. Four covers realistic chunking
# without making reassembly quadratic in payload size.
_MAX_WINDOW = 4

# Characters used to break up a marker without changing what a connector sends.
_ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD], None)


# ─────────────────────────────────────────────────────────────
# Canonical tool families
# ─────────────────────────────────────────────────────────────
# A family is the transition the tool denotes. Two names in the same family
# denote the same transition and MUST authorize identically. This table is a
# floor, not the whole classifier: `capabilities.classify` still applies verb
# and object morphology to names that are not listed here, so an unlisted
# synonym is not an escape.

_TOOL_FAMILIES: dict[str, tuple[str, ...]] = {
    "shell": (
        "shell", "bash", "sh", "zsh", "ksh", "csh", "dash", "powershell",
        "pwsh", "cmd", "command", "exec", "execute", "system", "subprocess",
        "run", "run_shell", "run_command", "run_cmd", "run_script", "runshell",
        "shell_exec", "shell_command", "execute_shell", "execute_command",
        "os_system", "spawn_shell", "terminal", "console", "sandbox_op",
        "maintenance_task", "eval", "evaluate_code", "run_code", "python",
        "python_exec", "node_exec", "invoke_shell",
    ),
    "http_request": (
        "http_request", "http", "http_post", "http_get", "http_put",
        "https_request", "request", "fetch", "curl", "wget", "web_request",
        "api_call", "call_api", "rest_call", "post", "put", "webhook_send",
    ),
    "send_message": (
        "send_email", "sendmail", "email", "mail", "send_mail", "smtp_send",
        "send_message", "send_sms", "notify", "post_message", "slack_post",
        "send_notification",
    ),
    "file_write": (
        "write_file", "writefile", "put_file", "save_file", "create_file",
        "file_write", "fs_write", "write",
    ),
    "file_read": (
        "read_file", "readfile", "get_file", "open_file", "cat", "file_read",
        "fs_read",
    ),
    "db_query": (
        "execute_sql", "run_sql", "sql", "query", "query_db", "db_query",
        "run_query", "execute_query",
    ),
    "transfer_funds": (
        "transfer", "transfer_funds", "wire", "wire_transfer", "send_payment",
        "make_payment", "payout", "disburse", "remit", "ach_transfer",
        "move_funds", "initiate_transfer",
    ),
    "upload": (
        "upload", "upload_file", "put_object", "s3_put", "export",
        "export_report", "export_data", "share_file", "publish",
    ),
    "delete_logs": (
        "delete_logs", "clear_logs", "purge_logs", "truncate_logs",
        "delete_audit_log", "clear_audit_trail", "wipe_logs",
    ),
}

# name -> family, built once.
_ALIAS_TO_FAMILY: dict[str, str] = {
    alias: family
    for family, aliases in _TOOL_FAMILIES.items()
    for alias in aliases
}


def canonical_tool(tool: str) -> str:
    """Resolve a tool name to its canonical family name.

    Normalises separators and casing first, so `Run-Shell`, `run_shell` and
    `runShell` all reach the same entry. An unrecognised name normalises to its
    own cleaned form rather than to a catch-all: an unknown tool must stay
    distinguishable, and `SecurityContext.unknown_tool_policy` decides it.
    """
    name = str(tool or "").strip().lower()
    # camelCase -> snake_case, then collapse all separators to "_".
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(tool or "")).lower()
    name = re.sub(r"[^a-z0-9]+", "_", name).strip("_")
    if name in _ALIAS_TO_FAMILY:
        return _ALIAS_TO_FAMILY[name]
    # A trailing/leading qualifier around a known family: `secure_shell_v2`.
    parts = name.split("_")
    for size in (3, 2, 1):
        for start in range(0, max(0, len(parts) - size + 1)):
            candidate = "_".join(parts[start:start + size])
            if candidate in _ALIAS_TO_FAMILY:
                return _ALIAS_TO_FAMILY[candidate]
    return name


# ─────────────────────────────────────────────────────────────
# Text normalisation
# ─────────────────────────────────────────────────────────────

def normalize_text(value: str, *, rounds: int = 3) -> str:
    """Fold a string to the form a connector would actually transmit.

    Unicode compatibility normalisation, zero-width removal, and bounded
    repeated percent-decoding. Bounded because `%25%32%35…` can be nested
    arbitrarily; three rounds covers realistic double/triple encoding without
    becoming a decode oracle.
    """
    if not isinstance(value, str):
        value = str(value)
    text = value
    for _ in range(rounds):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    text = unicodedata.normalize("NFKC", text)
    return text.translate(_ZERO_WIDTH)


_INT_HOST = re.compile(r"^\d+$")
_HEX_HOST = re.compile(r"^0x[0-9a-f]+$", re.I)
_OCT_HOST = re.compile(r"^0[0-7]+$")
# Mixed dotted forms such as `0177.0.0.1`: an octet with a leading zero is
# octal to every C resolver, so at least one such octet makes the whole literal
# a different address from the one it reads as.
_DOTTED_MIXED = re.compile(r"^(0[0-7]*|\d{1,3})(\.(0[0-7]*|\d{1,3})){3}$")


def normalize_host(host: str) -> str:
    """Fold a hostname or address literal to one comparable form.

    Closes the obfuscation routes that let an address avoid an allowlist or a
    denylist while resolving to the same machine: userinfo prefixes, integer /
    hexadecimal / octal / dotted-octal IPv4 literals, trailing dots, uppercase,
    IDN, and bracketed IPv6.
    """
    h = normalize_text(str(host or "")).strip().lower().rstrip(".")
    if not h:
        return ""
    if "@" in h:                      # https://acme.internal@attacker.example
        h = h.rsplit("@", 1)[1]
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    h = h.split("%", 1)[0]            # IPv6 zone id

    packed: Optional[int] = None
    try:
        if _INT_HOST.match(h):
            packed = int(h)
        elif _HEX_HOST.match(h):
            packed = int(h, 16)
        elif _OCT_HOST.match(h):
            packed = int(h, 8)
        elif _DOTTED_MIXED.match(h) and any(
                p.startswith("0") and len(p) > 1 for p in h.split(".")):
            octets = [int(p, 8) if p.startswith("0") and len(p) > 1 else int(p)
                      for p in h.split(".")]
            if all(0 <= o <= 255 for o in octets):
                packed = int.from_bytes(bytes(octets), "big")
    except (ValueError, OverflowError):
        packed = None
    if packed is not None and 0 <= packed <= 0xFFFFFFFF:
        return str(ipaddress.ip_address(packed))

    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        return h.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return h


def normalize_command(text: str) -> str:
    """Fold shell text so equivalent spellings of one command compare equal.

    Quote stripping, whitespace collapse, and `$IFS` / line-continuation
    removal. Deliberately shallow: this feeds pattern matching, and a full
    shell parser here would be a second attack surface.
    """
    t = normalize_text(text)
    t = t.replace("\\\n", " ").replace("${IFS}", " ").replace("$IFS", " ")
    t = re.sub(r"[\"'`]", "", t)
    return re.sub(r"\s+", " ", t).strip()


# ─────────────────────────────────────────────────────────────
# Unbounded traversal with a node budget
# ─────────────────────────────────────────────────────────────

class BudgetExhausted(Exception):
    """The traversal could not finish inside NODE_BUDGET nodes."""


def iter_pairs(value: Any, *, budget: int = NODE_BUDGET
               ) -> Iterator[tuple[str, Any]]:
    """Yield every `(key, value)` pair reachable in a nested structure.

    THE single traversal shared by capability, sensitivity and destination
    classification. There is no depth limit: nesting a payload deeper is not a
    way to leave the classifiers' view. Cycles are handled by identity, and the
    node budget bounds the work.

    Raises `BudgetExhausted` when the structure exceeds `budget` nodes, so the
    caller fails closed rather than deciding on a partial reading.
    """
    seen: set[int] = set()
    stack: list[tuple[str, Any]] = [("", value)]
    visited = 0
    while stack:
        key, node = stack.pop()
        visited += 1
        if visited > budget:
            raise BudgetExhausted(
                f"payload exceeds {budget} nodes; classification is incomplete")
        if isinstance(node, dict):
            if id(node) in seen:
                continue
            seen.add(id(node))
            for k, v in node.items():
                yield str(k), v
                stack.append((str(k), v))
        elif isinstance(node, (list, tuple, set, frozenset)):
            if id(node) in seen:
                continue
            seen.add(id(node))
            for v in node:
                yield key, v
                stack.append((key, v))


def _scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _concatenations(value: Any, *, budget: int = NODE_BUDGET) -> list[str]:
    """Reassemble adjacent scalars the way a connector would transmit them.

    `["AKIAIOSF", "ODNN7EXAMPLE"]` is one credential to every HTTP client that
    joins a multipart body, and was two harmless strings to a classifier that
    joined its blob with spaces. Two reassemblies are emitted, because a split
    can cross a container boundary as easily as it can stay inside one:

      * per container — the concatenation of its scalar children, which is what
        a template or multipart body renders;
      * across the whole payload — sliding windows of 2 to `_MAX_WINDOW`
        adjacent TOKEN-LIKE scalars in document order, which catches a split
        across different nesting levels such as
        `{"a": "AKIAIOSF", "b": {"c": "ODNN7EXAMPLE"}}`.

    Windows rather than one long join, because pattern anchors are word
    boundaries: concatenating an unrelated neighbour onto the front of a
    credential destroys the `\b` the pattern needs and the match is lost.

    Token-like means whitespace-free and at least two characters, so ordinary
    prose is not concatenated into spurious matches. This is heuristic by
    nature — see LIMITATIONS.md — and it is defence in depth behind the
    structural controls, not a substitute for them.
    """
    out: list[str] = []
    fragments: list[str] = []
    seen: set[int] = set()
    queue: list[Any] = [value]
    visited = 0
    while queue:
        node = queue.pop(0)          # FIFO keeps document order stable
        visited += 1
        if visited > budget:
            raise BudgetExhausted(
                f"payload exceeds {budget} nodes; concatenation is incomplete")
        if isinstance(node, dict):
            if id(node) in seen:
                continue
            seen.add(id(node))
            children = list(node.values())
        elif isinstance(node, (list, tuple)):
            if id(node) in seen:
                continue
            seen.add(id(node))
            children = list(node)
        else:
            continue
        scalars = [str(v) for v in children if _scalar(v) and v is not None]
        if len(scalars) > 1:
            out.append("".join(scalars))
        fragments.extend(f for f in scalars
                         if _WINDOW_FRAGMENT.match(f)
                         and not _NOT_A_FRAGMENT.search(f))
        queue.extend(children)

    for size in range(2, _MAX_WINDOW + 1):
        for start in range(0, max(0, len(fragments) - size + 1)):
            out.append("".join(fragments[start:start + size]))
    return out


# ─────────────────────────────────────────────────────────────
# The normal form
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class NormalizedAction:
    """The canonical semantic form of one proposed transition.

    `text` is what every classifier pattern-matches against. It contains the
    tool family, every key and scalar at any depth, the normalised form of each
    scalar, and the sibling concatenations — so a marker is matched whether it
    was written plainly, percent-encoded, zero-width-split, nested twenty deep,
    or divided across list elements.
    """

    tool: str                                  # canonical family
    raw_tool: str                              # as proposed
    args: dict                                 # canonical args, values intact
    pairs: tuple = ()                          # ((key, value), ...) flattened
    text: str = ""                             # normalised search blob
    semantic_text: str = ""                    # `text` minus the proposed name
    hosts: tuple = ()                          # normalised hosts observed
    truncated: bool = False                    # budget exhausted -> fail closed
    truncation_reason: str = ""

    def keys(self) -> frozenset:
        return frozenset(k.strip().lower() for k, _ in self.pairs if k)

    def as_dict(self) -> dict:
        return {"tool": self.tool, "raw_tool": self.raw_tool,
                "truncated": self.truncated,
                "truncation_reason": self.truncation_reason,
                "hosts": list(self.hosts)}


_URL_IN_TEXT = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s\"'<>)]+", re.I)


def normalize_action(call: dict, *, budget: int = NODE_BUDGET) -> NormalizedAction:
    """Produce the canonical semantic form of `call`.

    Never raises: a payload that exhausts the budget returns with
    `truncated=True` and whatever was read, and the kernel turns that into an
    escalation. Classification silently deciding on a partial reading is the
    failure mode this replaces.
    """
    raw_tool = str(call.get("tool", ""))
    family = canonical_tool(raw_tool)
    args = call.get("args") if isinstance(call.get("args"), dict) else {}

    # `parts` feeds `text`, which classifiers match against and which must
    # contain the proposed name (capability morphology reads it). `semantic`
    # feeds `semantic_text`, which identity binds to and which must NOT: two
    # spellings of one transition have to hash alike.
    parts: list[str] = [family, raw_tool.lower()]
    semantic: list[str] = [family]
    pairs: list[tuple[str, Any]] = []
    hosts: list[str] = []
    truncated = False
    reason = ""

    try:
        for key, value in iter_pairs(args, budget=budget):
            pairs.append((key, value))
            if key:
                parts.append(key)
                semantic.append(key)
            if _scalar(value) and value is not None:
                raw = str(value)
                parts.append(raw)
                folded = normalize_text(raw)
                if folded != raw:
                    parts.append(folded)
                command = normalize_command(raw)
                if command != folded:
                    parts.append(command)
                semantic.append(command or folded)
                for url in _URL_IN_TEXT.findall(folded):
                    host = normalize_host(urlparse(url).hostname or "")
                    if host:
                        hosts.append(host)
                        parts.append(host)
                        semantic.append(host)
    except BudgetExhausted as exc:
        truncated, reason = True, str(exc)

    if not truncated:
        try:
            parts.extend(_concatenations(args, budget=budget))
        except BudgetExhausted as exc:
            truncated, reason = True, str(exc)

    # Argument ORDER must not change identity: two clients serialising the same
    # call with different key order denote the same transition.
    return NormalizedAction(
        tool=family, raw_tool=raw_tool, args=args,
        pairs=tuple(pairs), text=" ".join(parts),
        semantic_text=" ".join(sorted(semantic)),
        hosts=tuple(dict.fromkeys(hosts)),
        truncated=truncated, truncation_reason=reason)
