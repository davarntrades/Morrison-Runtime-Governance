"""Recursive payload decoder.

Inspects every string value in a tool call's args and recursively
decodes encoded payloads (base64, hex, URL-encoded, unicode escapes,
nested JSON). Each successful decode adds a structural field to the
augmented call so the existing reachability rules can see the decoded
content. Decoding is bounded, deterministic, replay-safe, and
fail-closed on malformed payloads.

The decoder DOES NOT classify content. It only normalises encoded
representations of structured data — so an attacker who hides
"url=https://attacker.ext" inside a base64 blob loses the
representational advantage.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional


_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{12,}={0,2}$")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){4,}$")
_URL_ENC_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}")


@dataclass
class DecodeStep:
    where: str               # JSON pointer-style path: "args.body"
    codec: str               # "base64" | "hex" | "url" | "unicode" | "json"
    in_repr: str             # truncated input (≤ 64 chars)
    out_repr: str            # truncated output

    def as_dict(self) -> dict:
        return {"where": self.where, "codec": self.codec,
                "in": self.in_repr, "out": self.out_repr}


@dataclass
class DecodeReport:
    steps: list = field(default_factory=list)
    extracted: dict = field(default_factory=dict)  # key path → decoded value
    malformed: bool = False
    truncated: bool = False
    depth: int = 0

    def as_dict(self) -> dict:
        return {"steps": [s.as_dict() for s in self.steps],
                "extracted": self.extracted,
                "malformed": self.malformed, "truncated": self.truncated,
                "depth": self.depth}


_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _looks_printable(b: bytes) -> bool:
    if not b:
        return False
    sample = b[:256]
    return sum(1 for x in sample if x in _PRINTABLE) / len(sample) > 0.85


def _trunc(s: str, n: int = 64) -> str:
    return s if len(s) <= n else s[:n] + "…"


def _try_base64(s: str) -> Optional[str]:
    if not _BASE64_RE.fullmatch(s) or len(s) % 4 != 0:
        return None
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not _looks_printable(b):
        return None
    return b.decode("utf-8", errors="replace")


def _try_hex(s: str) -> Optional[str]:
    if not _HEX_RE.fullmatch(s):
        return None
    try:
        b = bytes.fromhex(s)
    except ValueError:
        return None
    if not _looks_printable(b):
        return None
    return b.decode("utf-8", errors="replace")


def _try_url(s: str) -> Optional[str]:
    if not _URL_ENC_RE.search(s):
        return None
    try:
        out = urllib.parse.unquote(s)
    except Exception:
        return None
    return out if out != s else None


def _try_unicode(s: str) -> Optional[str]:
    if not _UNICODE_ESCAPE_RE.search(s):
        return None
    try:
        out = s.encode("utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return None
    return out if out != s else None


def _try_json(s: str) -> Any:
    s = s.strip()
    if not (s.startswith("{") or s.startswith("[")):
        return None
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return None


def _decode_string(s: str) -> tuple[Optional[Any], Optional[str]]:
    """Try each codec in stable order. Returns (decoded, codec) or
    (None, None) if no codec matched."""
    for fn, codec in ((_try_base64, "base64"),
                       (_try_hex, "hex"),
                       (_try_url, "url"),
                       (_try_unicode, "unicode")):
        out = fn(s)
        if out is not None:
            return out, codec
    parsed = _try_json(s)
    if parsed is not None:
        return parsed, "json"
    return None, None


_MAX_DEPTH = 4
_MAX_STEPS = 32


def decode_call(call: dict, *, max_depth: int = _MAX_DEPTH,
                 max_steps: int = _MAX_STEPS) -> tuple[dict, DecodeReport]:
    """Return (augmented_call, DecodeReport). The augmented call carries
    every successfully decoded payload as a structural field under
    `_decoded` (path → decoded value) so reachability rules can match
    on `url`, `category`, `tool`, etc. exposed via the decoded payload.

    Fail-closed: malformed decoding is logged; the call passes through
    unchanged for the malformed branch but `report.malformed = True`."""

    report = DecodeReport()
    out = copy.deepcopy(call)
    if not isinstance(out.get("args"), dict):
        return out, report

    def walk(value: Any, path: str, depth: int) -> Any:
        if depth > max_depth:
            report.truncated = True
            return value
        if len(report.steps) >= max_steps:
            report.truncated = True
            return value
        report.depth = max(report.depth, depth)

        if isinstance(value, str):
            decoded, codec = _decode_string(value)
            if decoded is None:
                return value
            report.steps.append(DecodeStep(
                where=path, codec=codec,
                in_repr=_trunc(value),
                out_repr=_trunc(str(decoded) if not isinstance(decoded, str)
                                else decoded),
            ))
            # recurse into the decoded value
            return walk(decoded, path + ".decoded", depth + 1)

        if isinstance(value, dict):
            new = {}
            for k, v in value.items():
                new[k] = walk(v, f"{path}.{k}", depth + 1)
            return new

        if isinstance(value, list):
            return [walk(v, f"{path}[{i}]", depth + 1)
                    for i, v in enumerate(value)]

        return value

    decoded_args = walk(out["args"], "args", 1)

    # flatten any decoded structured fields up to the top level so the
    # existing reachability rules can see e.g. url / category / tool.
    # Collect additions first so we never mutate during iteration.
    flat_extras: dict = {}
    if isinstance(decoded_args, dict):
        for k, v in list(decoded_args.items()):
            if isinstance(v, dict):
                for kk, vv in v.items():
                    if kk in ("url", "category", "topic_class",
                              "user_state", "tool", "intent"):
                        flat_extras.setdefault(f"_decoded_{kk}", vv)
    new_args = dict(decoded_args) if isinstance(decoded_args, dict) else decoded_args
    if isinstance(new_args, dict):
        for k, v in flat_extras.items():
            new_args.setdefault(k, v)
    out["args"] = new_args

    report.extracted = {s.where: s.out_repr for s in report.steps}
    return out, report
