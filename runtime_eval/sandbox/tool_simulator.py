"""Deterministic safe tool simulator. No shell, no network, no fs writes
outside the sandbox dir. Every effect is a pure function of the tool
name + args; replays byte-identically.

The simulator's purpose is to give the planner a believable observation
stream so the harness exercises multi-turn dynamics, while keeping all
"effects" inert. The capability geometry presented here (read returns
data, http_request returns a stub response, etc.) is the spec real
deployments must implement."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable, Optional


_HandlerFn = Callable[[dict], dict]


def _hash(o: dict) -> str:
    return hashlib.sha256(
        json.dumps(o, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()[:16]


# Default handler table — purely simulated effects.
def _h_read_file(args):
    return {"tool": "read_file", "path": args.get("path", ""),
            "bytes": 0, "preview": "<simulated content>"}


def _h_query_db(args):
    return {"tool": "query_db", "sql": args.get("sql", ""),
            "rows": 0, "preview": []}


def _h_analyze(args):
    return {"tool": "analyze", "summary": "<simulated analysis>"}


def _h_summarize(args):
    return {"tool": "summarize", "text": "<simulated summary>"}


def _h_send_supportive(args):
    return {"tool": "send_supportive_message",
            "delivered": True,
            "route_to_support": bool(args.get("route_to_support"))}


def _h_route_crisis(args):
    return {"tool": "route_to_crisis_line",
            "delivered": True,
            "line": args.get("line", "")}


def _h_route_emergency(args):
    return {"tool": "route_to_emergency_services", "delivered": True}


def _h_ground(args):
    return {"tool": "ground_user",
            "technique": args.get("technique", "breathing"),
            "delivered": True}


def _h_respond(args):
    return {"tool": "respond", "delivered": True}


def _h_default(args):
    return {"simulated": True, "args_hash": _hash(args)}


_DEFAULT_HANDLERS: dict[str, _HandlerFn] = {
    "read_file": _h_read_file,
    "query_db": _h_query_db,
    "analyze": _h_analyze,
    "summarize": _h_summarize,
    "send_supportive_message": _h_send_supportive,
    "route_to_crisis_line": _h_route_crisis,
    "route_to_emergency_services": _h_route_emergency,
    "ground_user": _h_ground,
    "respond": _h_respond,
    "chat_reply": _h_respond,
    "reply": _h_respond,
    "narrate": _h_respond,
    "journal_entry": _h_respond,
}


@dataclass
class ToolSimulator:
    """Deterministic handler table. Override or extend per domain."""

    handlers: dict = field(default_factory=lambda: dict(_DEFAULT_HANDLERS))

    def register(self, tool: str, handler: _HandlerFn) -> None:
        self.handlers[tool] = handler

    def simulate(self, call: dict) -> dict:
        tool = str(call.get("tool", ""))
        args = call.get("args", {}) if isinstance(call.get("args"), dict) else {}
        handler = self.handlers.get(tool, _h_default)
        out = handler(args)
        out.setdefault("ok", True)
        out["call_hash"] = _hash({"tool": tool, "args": args})
        return out
