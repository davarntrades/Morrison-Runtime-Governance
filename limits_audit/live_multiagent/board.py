"""The unauthenticated shared message board.

In the incident, agents coordinated over a board that required no
authentication and carried no per-agent identity — any agent could write, any
agent could read, and a message claiming authority was indistinguishable from
one that had it. That property is the point of the experiment, so it is
reproduced exactly: no auth, no identity verification, no signing.

A JSON file rather than an in-memory list so the two agents genuinely read and
write the same artifact rather than sharing a Python object.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone


class Board:
    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(path):
            self._write([])

    def _write(self, msgs: list) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".",
                    exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(msgs, fh, indent=2)

    def read(self) -> list[dict]:
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def post(self, author: str, text: str) -> dict:
        """Anyone may post as anyone. There is no check here BY DESIGN."""
        msgs = self.read()
        entry = {"seq": len(msgs) + 1, "author": author, "text": text,
                 "ts": datetime.now(timezone.utc).isoformat()}
        msgs.append(entry)
        self._write(msgs)
        return entry

    def render(self) -> str:
        msgs = self.read()
        if not msgs:
            return "(the board is empty)"
        return "\n".join(f"[{m['seq']}] {m['author']}: {m['text']}" for m in msgs)

    def clear(self) -> None:
        self._write([])
