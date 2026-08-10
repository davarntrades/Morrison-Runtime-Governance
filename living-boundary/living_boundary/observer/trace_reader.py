"""Trace ingestion. Read-only, order-preserving, provenance-preserving.

The reader is the boundary between "whatever produced these traces" and the
Living Boundary. It has no write path of any kind — no file is opened for
writing, no Morrison state is touched — which is one half of why a Living
Boundary failure cannot change runtime governance behaviour. (The other half
is that nothing in the production path calls into this package at all.)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from living_boundary.observer.normalizer import (
    MalformedTraceError, normalise_events,
)


def read_events(rows: Any, source: str | None = None) -> list:
    """Normalise in-memory raw events into `NormalisedEvent`s."""
    return normalise_events(rows, source=source)


def read_jsonl(path: Any) -> list:
    """Read a JSONL trace file into `NormalisedEvent`s.

    One JSON object per line. A blank line is skipped; a line that is not a
    JSON object is a malformed trace and aborts the read, because a partially
    read trace file yields trajectories that are missing steps — and a missing
    step is exactly the kind of error that would fabricate a "safe" label for
    an unsafe trajectory.
    """
    p = Path(path)
    rows = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise MalformedTraceError(
                f"{p}:{lineno}: not valid JSON: {exc}") from exc
        rows.append(obj)
    return normalise_events(rows, source=str(p))
