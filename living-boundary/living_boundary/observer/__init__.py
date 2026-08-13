"""Trace observation: read, validate, normalise and group governance traces.

The observer is deliberately the ONLY component that touches raw trace input.
Everything downstream sees `NormalisedTrajectory` objects, so a malformed or
adversarially-shaped event cannot reach the discovery layer with its extra
fields intact — the normaliser accepts a closed key set and rejects the rest.
"""

from __future__ import annotations

from living_boundary.observer.normalizer import (
    ALLOWED_EVENT_KEYS, REQUIRED_EVENT_KEYS, NormalisedEvent,
    MalformedTraceError, normalise_event,
)
from living_boundary.observer.trace_reader import read_events, read_jsonl
from living_boundary.observer.trajectory_builder import (
    NormalisedTrajectory, build_trajectories,
)

__all__ = [
    "ALLOWED_EVENT_KEYS", "REQUIRED_EVENT_KEYS", "NormalisedEvent",
    "MalformedTraceError", "normalise_event", "read_events", "read_jsonl",
    "NormalisedTrajectory", "build_trajectories",
]
