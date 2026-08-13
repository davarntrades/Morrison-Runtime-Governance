"""Sealed, irreversible evidence — and the record identity that replaces replay.

LB-1 could ask the world the same question twice. LB-2 may not, because the
trajectories a governance system most needs to learn from are the ones that must
never be repeated: an email already sent, a payment already initiated, a
healthcare record already read.

THE ENFORCEMENT IS STRUCTURAL, NOT POLICY

`SealedArchive` has no `observe()`, no environment reference, and no callable of
any kind that could execute anything. The environment that produced these
outcomes exists only inside the harness at generation time and is discarded
before the archive is handed over. LB-2 cannot replay because there is nothing
to call — `tests/test_lb2_isolation.py` asserts both halves of that.

WHAT REPLACES THE PROBE

Replay let LB-1 ask "if I run this again, do I get the same answer?". The
observational substitute is to find, in the archive, another trajectory that is
the SAME EVENT as far as the telemetry is concerned, and see what happened to
it. That requires a notion of record identity, which is what this module
provides.

    feature signature   what the LB-0 grammar can see
    record signature    everything the telemetry recorded

They nest: the record determines the features, so two trajectories with the same
record always have the same features. The gap between the two levels is exactly
the information the telemetry captured and the representation ignored — and
measuring it is how LB-2 separates "the grammar is missing something" from
"nothing recorded distinguishes these at all".

CANONICALISATION, AND WHAT IT DELIBERATELY DISCARDS

Identifiers are alpha-renamed by order of first appearance: two sessions with
the same shape on different customers are the same event for this purpose, and
treating them as distinct would make every record unique and the whole method
vacuous. Timestamps are kept as offsets from the first step, not as absolute
clock values, for the same reason — with a coarse `period` tag retained so
temporal analysis still has something to work with.

Those choices are modelling assumptions, not facts, and they are the first thing
a reviewer should challenge: a corpus where customer identity genuinely matters
would be mis-matched by this canonicalisation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from living_boundary.discovery.features import feature_set
from living_boundary.observer.trajectory_builder import NormalisedTrajectory

# Record fields grouped by the observable they come from. Masking a group is how
# a matched cohort holds "everything except this observable" fixed.
OBSERVABLE_FIELDS = {
    "timestamp": ("offset",),
    "actor_id": ("actor",),
    "identity_id": ("identity",),
    "resource": ("resource_type", "subject"),
    "capability": ("capability", "action", "domain"),
}


def _digest(payload) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False,
                   default=str).encode("utf-8")).hexdigest()


def _alpha_rename(values):
    """Map identifiers to positional indices in order of first appearance."""
    mapping = {}
    for value in values:
        if value not in mapping:
            mapping[value] = len(mapping)
    return mapping


def canonical_record(trajectory, mask=()) -> list:
    """The full observable record, canonicalised, optionally with fields masked.

    `mask` names field groups to blank out (keys of `OBSERVABLE_FIELDS`). That
    is how a matched cohort is formed: stratify on the canonical record with the
    candidate observable removed, so every other recorded thing is held equal.
    """
    events = trajectory.events
    masked_fields = {name for group in mask
                     for name in OBSERVABLE_FIELDS.get(group, ())}

    identities = _alpha_rename(e.identity_id for e in events)
    actors = _alpha_rename(e.actor_id for e in events)
    subjects = _alpha_rename(e.subject for e in events)
    base = _epoch_of(events[0]) if events else 0

    rows = []
    for event in events:
        row = {
            "capability": event.capability,
            "action": event.action,
            "domain": event.domain,
            "boundary": event.trust_boundary,
            "scope": list(event.permission_scope),
            "decision": event.policy_decision,
            "outcome": event.execution_outcome,
            "identity": identities[event.identity_id],
            "actor": actors[event.actor_id],
            "resource_type": event.resource_type,
            "subject": subjects[event.subject],
            "offset": _epoch_of(event) - base,
        }
        for name in masked_fields:
            row[name] = None
        rows.append(row)
    return rows


def record_signature(trajectory, mask=()) -> str:
    """Stable digest of the canonicalised record.

    The session-level fields ride along because they are part of what was
    observed; `period` is retained so temporal analysis has a handle, while
    absolute clock time is not, for the reason in the module docstring.
    """
    payload = {
        "steps": canonical_record(trajectory, mask=mask),
        "provider": trajectory.provider,
        "region": trajectory.region,
        "session_tag": trajectory.session_tag,
        "period": period_of(trajectory),
    }
    return _digest(payload)[:24]


def feature_signature(trajectory) -> str:
    return _digest(sorted(feature_set(trajectory)))[:24]


# ── timestamps ──────────────────────────────────────────────────────────
# A third copy of this parser (the harness and the LB-1 extension pool have the
# others). They sit on different sides of isolation boundaries; sharing it would
# create the import edge those boundaries exist to forbid.

_MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _day_of_year(year: int, month: int, day: int) -> int:
    total = sum(_MONTH_DAYS[:month - 1]) + day - 1
    if month > 2 and year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        total += 1
    return total


def _epoch_of(event) -> int:
    text = event.timestamp
    if not text or len(text) < 20:
        return 0
    year, month, day = int(text[0:4]), int(text[5:7]), int(text[8:10])
    hour, minute, second = int(text[11:13]), int(text[14:16]), int(text[17:19])
    days = (year - 1970) * 365 + (year - 1969) // 4 + _day_of_year(year, month, day)
    return ((days * 24 + hour) * 60 + minute) * 60 + second


def period_of(trajectory) -> str:
    """Coarse era tag, read from the archive's own provenance.

    Not derived from the clock: the archive records which collection period a
    trajectory came from, and that is what temporal analysis should use. A
    derived bucket would silently change meaning if the generator's epoch moved.
    """
    if not trajectory.events:
        return ""
    return str(trajectory.events[0].provenance.get("period", ""))


# ── the archive ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SealedTrajectory:
    """One irreversible, already-executed trajectory and its seal."""

    trajectory: NormalisedTrajectory
    seal: str
    sealed_record: str

    @property
    def sequence_id(self) -> str:
        return self.trajectory.sequence_id

    @property
    def outcome(self) -> str:
        return self.trajectory.outcome

    def verify(self) -> bool:
        """Recompute the seal. A mismatch means the record was altered after
        the fact, which is a telemetry-integrity failure rather than evidence
        about the world."""
        return _digest(canonical_record(self.trajectory)) == self.sealed_record


@dataclass(frozen=True)
class SealedArchive:
    """Read-only evidence. NO execution surface of any kind.

    Deliberately not a wrapper around an environment with the dangerous method
    hidden: there is no environment here to hide. Anything LB-2 concludes, it
    concludes from these records.
    """

    archive_id: str
    entries: tuple = ()
    chain_head: str = ""
    provenance: dict = field(default_factory=dict)

    @property
    def trajectories(self) -> tuple:
        return tuple(entry.trajectory for entry in self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def integrity(self) -> dict:
        """Seal verification plus field-completeness, reported separately.

        Two different failures, and conflating them would hide one: a broken
        seal means the record was TAMPERED WITH, while an empty field means the
        record was never complete. Both make inference unsafe, for different
        reasons.
        """
        broken = [entry.sequence_id for entry in self.entries if not entry.verify()]
        total_events = 0
        missing_fields = 0
        gaps = 0
        for entry in self.entries:
            events = entry.trajectory.events
            total_events += len(events)
            for event in events:
                if not event.actor_id or not event.timestamp or not event.identity_id:
                    missing_fields += 1
            if [e.step_index for e in events] != list(range(len(events))):
                gaps += 1
        return {
            "entries": len(self.entries),
            "seals_broken": len(broken),
            "seal_failure_rate": round(len(broken) / max(1, len(self.entries)), 4),
            "events": total_events,
            "events_missing_fields": missing_fields,
            "field_incompleteness_rate": round(
                missing_fields / max(1, total_events), 4),
            "sequences_with_step_gaps": gaps,
            "example_broken_seals": broken[:5],
        }

    def manifest(self) -> dict:
        return {
            "archive_id": self.archive_id,
            "sealed_trajectories": len(self.entries),
            "chain_head": self.chain_head,
            "integrity": self.integrity(),
            "provenance": dict(self.provenance),
            "replayable": False,
            "note": ("this archive exposes no execution surface; the "
                     "environment that produced these outcomes was discarded "
                     "before the archive was created"),
        }
