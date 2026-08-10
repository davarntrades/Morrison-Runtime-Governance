"""A generic pool of candidate observables, and the localisation step.

ONCE an inadequacy has been ESTABLISHED, the useful next question is *what* the
representation is failing to read. This module answers it the only way that is
checkable: by trying each candidate observable and measuring how much of the
proven-unsplittable disagreement it resolves.

THE ORDER MATTERS AND IS ENFORCED BY THE PIPELINE

Detection never touches this pool. `adequacy.assess_representation` sees only
collisions and probe rates, and reaches its verdict before any extension is
tried. If detection consulted the pool, "the representation is inadequate" would
degenerate into "one of my spare features helps", which is a much weaker claim
and would fail on exactly the case that matters — an inadequacy nothing in the
pool can fix. That case is not hypothetical, and the pipeline reports it as
UNLOCALISED rather than pretending the pool is exhaustive.

THE POOL IS GENERIC

Nine families over observables the normalised trace already carries: elapsed
time, inter-step gaps, actor/identity divergence, actor and identity counts,
data-subject counts, resource repetition, time of day, capability multiplicity.
None is written for a particular failure. The same pool would be offered for a
corpus about credential handling or supply-chain approvals.

WHY THE TIMESTAMP PARSER IS DUPLICATED HERE

`experiments/lb1_environment.py` has one too. They sit on opposite sides of the
ground-truth boundary: the analysis layer must not import the harness, and the
harness must not import the analysis layer. Sharing this helper would create
exactly the import edge the isolation test exists to forbid, so the duplication
is the correct outcome rather than an oversight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from living_boundary.discovery.features import feature_set
from living_boundary.representation.collisions import find_collisions

SEP = "::"

# A generic ladder, not a tuned threshold. Log-spaced across the range a
# governed session plausibly spans, from "same breath" to "an hour".
_ELAPSED_LADDER = (30, 60, 120, 300, 900, 3600)
_GAP_LADDER = (10, 30, 60, 300, 900)
_COUNT_LADDER = (2, 3, 4)

_MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _day_of_year(year: int, month: int, day: int) -> int:
    total = sum(_MONTH_DAYS[:month - 1]) + day - 1
    if month > 2 and year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        total += 1
    return total


def _epoch(event) -> int:
    text = event.timestamp
    if not text or len(text) < 20:
        return 0
    year, month, day = int(text[0:4]), int(text[5:7]), int(text[8:10])
    hour, minute, second = int(text[11:13]), int(text[14:16]), int(text[17:19])
    days = (year - 1970) * 365 + (year - 1969) // 4 + _day_of_year(year, month, day)
    return ((days * 24 + hour) * 60 + minute) * 60 + second


def _stamps(trajectory):
    return [_epoch(event) for event in trajectory.events]


# ── candidate observables ───────────────────────────────────────────────

def _f_elapsed(trajectory) -> set:
    stamps = _stamps(trajectory)
    if len(stamps) < 2:
        return set()
    span = max(stamps) - min(stamps)
    return {f"elapsed_le{SEP}{limit}" for limit in _ELAPSED_LADDER if span <= limit}


def _f_max_gap(trajectory) -> set:
    stamps = _stamps(trajectory)
    if len(stamps) < 2:
        return set()
    gap = max(b - a for a, b in zip(stamps, stamps[1:]))
    return {f"max_gap_le{SEP}{limit}" for limit in _GAP_LADDER if gap <= limit}


def _f_actor_divergence(trajectory) -> set:
    names = set()
    for event in trajectory.events:
        if not event.actor_id:
            continue
        if event.actor_id != f"agent_{event.identity_id}":
            names.add(f"actor_diverges_from_identity{SEP}")
            names.add(f"actor_diverges_at{SEP}{event.token}")
    return names


def _f_actor_count(trajectory) -> set:
    count = len({event.actor_id for event in trajectory.events if event.actor_id})
    return {f"actors_ge{SEP}{k}" for k in _COUNT_LADDER if count >= k}


def _f_identity_count(trajectory) -> set:
    count = len(trajectory.identities)
    return {f"identities_ge{SEP}{k}" for k in _COUNT_LADDER if count >= k}


def _f_subject_count(trajectory) -> set:
    count = len(trajectory.subjects)
    return {f"subjects_ge{SEP}{k}" for k in _COUNT_LADDER if count >= k}


def _f_resource_repeat(trajectory) -> set:
    seen: dict = {}
    for event in trajectory.events:
        seen[event.resource] = seen.get(event.resource, 0) + 1
    names = set()
    if any(count >= 2 for count in seen.values()):
        names.add(f"resource_repeated{SEP}")
    if any(count >= 3 for count in seen.values()):
        names.add(f"resource_repeated_thrice{SEP}")
    return names


def _f_hour_of_day(trajectory) -> set:
    stamps = _stamps(trajectory)
    if not stamps:
        return set()
    hour = (min(stamps) // 3600) % 24
    return {f"hour_bucket{SEP}{hour // 6}"}


def _f_capability_multiplicity(trajectory) -> set:
    counts: dict = {}
    for capability in trajectory.capabilities:
        counts[capability] = counts.get(capability, 0) + 1
    return {f"cap_count_ge{SEP}{capability}{SEP}{k}"
            for capability, count in counts.items()
            for k in (2, 3) if count >= k}


@dataclass(frozen=True)
class ExtensionFamily:
    """One candidate observable the current representation does not read."""

    name: str
    observable: str
    description: str
    features: Callable

    def extend(self, base_fn=None):
        """A feature function that is the base grammar plus this family."""
        base = base_fn or feature_set

        def _combined(trajectory):
            return set(base(trajectory)) | self.features(trajectory)
        return _combined

    def as_dict(self) -> dict:
        return {"name": self.name, "observable": self.observable,
                "description": self.description}


EXTENSION_POOL = (
    ExtensionFamily(
        "elapsed", "timestamp",
        "Total elapsed time from the first step to the last, against a "
        "log-spaced ladder of thresholds.", _f_elapsed),
    ExtensionFamily(
        "max_gap", "timestamp",
        "The largest interval between consecutive steps.", _f_max_gap),
    ExtensionFamily(
        "actor_divergence", "actor_id",
        "Whether the acting agent differs from the authorising identity, "
        "overall and at each kind of step.", _f_actor_divergence),
    ExtensionFamily(
        "actor_count", "actor_id",
        "How many distinct actors participated.", _f_actor_count),
    ExtensionFamily(
        "identity_count", "identity_id",
        "How many distinct identities participated.", _f_identity_count),
    ExtensionFamily(
        "subject_count", "resource",
        "How many distinct data subjects were touched.", _f_subject_count),
    ExtensionFamily(
        "resource_repeat", "resource",
        "Whether any single resource was touched more than once.",
        _f_resource_repeat),
    ExtensionFamily(
        "hour_of_day", "timestamp",
        "Which six-hour bucket of the day the trajectory started in.",
        _f_hour_of_day),
    ExtensionFamily(
        "capability_multiplicity", "capability",
        "Whether a capability was exercised more than once.",
        _f_capability_multiplicity),
)


@dataclass
class LocalisationResult:
    """How much of the proven-unsplittable disagreement one family resolves."""

    family: str
    observable: str
    description: str
    minority_before: int
    minority_after: int
    collision_rate_after: float
    fully_resolves: bool = False

    @property
    def resolved(self) -> int:
        return self.minority_before - self.minority_after

    @property
    def resolution(self) -> float:
        return (self.resolved / self.minority_before
                if self.minority_before else 0.0)

    def as_dict(self) -> dict:
        return {
            "family": self.family, "observable": self.observable,
            "description": self.description,
            "minority_before": self.minority_before,
            "minority_after": self.minority_after,
            "resolved": self.resolved,
            "resolution": round(self.resolution, 4),
            "collision_rate_after": round(self.collision_rate_after, 4),
            "fully_resolves": self.fully_resolves,
        }


@dataclass
class Localisation:
    """The ranked pool, and whether anything in it accounts for the gap."""

    results: list = field(default_factory=list)
    localised: bool = False
    best: Optional[LocalisationResult] = None
    minimum_resolution: float = 0.0

    def as_dict(self) -> dict:
        return {
            "localised": self.localised,
            "minimum_resolution_required": self.minimum_resolution,
            "best": self.best.as_dict() if self.best else None,
            "ranked": [r.as_dict() for r in self.results],
        }


# A family has to account for most of the disagreement before it is offered as
# an explanation. A feature that resolves a fifth of the collisions is a partial
# correlate, and reporting it as "the missing observable" would be the same
# mistake LB-0's falsification runner exists to catch.
MIN_RESOLUTION = 0.80


def localise_inadequacy(trajectories, base_report, pool=EXTENSION_POOL,
                        base_fn=None, minimum_resolution: float = MIN_RESOLUTION
                        ) -> Localisation:
    """Rank candidate observables by how much of the gap each one closes.

    Returns `localised=False` when nothing in the pool clears the bar — which
    is a real and reportable outcome, not a failure of the run. An inadequacy
    the pool cannot explain is still an inadequacy; it just means the missing
    observable is not among the ones we thought to offer.
    """
    localisation = Localisation(minimum_resolution=minimum_resolution)
    if base_report.minority_total == 0:
        return localisation

    for family in pool:
        extended = find_collisions(trajectories, feature_fn=family.extend(base_fn))
        localisation.results.append(LocalisationResult(
            family=family.name,
            observable=family.observable,
            description=family.description,
            minority_before=base_report.minority_total,
            minority_after=extended.minority_total,
            collision_rate_after=extended.collision_rate,
            fully_resolves=extended.minority_total == 0))

    localisation.results.sort(
        key=lambda r: (-r.resolution, r.minority_after, r.family))
    best = localisation.results[0] if localisation.results else None
    if best and best.resolution >= minimum_resolution:
        localisation.localised = True
        localisation.best = best
    elif best:
        localisation.best = best
    return localisation
