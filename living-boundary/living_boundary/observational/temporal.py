"""Temporal consistency, and the drift it is there to catch.

An association measured once over a whole archive cannot tell a stable
governing structure from a relationship that held in March and reversed in June.
Both produce collisions; both produce a pooled risk difference; only one is
worth proposing as a missing observable.

So every candidate exposure is re-measured within each collection period, and a
candidate whose association changes SIGN across periods is not offered as a
localisation. The verdict downgrades to INCONCLUSIVE rather than to
"inadequate", because a reversing relationship is evidence that the world moved,
not that the representation is short a field.

This is also the closest LB-2 gets to a distribution-shift check. It is a weak
one — it detects shift only where shift changes the association — and that
limitation is reported rather than papered over.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.observational.archive import (
    OBSERVABLE_FIELDS, period_of, record_signature,
)
from living_boundary.observational.cohorts import _build_strata
from living_boundary.observational.uncertainty import mantel_haenszel

# Below this many trajectories a period cannot support its own estimate, and
# absence of evidence there must not be read as evidence of instability.
MIN_PERIOD_TRAJECTORIES = 60


@dataclass
class TemporalConsistency:
    """Per-period associations for one exposure, and whether they agree."""

    exposure: str
    periods: dict = field(default_factory=dict)
    testable: bool = False
    consistent: bool = True
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "exposure": self.exposure, "testable": self.testable,
            "consistent": self.consistent, "reason": self.reason,
            "periods": dict(sorted(self.periods.items())),
        }


def check_consistency(trajectories, name: str, family) -> TemporalConsistency:
    """Re-measure an exposure inside each collection period."""
    result = TemporalConsistency(exposure=name)

    by_period: dict = {}
    for trajectory in trajectories:
        by_period.setdefault(period_of(trajectory), []).append(trajectory)
    usable = {period: rows for period, rows in by_period.items()
              if period and len(rows) >= MIN_PERIOD_TRAJECTORIES}

    if len(usable) < 2:
        result.reason = (
            f"only {len(usable)} collection period(s) carry at least "
            f"{MIN_PERIOD_TRAJECTORIES} trajectories; temporal stability is "
            f"untestable here and is not counted either way")
        return result

    result.testable = True
    mask = (family.observable,) if family.observable in OBSERVABLE_FIELDS else ()

    def exposure_fn(trajectory):
        return name in family.features(trajectory)

    estimates = {}
    for period, rows in sorted(usable.items()):
        strata = _build_strata(rows, exposure_fn,
                               lambda t: record_signature(t, mask=mask))
        association = mantel_haenszel(strata, exposure=name,
                                      observable=family.observable)
        estimates[period] = association.pooled_risk_difference
        result.periods[period] = association.as_dict()

    values = list(estimates.values())
    positive = [v for v in values if v > 0.05]
    negative = [v for v in values if v < -0.05]
    if positive and negative:
        result.consistent = False
        result.reason = (
            f"the association reverses sign across collection periods "
            f"({', '.join(f'{p}={v:+.3f}' for p, v in sorted(estimates.items()))}); "
            f"a relationship that flips is evidence the world moved, not that "
            f"the representation is missing a field")
    else:
        result.reason = (
            f"the association keeps its sign across periods "
            f"({', '.join(f'{p}={v:+.3f}' for p, v in sorted(estimates.items()))})")
    return result


@dataclass
class DistributionShift:
    """Coarse covariate drift between two corpora, reported not gated.

    Included because a held-out improvement measured across a shifted
    distribution means less than one measured across a stable one, and a
    reviewer should be able to see which they are looking at. It is NOT part of
    the verdict ladder: this statistic is too blunt to carry that weight, and
    saying so is better than pretending otherwise.
    """

    l1_distance: float = 0.0
    compared_signatures: int = 0

    def as_dict(self) -> dict:
        return {"l1_distance": round(self.l1_distance, 4),
                "compared_signatures": self.compared_signatures,
                "note": "reported for context; not an input to the verdict"}


def distribution_shift(left, right) -> DistributionShift:
    """L1 distance between the record-signature distributions of two corpora."""
    def _histogram(rows):
        counts: dict = {}
        for trajectory in rows:
            key = record_signature(trajectory)
            counts[key] = counts.get(key, 0) + 1
        total = sum(counts.values()) or 1
        return {key: value / total for key, value in counts.items()}

    first, second = _histogram(left), _histogram(right)
    keys = set(first) | set(second)
    distance = sum(abs(first.get(key, 0.0) - second.get(key, 0.0)) for key in keys)
    return DistributionShift(l1_distance=distance, compared_signatures=len(keys))
