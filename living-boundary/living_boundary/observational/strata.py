"""The nested decomposition that replaces the replay probe.

LB-1 asked the world twice. LB-2 asks the archive whether it already contains
the answer, by stratifying disagreement at two levels:

    FEATURE-LEVEL COLLISION   same features, different outcome
                              -> no predicate over the grammar separates these

    RECORD-LEVEL COLLISION    same complete record, different outcome
                              -> NOTHING the telemetry captured separates these

Records determine features, so record collisions are a strict subset of feature
collisions, and the difference between the two is the quantity LB-2 is really
after:

    resolvable = feature-level minority  −  record-level minority

That is disagreement the telemetry DID capture and the representation ignored.
It is the observational stand-in for LB-1's "the world is reproducible and the
record is faithful, yet the grammar cannot separate these".

WHAT THE TWO EXTREMES MEAN

  resolvable ≈ all of it   the grammar is missing something that was recorded
                           -> a representation problem, and a localisable one

  resolvable ≈ none of it  trajectories identical in every recorded field ended
                           differently -> BEYOND TELEMETRY

And here is the honest part, stated up front because it is the price of losing
replay: *beyond telemetry* does not mean *random*. A genuinely stochastic world
and a real cause that was never recorded produce identical archives. LB-1 could
separate them by re-running; LB-2 cannot, and must not pretend otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.observational.archive import (
    feature_signature, record_signature,
)
from living_boundary.observational.uncertainty import Interval, wilson


@dataclass(frozen=True)
class Group:
    signature: str
    size: int
    unsafe: int

    @property
    def minority(self) -> int:
        return min(self.unsafe, self.size - self.unsafe)

    @property
    def colliding(self) -> bool:
        return 0 < self.unsafe < self.size


def _group(trajectories, key_fn):
    counts: dict = {}
    for trajectory in trajectories:
        key = key_fn(trajectory)
        entry = counts.setdefault(key, [0, 0])
        entry[0] += 1
        entry[1] += 1 if trajectory.is_unsafe_observed else 0
    return [Group(signature=key, size=size, unsafe=unsafe)
            for key, (size, unsafe) in sorted(counts.items())]


@dataclass
class StratifiedCollisions:
    """Disagreement, decomposed by how much of it the telemetry could explain."""

    trajectories: int = 0
    feature_groups: int = 0
    feature_colliding: int = 0
    feature_in_collisions: int = 0
    feature_minority: int = 0
    record_groups: int = 0
    record_colliding: int = 0
    record_minority: int = 0
    colliding_sequence_ids: tuple = ()
    beyond_telemetry_sequence_ids: tuple = ()
    _rate: Interval = field(default_factory=lambda: wilson(0, 0))
    _resolvable: Interval = field(default_factory=lambda: wilson(0, 0))

    @property
    def resolvable_minority(self) -> int:
        return max(0, self.feature_minority - self.record_minority)

    @property
    def collision_rate(self) -> Interval:
        return self._rate

    @property
    def resolvable_fraction(self) -> Interval:
        """Of the disagreement the grammar cannot handle, how much did the
        telemetry nonetheless record? Interval, not point — this number decides
        a verdict and is estimated from finite strata."""
        return self._resolvable

    @property
    def irreducible_error_rate(self) -> float:
        """Lower bound on the error of any predicate over the CURRENT grammar."""
        return (self.feature_minority / self.trajectories
                if self.trajectories else 0.0)

    @property
    def telemetry_floor(self) -> float:
        """Lower bound on the error of any predicate over ANY representation
        built from this telemetry. Nothing recorded can go below it."""
        return (self.record_minority / self.trajectories
                if self.trajectories else 0.0)

    def as_dict(self) -> dict:
        return {
            "trajectories": self.trajectories,
            "feature_groups": self.feature_groups,
            "feature_colliding_groups": self.feature_colliding,
            "trajectories_in_feature_collisions": self.feature_in_collisions,
            "feature_minority": self.feature_minority,
            "record_groups": self.record_groups,
            "record_colliding_groups": self.record_colliding,
            "record_minority": self.record_minority,
            "resolvable_minority": self.resolvable_minority,
            "collision_rate": self._rate.as_dict(),
            "resolvable_fraction": self._resolvable.as_dict(),
            "irreducible_error_rate_current_grammar": round(
                self.irreducible_error_rate, 4),
            "telemetry_floor": round(self.telemetry_floor, 4),
            "example_colliding": list(self.colliding_sequence_ids[:5]),
            "example_beyond_telemetry": list(
                self.beyond_telemetry_sequence_ids[:5]),
        }


def stratify(trajectories) -> StratifiedCollisions:
    """Decompose disagreement into feature-level and record-level strata."""
    total = len(trajectories)
    feature_groups = _group(trajectories, feature_signature)
    record_groups = _group(trajectories, record_signature)

    feature_colliding = [g for g in feature_groups if g.colliding]
    record_colliding = [g for g in record_groups if g.colliding]

    feature_minority = sum(g.minority for g in feature_colliding)
    record_minority = sum(g.minority for g in record_colliding)
    in_collisions = sum(g.size for g in feature_colliding)

    colliding_keys = {g.signature for g in feature_colliding}
    beyond_keys = {g.signature for g in record_colliding}

    resolvable = max(0, feature_minority - record_minority)

    return StratifiedCollisions(
        trajectories=total,
        feature_groups=len(feature_groups),
        feature_colliding=len(feature_colliding),
        feature_in_collisions=in_collisions,
        feature_minority=feature_minority,
        record_groups=len(record_groups),
        record_colliding=len(record_colliding),
        record_minority=record_minority,
        colliding_sequence_ids=tuple(
            t.sequence_id for t in trajectories
            if feature_signature(t) in colliding_keys)[:200],
        beyond_telemetry_sequence_ids=tuple(
            t.sequence_id for t in trajectories
            if record_signature(t) in beyond_keys)[:200],
        _rate=wilson(in_collisions, total),
        _resolvable=wilson(resolvable, feature_minority))


def colliding_trajectories(trajectories):
    """The subset sitting in a feature-level group the grammar cannot split."""
    groups = {g.signature for g in _group(trajectories, feature_signature)
              if g.colliding}
    return [t for t in trajectories if feature_signature(t) in groups]


def resolution_for(trajectories, extra_fn, base_minority: int,
                   feature_keys=None) -> float:
    """How much feature-level disagreement one extra observable would remove.

    Deliberately SIGN-BLIND. An exposure that separates the colliding groups
    resolves them whether its association is positive, negative, or reverses
    halfway through the archive — which is exactly why this, and not the pooled
    effect size, is the right way to pick which candidates deserve a temporal
    consistency check. Ranking by effect size would rank a drifting exposure
    near zero and never look at it again.
    """
    if base_minority <= 0:
        return 0.0

    keys = feature_keys or [feature_signature(t) for t in trajectories]
    counter = {"i": -1}

    def _key(trajectory):
        counter["i"] += 1
        return keys[counter["i"]] + "|" + "\x1f".join(sorted(extra_fn(trajectory)))

    minority = sum(g.minority for g in _group(trajectories, _key) if g.colliding)
    return max(0.0, (base_minority - minority) / base_minority)
