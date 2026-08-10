"""Feature-space collisions: proof that the current representation cannot separate.

THE ARGUMENT

Every candidate primitive LB-0 can produce is a predicate over the feature set
of a trajectory. So if two trajectories have the SAME feature set and DIFFERENT
outcomes, then no predicate expressible in that grammar assigns them different
answers — not the one we found, not a better one, not one found next year with a
wider beam. The grammar's best achievable accuracy is bounded away from perfect,
and the bound is computable directly from the collisions.

That is a proof, not an inference, and it is what distinguishes this from an
ordinary "the model has residual error" observation. Residual error can always
be blamed on the search. Collisions cannot.

WHAT COLLISIONS DO NOT TELL YOU

Why. A missing observable, a mislabelled record and a genuinely stochastic world
all produce exactly this signature. Separating them requires running a
trajectory again, which is `experiments/replay_probe.py`, and combining the two
is `adequacy.py`. This module deliberately stops at the arithmetic.

Everything here is pure: no oracle, no environment, no RNG, no I/O.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from living_boundary.discovery.features import feature_set


def signature_of(names) -> str:
    """A stable digest of a feature set.

    Sorted before hashing, so it does not depend on set iteration order, and
    hashed rather than stored so a group key stays small when a trajectory
    carries several hundred features.
    """
    joined = "\n".join(sorted(names))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class CollisionGroup:
    """Trajectories the current representation cannot tell apart."""

    signature: str
    size: int
    outcome_counts: dict
    sequence_ids: tuple

    @property
    def minority(self) -> int:
        if len(self.outcome_counts) < 2:
            return 0
        return self.size - max(self.outcome_counts.values())

    @property
    def minority_fraction(self) -> float:
        return self.minority / self.size if self.size else 0.0

    @property
    def is_colliding(self) -> bool:
        return len(self.outcome_counts) > 1

    def as_dict(self) -> dict:
        return {
            "signature": self.signature,
            "size": self.size,
            "outcome_counts": dict(sorted(self.outcome_counts.items())),
            "minority": self.minority,
            "minority_fraction": round(self.minority_fraction, 4),
            "example_sequence_ids": list(self.sequence_ids[:5]),
        }


@dataclass
class CollisionReport:
    """Everything the collision analysis established about a corpus."""

    trajectories: int = 0
    groups: int = 0
    colliding_groups: int = 0
    trajectories_in_colliding_groups: int = 0
    minority_total: int = 0
    top_groups: list = field(default_factory=list)
    colliding_sequence_ids: tuple = ()

    @property
    def collision_rate(self) -> float:
        """Fraction of the corpus sitting inside a group the grammar cannot split."""
        return (self.trajectories_in_colliding_groups / self.trajectories
                if self.trajectories else 0.0)

    @property
    def irreducible_error_rate(self) -> float:
        """Lower bound on the error of ANY predicate over this representation.

        Within a colliding group the best a predicate can do is answer with the
        majority label, so it gets the minority members wrong. Summing minority
        counts over all groups and dividing by the corpus size is therefore a
        floor on achievable error — the price of the representation itself,
        before any question of search quality.
        """
        return self.minority_total / self.trajectories if self.trajectories else 0.0

    @property
    def mean_minority_fraction(self) -> float:
        """How MIXED the colliding groups are, on average.

        A discriminating statistic, though not a sufficient one. Under label
        noise at rate e, a colliding group is mostly one label with a thin
        minority, so this lands near e. Under a missing observable — or a
        stochastic world — the groups are genuinely mixed and this lands near
        the mixing proportion. It separates noise from the other two; it does
        NOT separate a missing observable from stochasticity, which is why the
        probe exists.
        """
        colliding = [g for g in self.top_groups if g.is_colliding]
        if not colliding:
            return 0.0
        return sum(g.minority_fraction for g in colliding) / len(colliding)

    def as_dict(self) -> dict:
        return {
            "trajectories": self.trajectories,
            "distinct_feature_signatures": self.groups,
            "colliding_groups": self.colliding_groups,
            "trajectories_in_colliding_groups": self.trajectories_in_colliding_groups,
            "collision_rate": round(self.collision_rate, 4),
            "minority_total": self.minority_total,
            "irreducible_error_rate": round(self.irreducible_error_rate, 4),
            "mean_minority_fraction": round(self.mean_minority_fraction, 4),
            "largest_colliding_groups": [
                g.as_dict() for g in self.top_groups if g.is_colliding][:8],
        }


def find_collisions(trajectories, feature_fn=None, outcome_fn=None) -> CollisionReport:
    """Group trajectories by feature set and report the ones that disagree.

    `feature_fn` defaults to the LB-0 grammar, which is the representation under
    examination. Passing an extended function is how `extensions.py` asks "would
    this additional observable resolve the collisions?".
    """
    feature_fn = feature_fn or feature_set
    outcome_fn = outcome_fn or (lambda t: t.outcome)

    buckets: dict = {}
    for trajectory in trajectories:
        signature = signature_of(feature_fn(trajectory))
        entry = buckets.setdefault(signature, {"outcomes": {}, "ids": []})
        outcome = outcome_fn(trajectory)
        entry["outcomes"][outcome] = entry["outcomes"].get(outcome, 0) + 1
        entry["ids"].append(trajectory.sequence_id)

    groups = []
    for signature in sorted(buckets):
        entry = buckets[signature]
        groups.append(CollisionGroup(
            signature=signature,
            size=len(entry["ids"]),
            outcome_counts=dict(entry["outcomes"]),
            sequence_ids=tuple(entry["ids"])))

    colliding = [g for g in groups if g.is_colliding]
    # Deterministic ordering: biggest disagreement first, then size, then
    # signature — so the report is stable across runs and machines.
    colliding.sort(key=lambda g: (-g.minority, -g.size, g.signature))

    report = CollisionReport(
        trajectories=len(trajectories),
        groups=len(groups),
        colliding_groups=len(colliding),
        trajectories_in_colliding_groups=sum(g.size for g in colliding),
        minority_total=sum(g.minority for g in colliding),
        top_groups=colliding,
        colliding_sequence_ids=tuple(
            sid for g in colliding for sid in g.sequence_ids))
    return report
