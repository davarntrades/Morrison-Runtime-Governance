"""Confidence-bounded inference. Nothing here claims more than it can support.

LB-1 could afford point estimates: it ran an experiment, and a probe that
disagrees with itself 17% of the time is not a borderline call. LB-2 estimates
everything from a finite observational sample, so every rate it reports carries
an interval, and every claim it makes is gated on that interval rather than on
the point estimate.

WILSON, NOT NORMAL

The proportions here are frequently near 0 or 1 on small strata — "how many of
these eleven matched trajectories went wrong?" — where the normal approximation
produces intervals that extend below zero and badly understate coverage. The
Wilson score interval is well behaved in exactly that regime, which is the
regime observational stratification lives in.

MANTEL–HAENSZEL, NOT A POOLED RATE

Comparing exposed against unexposed across the whole corpus is confounded by
construction: the strata differ in composition. The MH pooled risk difference
weights each stratum by its own size, so the comparison is only ever made
between trajectories that agree on everything else recorded. That is the closest
an observational method gets to holding the world fixed, and it is still not
causation — see `inference.py` for what is and is not claimed on the strength of
it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# 1.959964 = the 97.5th percentile of the standard normal. Hard-coded rather
# than imported so the package stays standard-library-only and deterministic.
Z_95 = 1.959964


@dataclass(frozen=True)
class Interval:
    """A proportion with a Wilson score interval."""

    successes: int
    total: int
    lower: float
    upper: float

    @property
    def point(self) -> float:
        return self.successes / self.total if self.total else 0.0

    @property
    def width(self) -> float:
        return self.upper - self.lower

    def excludes(self, value: float) -> bool:
        return value < self.lower or value > self.upper

    def as_dict(self) -> dict:
        return {"successes": self.successes, "total": self.total,
                "point": round(self.point, 4), "lower": round(self.lower, 4),
                "upper": round(self.upper, 4), "width": round(self.width, 4)}


def wilson(successes: int, total: int, z: float = Z_95) -> Interval:
    """Wilson score interval for a binomial proportion."""
    if total <= 0:
        return Interval(0, 0, 0.0, 1.0)
    phat = successes / total
    denominator = 1 + z * z / total
    centre = (phat + z * z / (2 * total)) / denominator
    margin = (z * math.sqrt(phat * (1 - phat) / total
                            + z * z / (4 * total * total))) / denominator
    return Interval(successes, total, max(0.0, centre - margin),
                    min(1.0, centre + margin))


@dataclass
class StratumCounts:
    """One matched stratum: exposed and unexposed arms, with outcomes."""

    key: str
    exposed_total: int = 0
    exposed_unsafe: int = 0
    unexposed_total: int = 0
    unexposed_unsafe: int = 0

    @property
    def informative(self) -> bool:
        """Both arms present. A stratum with only one arm contributes nothing
        to a comparison and must not be counted as evidence for it."""
        return self.exposed_total > 0 and self.unexposed_total > 0

    @property
    def total(self) -> int:
        return self.exposed_total + self.unexposed_total

    @property
    def risk_difference(self) -> float:
        if not self.informative:
            return 0.0
        return (self.exposed_unsafe / self.exposed_total
                - self.unexposed_unsafe / self.unexposed_total)

    def as_dict(self) -> dict:
        return {"key": self.key, "exposed": [self.exposed_unsafe, self.exposed_total],
                "unexposed": [self.unexposed_unsafe, self.unexposed_total],
                "risk_difference": round(self.risk_difference, 4)}


@dataclass
class Association:
    """A stratified association, with the interval that decides whether to
    believe it."""

    exposure: str
    observable: str
    strata_total: int = 0
    strata_informative: int = 0
    matched_trajectories: int = 0
    pooled_risk_difference: float = 0.0
    lower: float = 0.0
    upper: float = 0.0
    per_stratum: tuple = ()

    @property
    def significant(self) -> bool:
        """The interval excludes zero on the positive side.

        One-sided in effect: LB-2 is looking for an observable whose presence
        makes harm MORE likely within matched strata. A protective association
        is a real finding but not the one being tested for.
        """
        return self.lower > 0.0

    def as_dict(self) -> dict:
        return {
            "exposure": self.exposure, "observable": self.observable,
            "strata_total": self.strata_total,
            "strata_informative": self.strata_informative,
            "matched_trajectories": self.matched_trajectories,
            "pooled_risk_difference": round(self.pooled_risk_difference, 4),
            "ci_lower": round(self.lower, 4), "ci_upper": round(self.upper, 4),
            "significant": self.significant,
            "example_strata": [s.as_dict() for s in self.per_stratum[:5]],
        }


def mantel_haenszel(strata, exposure: str = "", observable: str = "") -> Association:
    """Pool per-stratum risk differences, weighting by stratum size.

    The variance is the standard weighted sum; where an arm is empty the
    stratum is skipped entirely rather than smoothed, because inventing a
    pseudo-count would manufacture evidence from a comparison that was never
    available.
    """
    informative = [s for s in strata if s.informative]
    association = Association(
        exposure=exposure, observable=observable, strata_total=len(strata),
        strata_informative=len(informative),
        matched_trajectories=sum(s.total for s in informative),
        per_stratum=tuple(sorted(informative,
                                 key=lambda s: (-s.total, s.key))))
    if not informative:
        return association

    weight_total = 0.0
    weighted = 0.0
    variance = 0.0
    for stratum in informative:
        n1, n0 = stratum.exposed_total, stratum.unexposed_total
        weight = (n1 * n0) / (n1 + n0)
        p1 = stratum.exposed_unsafe / n1
        p0 = stratum.unexposed_unsafe / n0
        weighted += weight * (p1 - p0)
        weight_total += weight
        variance += (weight ** 2) * (p1 * (1 - p1) / n1 + p0 * (1 - p0) / n0)

    if weight_total <= 0:
        return association
    pooled = weighted / weight_total
    standard_error = math.sqrt(variance) / weight_total if variance > 0 else 0.0
    association.pooled_risk_difference = pooled
    association.lower = pooled - Z_95 * standard_error
    association.upper = pooled + Z_95 * standard_error
    return association


def agreement(left, right) -> float:
    """Fraction of positions where two boolean vectors agree.

    Used for collinearity: two exposures that agree everywhere in the observed
    data cannot be told apart by any amount of observational analysis, and
    saying which one is the cause would be a guess dressed as a finding.
    """
    if not left:
        return 1.0
    same = sum(1 for a, b in zip(left, right) if bool(a) == bool(b))
    return same / len(left)
