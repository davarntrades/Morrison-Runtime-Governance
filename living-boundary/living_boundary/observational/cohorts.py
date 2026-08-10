"""Matched observational cohorts, and the counterfactual proxies inside them.

An association computed over the whole archive is confounded by construction —
the exposed and unexposed trajectories differ in a hundred other recorded ways.
The observational answer is to compare only trajectories that agree on
everything else the telemetry captured, which is what a matched stratum is:

    stratum key = the canonical record with the candidate observable MASKED OUT
    arms        = the candidate observable present / absent
    outcome     = what actually happened, already, irreversibly

Each pair drawn from one stratum is a COUNTERFACTUAL PROXY: not a counterfactual
(nobody re-ran anything) but the nearest thing an archive can supply — two real
events that the telemetry says were the same except for one thing.

EXACT FIRST, NEAREST-NEIGHBOUR ONLY AS A FALLBACK, ALWAYS LABELLED

Exact matching is sparse, and sparsity is the standing occupational hazard of
observational work. When too few strata carry both arms, this module falls back
to matching on the feature signature alone — a coarser key that pools genuinely
different records together. That is weaker evidence and it is reported as such
in `matching`, never silently substituted, because the difference between
"matched on everything recorded" and "matched on what the grammar happens to
look at" is the difference between a defensible comparison and a hopeful one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.observational.archive import (
    OBSERVABLE_FIELDS, feature_signature, record_signature,
)
from living_boundary.observational.uncertainty import (
    Association, StratumCounts, agreement, mantel_haenszel,
)

# Below this many strata carrying BOTH arms, an exact-matched comparison is not
# a comparison. The fallback is tried, and if that also fails the exposure is
# reported as unmatchable rather than scored.
MIN_INFORMATIVE_STRATA = 4
# A pooled estimate resting on a handful of trajectories is noise with a
# decimal point.
MIN_MATCHED_TRAJECTORIES = 30
# Two exposures agreeing this often in the observed data cannot be separated by
# any observational method, however much data there is.
COLLINEARITY_THRESHOLD = 0.98


@dataclass
class ExposureResult:
    """One candidate observable, matched and scored."""

    name: str
    family: str
    observable: str
    association: Association
    matching: str = "exact"
    matchable: bool = True
    proxy_pairs: int = 0
    proxy_availability: float = 0.0

    @property
    def usable(self) -> bool:
        return (self.matchable
                and self.association.strata_informative >= MIN_INFORMATIVE_STRATA
                and self.association.matched_trajectories >= MIN_MATCHED_TRAJECTORIES)

    @property
    def supported(self) -> bool:
        return self.usable and self.association.significant

    def as_dict(self) -> dict:
        return {
            "exposure": self.name, "family": self.family,
            "observable": self.observable, "matching": self.matching,
            "matchable": self.matchable, "usable": self.usable,
            "supported": self.supported,
            "proxy_pairs": self.proxy_pairs,
            "proxy_availability": round(self.proxy_availability, 4),
            "association": self.association.as_dict(),
        }


def _build_strata(trajectories, exposure_fn, key_fn, keys=None):
    """Group into matched strata.

    `keys` lets a caller supply record signatures computed once and reused
    across every exposure that shares a mask. Signature construction dominates
    the runtime — it canonicalises, serialises and hashes an entire trajectory —
    and recomputing it per exposure made a full run several times slower for no
    change in result.
    """
    strata: dict = {}
    for index, trajectory in enumerate(trajectories):
        key = keys[index] if keys is not None else key_fn(trajectory)
        stratum = strata.setdefault(key, StratumCounts(key=key))
        exposed = (exposure_fn[index] if isinstance(exposure_fn, list)
                   else exposure_fn(trajectory))
        unsafe = 1 if trajectory.is_unsafe_observed else 0
        if exposed:
            stratum.exposed_total += 1
            stratum.exposed_unsafe += unsafe
        else:
            stratum.unexposed_total += 1
            stratum.unexposed_unsafe += unsafe
    return list(strata.values())


def signature_table(trajectories, masks):
    """Record signatures for every mask a cohort analysis will need, once."""
    return {mask: [record_signature(t, mask=mask) for t in trajectories]
            for mask in masks}


def _proxy_stats(strata) -> tuple:
    """How many real counterfactual pairs the archive actually supplied."""
    informative = [s for s in strata if s.informative]
    pairs = sum(min(s.exposed_total, s.unexposed_total) for s in informative)
    covered = sum(s.total for s in informative)
    total = sum(s.total for s in strata)
    return pairs, (covered / total if total else 0.0)


def mask_for(family):
    return (family.observable,) if family.observable in OBSERVABLE_FIELDS else ()


def evaluate_exposure(trajectories, name: str, family, *, exposure=None,
                      keys=None, feature_keys=None) -> ExposureResult:
    """Match on everything except this observable, then compare outcomes.

    `exposure`, `keys` and `feature_keys` may be supplied precomputed; they are
    identical for every exposure drawn from the same family, and recomputing
    them per exposure dominated the runtime.
    """
    if exposure is None:
        exposure = [name in family.features(t) for t in trajectories]

    mask = mask_for(family)
    strata = _build_strata(trajectories, exposure,
                           lambda t: record_signature(t, mask=mask), keys=keys)
    association = mantel_haenszel(strata, exposure=name,
                                  observable=family.observable)
    pairs, availability = _proxy_stats(strata)
    result = ExposureResult(
        name=name, family=family.name, observable=family.observable,
        association=association, matching="exact",
        proxy_pairs=pairs, proxy_availability=availability)

    if result.usable:
        return result

    # ── fallback: coarser matching, explicitly labelled ──
    fallback_strata = _build_strata(trajectories, exposure, feature_signature,
                                    keys=feature_keys)
    fallback = mantel_haenszel(fallback_strata, exposure=name,
                               observable=family.observable)
    pairs, availability = _proxy_stats(fallback_strata)
    fallback_result = ExposureResult(
        name=name, family=family.name, observable=family.observable,
        association=fallback, matching="nearest_neighbour",
        proxy_pairs=pairs, proxy_availability=availability)
    if fallback_result.usable:
        return fallback_result

    result.matchable = False
    return result


def family_feature_table(trajectories, pool):
    """Each family's feature set for each trajectory, computed once."""
    return {family.name: [family.features(t) for t in trajectories]
            for family in pool}


def candidate_exposures(trajectories, pool, min_support: int = 15,
                        feature_table=None):
    """Every feature name in the pool that occurs often enough to be tested.

    Support-filtered on both sides: a name that fires for three trajectories, or
    for all but three, cannot support a stratified comparison whichever way the
    outcome falls.
    """
    total = len(trajectories)
    feature_table = feature_table or family_feature_table(trajectories, pool)
    out = []
    for family in pool:
        counts: dict = {}
        for names in feature_table[family.name]:
            for name in names:
                counts[name] = counts.get(name, 0) + 1
        for name in sorted(counts):
            if min_support <= counts[name] <= total - min_support:
                out.append((name, family))
    return out


@dataclass
class CohortAnalysis:
    """Every candidate exposure, scored and ranked, plus collinear groupings."""

    results: list = field(default_factory=list)
    collinear_groups: list = field(default_factory=list)

    @property
    def supported(self):
        return [r for r in self.results if r.supported]

    def as_dict(self) -> dict:
        return {
            "exposures_tested": len(self.results),
            "exposures_supported": len(self.supported),
            "collinear_groups": [list(group) for group in self.collinear_groups],
            "ranked": [r.as_dict() for r in self.results[:12]],
        }


def analyse_cohorts(trajectories, pool, min_support: int = 15) -> CohortAnalysis:
    """Score every candidate observable and detect indistinguishable ones."""
    analysis = CohortAnalysis()
    feature_table = family_feature_table(trajectories, pool)
    exposures = candidate_exposures(trajectories, pool, min_support=min_support,
                                    feature_table=feature_table)

    # Signatures are the expensive part and depend only on the mask, so every
    # exposure sharing an observable shares one table.
    masks = {mask_for(family) for _, family in exposures}
    table = signature_table(trajectories, masks)
    feature_keys = [feature_signature(t) for t in trajectories]

    vectors = {}
    for name, family in exposures:
        exposure = [name in names for names in feature_table[family.name]]
        vectors[name] = exposure
        analysis.results.append(evaluate_exposure(
            trajectories, name, family, exposure=exposure,
            keys=table[mask_for(family)], feature_keys=feature_keys))

    analysis.results.sort(
        key=lambda r: (not r.supported,
                       -r.association.pooled_risk_difference,
                       r.name))

    # Collinearity is computed among the SUPPORTED exposures only. Two
    # irrelevant features that happen to agree everywhere are not a problem;
    # two supported ones that do are the reason localisation must abstain.
    supported = [r.name for r in analysis.supported]
    grouped: list = []
    for name in supported:
        placed = False
        for group in grouped:
            if agreement(vectors[name], vectors[group[0]]) >= COLLINEARITY_THRESHOLD:
                group.append(name)
                placed = True
                break
        if not placed:
            grouped.append([name])
    analysis.collinear_groups = [tuple(group) for group in grouped]
    return analysis
