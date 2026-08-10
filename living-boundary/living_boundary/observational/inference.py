"""The LB-2 verdict ladder, and the abstentions that make it worth anything.

Six outcomes, reached by elimination in a fixed order. The order is the
argument: each rung rules out an explanation that would otherwise be able to
account for the same evidence, and the conclusion is only ever what survives.

    TELEMETRY_LIMITED   the evidence itself is broken or incomplete, so no
                        inference about the world is licensed at all
    INCONCLUSIVE        the evidence is intact but does not support a claim —
                        too few matched trajectories, or an association that
                        reverses over time
    ADEQUATE            no material disagreement the grammar cannot handle
    BEYOND_TELEMETRY    the disagreement is real and NOTHING recorded explains
                        it
    INADEQUATE_UNLOCALISED  the telemetry does explain it, but which observable
                        is not identifiable from this archive
    INADEQUATE_LOCALISED    ...and one observable survives matching, temporal
                        consistency, shadow perturbation, and replication on a
                        second archive it was not selected on

CAUSAL HUMILITY IS THE POINT, NOT A CAVEAT

Matched cohorts hold constant everything the telemetry recorded. They cannot
hold constant what it did not, so LB-2 never says "X causes the outcome". The
two claims it is permitted to make are weaker and separately gated:

    "the current representation is insufficient"
        licensed by the collision decomposition, which is arithmetic on
        recorded facts and does not depend on any causal reading

    "this specific observable is likely missing"
        licensed only when a matched association survives with an interval
        excluding zero, keeps its sign across periods, is not collinear with a
        rival, moves the hypothesis when perturbed, and reappears on a
        validation archive drawn from disjoint identities and subjects

Anything less lands on a weaker rung. `INCONCLUSIVE` is a first-class result
here, not a failure to run.

WHAT LOSING REPLAY COSTS, STATED IN THE LADDER ITSELF

`BEYOND_TELEMETRY` covers two situations that LB-1 could separate and LB-2
cannot: a genuinely stochastic world, and a real cause that was never recorded.
Both leave archives in which trajectories identical in every captured field
ended differently. Distinguishing them requires asking the world the same
question twice, and that is exactly the operation LB-2 has given up. The verdict
is named for what the evidence supports rather than for either of the two
stories, and the report says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── declared thresholds ─────────────────────────────────────────────────

# Seals are cryptographic: any break at all means records were altered after
# sealing, and a single tampered record puts the whole archive in question.
MAX_SEAL_FAILURE_RATE = 0.001
# Blank required fields are a different failure — never captured rather than
# altered — and tolerable in small amounts before matching becomes unreliable.
MAX_FIELD_INCOMPLETENESS = 0.02
# Below this, the archive cannot certify anything, including adequacy.
MIN_ARCHIVE_TRAJECTORIES = 200
# The collision-rate interval must be tight enough to act on. A corpus whose
# collision rate is 5% ± 15% has told us nothing.
MAX_COLLISION_RATE_WIDTH = 0.15
# Below this upper bound, disagreement is not material.
MAX_ADEQUATE_COLLISION_RATE = 0.02
# Above this share of the disagreement being record-explicable, the telemetry
# clearly did capture the difference. Below it, it clearly did not.
MIN_RESOLVABLE_FRACTION = 0.60
MAX_BEYOND_TELEMETRY_RESOLVABLE = 0.20


class Lb2Verdict:
    TELEMETRY_LIMITED = "TELEMETRY_LIMITED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ADEQUATE = "ADEQUATE"
    BEYOND_TELEMETRY = "BEYOND_TELEMETRY"
    INADEQUATE_UNLOCALISED = "INADEQUATE_UNLOCALISED"
    INADEQUATE_LOCALISED = "INADEQUATE_LOCALISED"


INADEQUATE_VERDICTS = (Lb2Verdict.INADEQUATE_LOCALISED,
                       Lb2Verdict.INADEQUATE_UNLOCALISED)


@dataclass
class Lb2Assessment:
    """A verdict, the eliminations behind it, and what it refuses to claim."""

    verdict: str
    reason: str
    eliminations: list = field(default_factory=list)
    localisation: dict = field(default_factory=dict)
    claims: dict = field(default_factory=dict)
    integrity: dict = field(default_factory=dict)
    strata: dict = field(default_factory=dict)
    cohorts: dict = field(default_factory=dict)

    @property
    def abstained(self) -> bool:
        return self.verdict in (Lb2Verdict.INCONCLUSIVE,
                                Lb2Verdict.TELEMETRY_LIMITED)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict, "reason": self.reason,
            "abstained": self.abstained,
            "eliminations": list(self.eliminations),
            "claims": dict(self.claims),
            "localisation": dict(self.localisation),
            "integrity": dict(self.integrity),
            "strata": dict(self.strata),
            "cohorts": dict(self.cohorts),
            "status": "experimental",
            "causal_claim": "none",
        }


def _claims(insufficient: bool, localised: bool) -> dict:
    return {
        "representation_is_insufficient": insufficient,
        "specific_observable_is_missing": localised,
        "causation_established": False,
        "note": ("matched cohorts hold constant only what the telemetry "
                 "recorded; an unrecorded common cause remains possible and "
                 "cannot be excluded observationally"),
    }


def assess(archive_integrity, strata, cohorts, temporal_checks,
           shadow_results, *, replication=None) -> Lb2Assessment:
    """Apply the ladder. Every rung is reported, passed or not."""
    eliminations = []

    def _finish(verdict, reason, insufficient=False, localised=False,
                localisation=None):
        return Lb2Assessment(
            verdict=verdict, reason=reason, eliminations=eliminations,
            localisation=localisation or {},
            claims=_claims(insufficient, localised),
            integrity=dict(archive_integrity), strata=strata.as_dict(),
            cohorts=cohorts.as_dict())

    # ── 1. is the evidence usable at all? ──
    seal_rate = archive_integrity.get("seal_failure_rate", 0.0)
    incompleteness = archive_integrity.get("field_incompleteness_rate", 0.0)
    gaps = archive_integrity.get("sequences_with_step_gaps", 0)
    if (seal_rate > MAX_SEAL_FAILURE_RATE
            or incompleteness > MAX_FIELD_INCOMPLETENESS or gaps):
        return _finish(
            Lb2Verdict.TELEMETRY_LIMITED,
            (f"The archive cannot carry an inference: {seal_rate:.1%} of seals "
             f"fail to verify, {incompleteness:.1%} of events are missing "
             f"required fields, and {gaps} sequences have step gaps. Records "
             f"that were altered or never completed cannot be matched against "
             f"each other, so every downstream comparison would be between "
             f"trajectories we cannot claim were comparable."))
    eliminations.append(
        f"the evidence is intact: seal failures {seal_rate:.4f}, field "
        f"incompleteness {incompleteness:.4f}, {gaps} step gaps")

    # ── 2. is there enough of it? ──
    rate = strata.collision_rate
    if strata.trajectories < MIN_ARCHIVE_TRAJECTORIES:
        return _finish(
            Lb2Verdict.INCONCLUSIVE,
            (f"Only {strata.trajectories} sealed trajectories are available "
             f"(minimum {MIN_ARCHIVE_TRAJECTORIES}). That is too few to "
             f"certify adequacy OR to establish a gap; the honest answer is "
             f"that this archive does not settle the question."))
    if rate.width > MAX_COLLISION_RATE_WIDTH:
        return _finish(
            Lb2Verdict.INCONCLUSIVE,
            (f"The collision rate is {rate.point:.3f} with a 95% interval of "
             f"[{rate.lower:.3f}, {rate.upper:.3f}] — a width of {rate.width:.3f}, "
             f"wider than the {MAX_COLLISION_RATE_WIDTH} needed to act on it."))
    eliminations.append(
        f"the sample supports an estimate: {strata.trajectories} sealed "
        f"trajectories, collision rate {rate.point:.3f} "
        f"[{rate.lower:.3f}, {rate.upper:.3f}]")

    # ── 3. is there anything to explain? ──
    if rate.upper < MAX_ADEQUATE_COLLISION_RATE:
        return _finish(
            Lb2Verdict.ADEQUATE,
            (f"No material disagreement survives the current representation: "
             f"the collision rate's upper bound is {rate.upper:.4f}, below the "
             f"{MAX_ADEQUATE_COLLISION_RATE} floor. The grammar separates this "
             f"archive; residual error belongs to the search, not to the "
             f"representation."))
    eliminations.append(
        f"{strata.feature_minority} trajectories sit in feature signatures "
        f"carrying more than one outcome, an error floor of "
        f"{strata.irreducible_error_rate:.2%} for any predicate over the "
        f"current grammar")

    # ── 4. did the telemetry capture the difference at all? ──
    resolvable = strata.resolvable_fraction
    if resolvable.upper < MAX_BEYOND_TELEMETRY_RESOLVABLE:
        return _finish(
            Lb2Verdict.BEYOND_TELEMETRY,
            (f"The disagreement is real and nothing recorded explains it: only "
             f"{resolvable.point:.1%} [{resolvable.lower:.1%}, "
             f"{resolvable.upper:.1%}] of it survives matching on the COMPLETE "
             f"record, so trajectories identical in every captured field ended "
             f"differently. Two situations produce this and observation cannot "
             f"separate them — a genuinely stochastic world, and a real cause "
             f"that was never recorded. Distinguishing them needs the same "
             f"question asked of the world twice, which is the operation this "
             f"phase has given up. Extending the representation would not help "
             f"either way; the next move is better telemetry, not a new "
             f"feature."),
            insufficient=False)
    if resolvable.lower < MIN_RESOLVABLE_FRACTION:
        return _finish(
            Lb2Verdict.INCONCLUSIVE,
            (f"The disagreement is split between what the record explains and "
             f"what it does not — resolvable fraction {resolvable.point:.1%} "
             f"[{resolvable.lower:.1%}, {resolvable.upper:.1%}] — and the "
             f"interval spans the {MIN_RESOLVABLE_FRACTION:.0%} threshold. "
             f"This archive does not establish which reading is right."))
    eliminations.append(
        f"{resolvable.point:.1%} [{resolvable.lower:.1%}, {resolvable.upper:.1%}] "
        f"of the disagreement disappears once trajectories are matched on the "
        f"COMPLETE record, so the telemetry did capture what the grammar missed")

    # ── 5. does anything that separates the collisions also reverse in time? ──
    # Checked BEFORE localisation and against every exposure that resolves the
    # disagreement, not only the ones with a strong pooled effect. An exposure
    # whose association flips sign between periods pools to roughly zero, so
    # ranking by effect size would rank it last and never look at it — and the
    # archive would be reported as missing a stable observable when what it
    # actually shows is a world that moved.
    drifting = [(name, check) for name, check in sorted(temporal_checks.items())
                if check.testable and not check.consistent]
    if drifting:
        name, check = drifting[0]
        return _finish(
            Lb2Verdict.INCONCLUSIVE,
            (f"An observable that separates the disagreement does not hold its "
             f"direction over time: {check.reason} A relationship that reverses "
             f"between collection periods is evidence that the world changed, "
             f"not that the representation is short a field, and this archive "
             f"cannot tell those apart. {len(drifting)} exposure(s) reverse; "
             f"the first is {name!r}."),
            insufficient=False,
            localisation={"localised": False, "reason": "temporal reversal",
                          "reversing_exposures": [n for n, _ in drifting][:8],
                          "temporal": check.as_dict()})
    eliminations.append(
        f"no exposure that separates the disagreement reverses direction across "
        f"collection periods ({len(temporal_checks)} tested)")

    # ── 6. from here the representation IS insufficient. Localise, or don't. ──
    supported = cohorts.supported
    if not supported:
        return _finish(
            Lb2Verdict.INADEQUATE_UNLOCALISED,
            ("The representation is insufficient — the telemetry distinguishes "
             "trajectories the grammar cannot — but no candidate observable "
             "survived matched-cohort analysis with an interval excluding "
             "zero. Something recorded is being ignored; this archive does not "
             "say what."),
            insufficient=True,
            localisation={"localised": False, "reason": "no supported exposure"})

    collinear = [group for group in cohorts.collinear_groups if len(group) > 1]
    if collinear:
        observables = sorted({
            result.observable for result in supported
            if any(result.name in group for group in collinear)})
        if len(observables) > 1:
            return _finish(
                Lb2Verdict.INADEQUATE_UNLOCALISED,
                (f"The representation is insufficient, but WHICH observable is "
                 f"not identifiable from this archive: {observables} move "
                 f"together in every trajectory recorded, so no matched "
                 f"comparison can separate them. Naming one would be a guess "
                 f"presented as a finding. Separating them requires an archive "
                 f"in which they vary independently."),
                insufficient=True,
                localisation={"localised": False, "reason": "collinear candidates",
                              "collinear_observables": observables,
                              "collinear_groups": [list(g) for g in collinear]})

    best = supported[0]
    temporal = temporal_checks.get(best.name)
    if temporal is not None and temporal.testable and not temporal.consistent:
        return _finish(
            Lb2Verdict.INCONCLUSIVE,
            (f"The strongest candidate ({best.name!r}) does not hold up over "
             f"time: {temporal.reason}. An association that reverses is "
             f"evidence the world moved, not that the representation is short "
             f"a field, and this archive cannot tell the two apart."),
            insufficient=False,
            localisation={"localised": False, "reason": "temporal inconsistency",
                          "temporal": temporal.as_dict()})

    shadow = shadow_results.get(best.name)
    if shadow is not None and shadow.synthesisable and not shadow.consistent:
        return _finish(
            Lb2Verdict.INADEQUATE_UNLOCALISED,
            (f"The representation is insufficient, but the candidate does not "
             f"survive perturbation: moving {best.observable!r} in the record "
             f"changed the hypothesis's prediction in only "
             f"{shadow.flip_rate:.0%} of cases, so it is keyed to something "
             f"that travels with that observable rather than to the observable "
             f"itself."),
            insufficient=True,
            localisation={"localised": False, "reason": "shadow inconsistency",
                          "shadow": shadow.as_dict()})

    # ── 7. does the association reappear in a corpus it was not chosen on? ──
    # Discovery selected this exposure out of every candidate the pool offered.
    # Selection over many candidates finds something whether or not anything is
    # there, so the winner is re-measured on a validation archive drawn from
    # disjoint identities and subjects, and has to hold up.
    replicated = (replication or {}).get(best.name)
    if replicated is None or not replicated.get("supported"):
        detail = (replicated or {}).get("detail", "no validation estimate")
        return _finish(
            Lb2Verdict.INADEQUATE_UNLOCALISED,
            (f"The representation is insufficient, but the candidate does not "
             f"replicate: {best.name!r} was selected on the discovery archive "
             f"and does not reach significance on a validation archive drawn "
             f"from disjoint identities and subjects ({detail}). Selection over "
             f"many candidates finds something whether or not anything is "
             f"there, which is exactly what a second corpus is for."),
            insufficient=True,
            localisation={"localised": False, "reason": "no replication",
                          "replication": replicated})
    if replicated.get("sign_flipped"):
        return _finish(
            Lb2Verdict.INADEQUATE_UNLOCALISED,
            (f"The representation is insufficient, but {best.name!r} points the "
             f"other way on the validation archive "
             f"({replicated.get('detail')}). An association that changes "
             f"direction between corpora is not a missing observable."),
            insufficient=True,
            localisation={"localised": False, "reason": "replication sign flip",
                          "replication": replicated})
    eliminations.append(
        f"the association replicates on a validation archive with disjoint "
        f"identities and subjects ({replicated.get('detail')})")

    return _finish(
        Lb2Verdict.INADEQUATE_LOCALISED,
        (f"The representation is insufficient and the gap localises to "
         f"{best.observable!r}. Matched on the complete record minus that "
         f"observable, its presence shifts the outcome rate by "
         f"{best.association.pooled_risk_difference:+.3f} "
         f"[{best.association.lower:+.3f}, {best.association.upper:+.3f}] "
         f"across {best.association.strata_informative} informative strata "
         f"covering {best.association.matched_trajectories} trajectories "
         f"({best.matching} matching). The association keeps its sign across "
         f"collection periods, no rival observable is collinear with it, "
         f"perturbing it in the record moves the hypothesis, and it replicates "
         f"on a validation archive it was not selected on. This is an "
         f"association under matching, not a demonstrated cause."),
        insufficient=True, localised=True,
        localisation={
            "localised": True, "observable": best.observable,
            "exposure": best.name, "family": best.family,
            "matching": best.matching,
            "association": best.association.as_dict(),
            "temporal": temporal.as_dict() if temporal else None,
            "shadow": shadow.as_dict() if shadow else None,
            "replication": replicated,
        })
