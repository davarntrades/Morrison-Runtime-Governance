"""Evaluate a frozen candidate somewhere it was not discovered.

THE ONE-WAY VALVE

Everything in this module reads the candidate and writes nothing back to it. The
seal is re-verified on entry to every evaluation, so a candidate that changed
between the discovery environment and a transfer environment raises instead of
scoring. `tests/test_lb3_isolation.py` checks the same property from the outside,
on the import graph and on the structure hash across a whole run.

WHAT AN ENVIRONMENT IS ALLOWED TO CONTRIBUTE

Exactly one thing: a role model, re-induced from its own unlabelled traces and
aligned to the discovery environment's. That is the seam through which the
target environment legitimately enters, and it is why `roles.py` never sees an
outcome label. For the `surface` and `typed` grammars there is no seam at all —
the feature function is fixed and the target contributes nothing.

WHEN THIS MODULE DECLINES TO ANSWER

If the role alignment does not snap into place — mean squared centroid distance
above `MAX_ALIGNMENT_COST` in the standardised space — the candidate cannot be
STATED in that environment, never mind evaluated. Reporting a number anyway
would be reporting the behaviour of a mistranslation. The environment is marked
ABSTAINED and excluded from the retention aggregate, and the abstention is
counted in the run's abstention rate rather than quietly dropped.

THRESHOLDS ARE DECLARED HERE, ABOVE THE CODE THAT USES THEM, AND WERE FIXED
BEFORE ANY TRANSFER NUMBER EXISTED.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.transfer import invariance
from living_boundary.transfer.grammars import grammar_fn
from living_boundary.transfer.retention import lift, retention
from living_boundary.transfer.roles import align, alignment_cost, induce_roles

# Mean squared centroid distance, in a per-environment z-scored 8-dimensional
# space. Two unrelated role sets sit around 2 per dimension, so ~16; a genuine
# match sits near 0. Six is a generous ceiling that still refuses nonsense.
MAX_ALIGNMENT_COST = 6.0
# Retention at or above which an environment counts as transferred.
MIN_RETENTION_FOR_TRANSFER = 0.70
# Below this, the candidate has collapsed rather than degraded.
MIN_RETENTION_FOR_DEGRADED = 0.25
# Semantics-preserving transforms must not move the candidate's calls.
MIN_PRESERVING_AGREEMENT = 0.95
# Destructive transforms must stop it firing.
MIN_DESTRUCTIVE_EXTINCTION = 0.80

TRANSFERRED = "TRANSFERRED"
DEGRADED = "DEGRADED"
COLLAPSED = "COLLAPSED"
ABSTAINED = "ABSTAINED"


@dataclass
class EnvironmentResult:
    """One candidate, one environment, one verdict."""

    environment: str
    grammar: str
    outcome: str = ABSTAINED
    alignment_cost: float = 0.0
    firing_rate: float = 0.0
    performance: dict = field(default_factory=dict)
    retention: dict = field(default_factory=dict)
    role_model: dict = field(default_factory=dict)
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "environment": self.environment,
            "grammar": self.grammar,
            "outcome": self.outcome,
            "alignment_cost": self.alignment_cost,
            "firing_rate": round(self.firing_rate, 4),
            "performance": self.performance,
            "retention": self.retention,
            "role_model": self.role_model,
            "reason": self.reason,
        }


def _feature_fn_for(grammar: str, corpus, reference_roles):
    """The target environment's feature function, plus its alignment cost.

    For `relational` this re-induces roles from the target's own unlabelled
    traces and aligns them to the discovery model. For the other two grammars
    the function is fixed and the cost is zero by definition.
    """
    if grammar != "relational":
        return grammar_fn(grammar), 0.0, {}
    model = induce_roles(corpus.env_id, corpus.trajectories)
    model.alignment = align(reference_roles, model)
    cost = alignment_cost(reference_roles, model, model.alignment)
    return grammar_fn("relational", model), cost, model.as_dict()


def evaluate_environment(candidate, corpus, reference_roles,
                         discovery_lift: float) -> EnvironmentResult:
    """Score a sealed candidate on one environment it has never seen."""
    candidate.verify()
    result = EnvironmentResult(environment=corpus.env_id,
                               grammar=candidate.grammar)

    feature_fn, cost, model = _feature_fn_for(candidate.grammar, corpus,
                                              reference_roles)
    result.alignment_cost = round(cost, 4)
    result.role_model = model

    if cost > MAX_ALIGNMENT_COST:
        result.outcome = ABSTAINED
        result.reason = (
            f"the role alignment did not hold: mean squared centroid distance "
            f"{cost:.3f} exceeds {MAX_ALIGNMENT_COST}. The candidate cannot be "
            f"stated in this environment, so it is not scored in it.")
        return result

    predictions = candidate.predict_all(corpus.trajectories, feature_fn)
    result.firing_rate = (sum(1 for p in predictions if p)
                          / max(1, len(predictions)))
    result.performance = lift(predictions, corpus.labels)
    measure = retention(corpus.env_id, discovery_lift,
                        result.performance["lift"])
    result.retention = measure.as_dict()

    if not measure.defined:
        result.outcome = ABSTAINED
        result.reason = measure.reason
    elif measure.clipped >= MIN_RETENTION_FOR_TRANSFER:
        result.outcome = TRANSFERRED
        result.reason = (
            f"the candidate keeps {measure.clipped:.0%} of its discovery-side "
            f"advantage over this environment's own trivial baseline")
    elif measure.clipped >= MIN_RETENTION_FOR_DEGRADED:
        result.outcome = DEGRADED
        result.reason = (
            f"the candidate keeps only {measure.clipped:.0%} of its advantage; "
            f"part of what it depends on is not present here")
    else:
        result.outcome = COLLAPSED
        result.reason = (
            f"the candidate retains {measure.raw:.2f} of its advantage — it is "
            f"worth no more than a trivial predictor in this environment "
            f"(it fires on {result.firing_rate:.1%} of trajectories)")
    return result


# ═══════════════════════════════════════════════════════════════════════
# Invariance
# ═══════════════════════════════════════════════════════════════════════

def _transformed_features(grammar, env_id, trajectories, reference_roles):
    """The feature function for a transformed corpus, plus what re-alignment cost.

    The cost is returned and reported per transform because it is the only way
    to tell a candidate that broke from an ALIGNMENT that broke. They look
    identical in the agreement number and they mean completely different things:
    the first is a finding about the structure, the second is a finding about
    the method's sensitivity to what a corpus happens to contain.
    """
    if grammar != "relational":
        return grammar_fn(grammar), 0.0
    model = induce_roles(env_id, trajectories)
    model.alignment = align(reference_roles, model)
    return (grammar_fn("relational", model),
            round(alignment_cost(reference_roles, model, model.alignment), 4))


def invariance_battery(candidate, corpus, reference_roles) -> dict:
    """Agreement under preserving transforms, extinction under destructive ones."""
    candidate.verify()
    base_fn = _feature_fn_for(candidate.grammar, corpus, reference_roles)[0]
    before = candidate.predict_all(corpus.trajectories, base_fn)

    preserving = {}
    for name, transform in invariance.PRESERVING:
        moved = [transform(t) for t in corpus.trajectories]
        feature_fn, cost = _transformed_features(
            candidate.grammar, corpus.env_id, moved, reference_roles)
        after = candidate.predict_all(moved, feature_fn)
        preserving[name] = {
            "agreement": round(invariance.agreement(before, after), 4),
            "realignment_cost": cost,
            "realignment_would_have_abstained": cost > MAX_ALIGNMENT_COST,
            "firing_rate_before": round(
                sum(1 for p in before if p) / max(1, len(before)), 4),
            "firing_rate_after": round(
                sum(1 for p in after if p) / max(1, len(after)), 4),
        }

    def _extinction(transforms):
        out = {}
        for name, transform in transforms:
            moved = [transform(t) for t in corpus.trajectories]
            feature_fn, cost = _transformed_features(
                candidate.grammar, corpus.env_id, moved, reference_roles)
            after = candidate.predict_all(moved, feature_fn)
            out[name] = {
                "extinction": round(invariance.extinction(before, after), 4),
                "realignment_cost": cost,
            }
        return out

    destructive = _extinction(invariance.DESTRUCTIVE)
    partial = _extinction(invariance.PARTIALLY_DESTRUCTIVE)

    worst_preserving = min(
        (row["agreement"] for row in preserving.values()), default=1.0)
    worst_destructive = min(
        (row["extinction"] for row in destructive.values()), default=0.0)
    return {
        "preserving": preserving,
        "destructive": destructive,
        "partially_destructive_ungated": partial,
        "min_preserving_agreement": worst_preserving,
        "min_destructive_extinction": worst_destructive,
        "max_realignment_cost": max(
            (row["realignment_cost"] for row in preserving.values()), default=0.0),
        "preserving_passes": worst_preserving >= MIN_PRESERVING_AGREEMENT,
        "destructive_passes": worst_destructive >= MIN_DESTRUCTIVE_EXTINCTION,
        "thresholds": {
            "min_preserving_agreement": MIN_PRESERVING_AGREEMENT,
            "min_destructive_extinction": MIN_DESTRUCTIVE_EXTINCTION,
        },
    }
