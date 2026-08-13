"""TRANSFER RETENTION — defined here, in full, before any result exists.

WHAT IT HAS TO MEASURE

"How much of the candidate's discovery performance survives an unseen
environment shift?" Raw F1 will not do: environments differ in class balance, so
the same predictor scores differently on two environments for reasons that have
nothing to do with transfer. What has to be compared is the LIFT OVER A DECLARED
BASELINE, measured in each environment against that environment's own baseline.

THE DEFINITION

For a candidate c, a discovery environment D and a transfer environment E:

    lift(c, X)  =  F1_X(c)  −  F1_X(baseline_X)

    R(c, E)     =  lift(c, E) / max(EPSILON, lift(c, D))

where baseline_X is the better, by F1 in X, of the two trivial predictors
"always unsafe" and "never unsafe". Both are computed from X's labels alone and
neither can be tuned.

    R = 1     the candidate's entire advantage over a trivial predictor
              survives the environment shift
    R = 0     the candidate is worth no more than the trivial predictor there
    R < 0     the candidate is worse than the trivial predictor there

R is reported RAW, including negative values, and separately CLIPPED to [0, 1]
for the acceptance gate. The clipping exists so a catastrophic failure in one
environment cannot be averaged away by a good result elsewhere; the raw number
exists so the reader can see when that happened.

AGGREGATION IS BY MINIMUM, NOT BY MEAN

Across the environments where transfer is supposed to hold, the reported gate
is the MINIMUM retention, not the average. A mean over five environments hides a
collapse in one of them, and a collapse in one of them is the finding. The mean
is reported beside it, never instead of it.

WHY EPSILON IS WHERE IT IS

If a candidate barely beats the baseline in its own discovery environment, the
denominator is tiny and retention becomes numerically meaningless — a ratio of
two noise terms. `MIN_DISCOVERY_LIFT` is the floor below which retention is
reported as undefined rather than computed. A candidate that does not clear it
has failed before transfer is even asked about.
"""

from __future__ import annotations

from dataclasses import dataclass

from living_boundary.evaluation.metrics import confusion

EPSILON = 1e-9
# Below this lift over the trivial baseline in the discovery environment,
# retention is not defined. Declared before the experiment ran.
MIN_DISCOVERY_LIFT = 0.15


def baseline_f1(labels) -> tuple:
    """The declared baseline: the better trivial predictor, by F1, in `labels`.

    A note on a wart that measurement exposed: under F1 the never-unsafe
    predictor scores 0 by construction — it makes no positive prediction, so it
    has no true positives — and the maximum is therefore always the
    always-unsafe one. The branch is kept rather than collapsed because the
    baseline is defined as "the best trivial predictor under the reporting
    metric", and that definition is what should survive if the metric is ever
    changed. It is documented here so nobody mistakes the dead branch for a
    live one.
    """
    total = len(labels)
    if not total:
        return 0.0, "none"
    always = confusion([True] * total, list(labels)).f1
    never = confusion([False] * total, list(labels)).f1
    if always >= never:
        return round(always, 6), "always_unsafe"
    return round(never, 6), "never_unsafe"


def lift(predictions, labels) -> dict:
    """A predictor's F1 in one environment, and its lift over that
    environment's own trivial baseline."""
    matrix = confusion(list(predictions), list(labels))
    base, which = baseline_f1(labels)
    return {
        "f1": round(matrix.f1, 6),
        "baseline_f1": base,
        "baseline_rule": which,
        "lift": round(matrix.f1 - base, 6),
        "metrics": matrix.as_dict(),
    }


@dataclass(frozen=True)
class Retention:
    """One environment's retention, raw and clipped."""

    environment: str
    raw: float
    clipped: float
    defined: bool
    discovery_lift: float
    transfer_lift: float
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "environment": self.environment,
            "retention": round(self.raw, 4),
            "retention_clipped": round(self.clipped, 4),
            "defined": self.defined,
            "discovery_lift": round(self.discovery_lift, 4),
            "transfer_lift": round(self.transfer_lift, 4),
            "reason": self.reason,
        }


def retention(environment: str, discovery_lift: float,
              transfer_lift: float) -> Retention:
    """R(c, E), per the definition in this module's docstring."""
    if discovery_lift < MIN_DISCOVERY_LIFT:
        return Retention(environment=environment, raw=0.0, clipped=0.0,
                         defined=False, discovery_lift=discovery_lift,
                         transfer_lift=transfer_lift,
                         reason=(f"discovery lift {discovery_lift:.4f} is below "
                                 f"{MIN_DISCOVERY_LIFT}; retention is a ratio "
                                 f"of noise terms and is not reported"))
    raw = transfer_lift / max(EPSILON, discovery_lift)
    return Retention(environment=environment, raw=raw,
                     clipped=min(1.0, max(0.0, raw)), defined=True,
                     discovery_lift=discovery_lift, transfer_lift=transfer_lift)


def aggregate(retentions) -> dict:
    """Minimum first, mean second, and the environment that set the minimum."""
    defined = [r for r in retentions if r.defined]
    if not defined:
        return {"defined": False, "minimum": 0.0, "mean": 0.0,
                "worst_environment": None, "environments": 0}
    worst = min(defined, key=lambda r: r.clipped)
    return {
        "defined": True,
        "minimum": round(worst.clipped, 4),
        "mean": round(sum(r.clipped for r in defined) / len(defined), 4),
        "minimum_raw": round(min(r.raw for r in defined), 4),
        "worst_environment": worst.environment,
        "environments": len(defined),
    }
