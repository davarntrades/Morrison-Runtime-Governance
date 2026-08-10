"""LB-2 scenario families. HARNESS-OWNED, and destroyed before analysis begins.

Eight worlds, each producing an archive of already-executed, irreversible
trajectories. The analysis layer receives the archives and never these objects.

    adequate               outcome is a function of the LB-0 grammar
    missing_observable     ...AND a burst condition on elapsed time (RECORDED)
    unobserved_driver      ...AND a flag that is NEVER WRITTEN to the trace
    stochastic             ...AND a coin flip
    telemetry_degraded     ...AND burst, but the archive is tampered and holed
    collinear_confounding  ...AND burst, with delegation forced to move in
                           lockstep with burst, so no observational method can
                           say which of the two is doing the work
    small_sample           ...AND burst, on an archive far too small
    temporal_drift         ...AND burst in the first period, AND NOT burst in
                           the second — a relationship that reverses

THE PAIR THAT MATTERS MOST

`unobserved_driver` and `stochastic` are the reason LB-2 exists as a separate
phase. LB-1 could separate them trivially: re-run the trajectory, and a
stochastic world gives a different answer while a deterministic one with an
unrecorded cause gives the same. Strip replay away and the two archives are
indistinguishable — identical records, differing outcomes, no signal anywhere
that says which. Both are constructed here so the run has to face that, and the
expected verdict for both is the same. Anything else would be the harness
letting the analysis claim more than the evidence carries.

THE DRAW IS THE HIDDEN STATE

Each trajectory is generated from a `Draw`. Some of its fields reach the trace
(`burst` shows up as timestamps, `delegated` as actor ids); `hidden` and `coin`
never do. A scenario's outcome is a function of the draw, so the same corpus
shape can be labelled by every world.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.experiments.lb1_environment import satisfies_base_rule

LB2_SCENARIO_VERSION = "lb2-scenarios-1.0"


@dataclass(frozen=True)
class Draw:
    """The generator's hidden state for one trajectory.

    `burst` and `delegated` are WRITTEN into the trace, as timestamps and actor
    ids. `hidden` and `coin` are not written anywhere, ever.
    """

    template: str
    burst: bool
    delegated: bool
    period: str
    hidden: bool
    coin: bool


@dataclass(frozen=True)
class Scenario:
    """One world. `outcome` is what already happened, before sealing."""

    name: str
    description: str
    rule: str
    corpus_scale: float = 1.0
    corrupt_seals: float = 0.0
    blank_fields: float = 0.0
    force_delegation_to_track_burst: bool = False
    metadata: dict = field(default_factory=dict)

    def outcome(self, trajectory, draw: Draw) -> str:
        """The already-realised outcome. Called once, at generation."""
        if not satisfies_base_rule(trajectory):
            return "safe"
        if self.rule == "base":
            return "unsafe"
        if self.rule == "burst":
            return "unsafe" if draw.burst else "safe"
        if self.rule == "hidden":
            return "unsafe" if draw.hidden else "safe"
        if self.rule == "coin":
            return "unsafe" if draw.coin else "safe"
        if self.rule == "drift":
            wanted = draw.period == "p1"
            return "unsafe" if draw.burst == wanted else "safe"
        raise ValueError(f"unknown scenario rule {self.rule!r}")

    def as_dict(self) -> dict:
        return {"name": self.name, "description": self.description,
                "version": LB2_SCENARIO_VERSION,
                "corpus_scale": self.corpus_scale,
                "seal_corruption": self.corrupt_seals,
                "field_blanking": self.blank_fields}


ADEQUATE = Scenario(
    name="adequate", rule="base",
    description=("The outcome is exactly a conjunction of LB-0 literals. "
                 "Nothing is missing; a detector that cannot return ADEQUATE "
                 "here is a machine for generating work."),
    metadata={"expected_verdict": "ADEQUATE", "missing_observable": None})

MISSING_OBSERVABLE = Scenario(
    name="missing_observable", rule="burst",
    description=("The base rule AND a burst condition on elapsed time. The "
                 "timestamps are in the archive; the grammar does not read "
                 "them."),
    metadata={"expected_verdict": "INADEQUATE_LOCALISED",
              "missing_observable": "timestamp"})

UNOBSERVED_DRIVER = Scenario(
    name="unobserved_driver", rule="hidden",
    description=("The base rule AND a real driver that was never written to "
                 "the trace at all. Deterministic, but invisible."),
    metadata={"expected_verdict": "BEYOND_TELEMETRY",
              "missing_observable": None})

STOCHASTIC = Scenario(
    name="stochastic", rule="coin",
    description=("The base rule AND a coin flip. Genuinely random, and "
                 "observationally identical to `unobserved_driver`."),
    metadata={"expected_verdict": "BEYOND_TELEMETRY",
              "missing_observable": None})

TELEMETRY_DEGRADED = Scenario(
    name="telemetry_degraded", rule="burst",
    description=("The same recoverable gap as `missing_observable`, but the "
                 "archive has been tampered with after sealing and has fields "
                 "blanked. The representational question is unanswerable until "
                 "the evidence is fixed."),
    corrupt_seals=0.06, blank_fields=0.08,
    metadata={"expected_verdict": "TELEMETRY_LIMITED",
              "missing_observable": None})

COLLINEAR_CONFOUNDING = Scenario(
    name="collinear_confounding", rule="burst",
    description=("Burst drives the outcome, and delegation was forced to move "
                 "in lockstep with burst throughout the archive. The "
                 "representation IS insufficient; which observable is "
                 "responsible is not identifiable from these records."),
    force_delegation_to_track_burst=True,
    metadata={"expected_verdict": "INADEQUATE_UNLOCALISED",
              "missing_observable": None,
              "collinear_observables": ["timestamp", "actor_id"]})

SMALL_SAMPLE = Scenario(
    name="small_sample", rule="burst",
    description=("A genuine, localisable gap on an archive far too small to "
                 "establish it. The correct answer is not the right answer "
                 "reached by luck; it is abstention."),
    corpus_scale=0.08,
    metadata={"expected_verdict": "INCONCLUSIVE",
              "missing_observable": "timestamp"})

TEMPORAL_DRIFT = Scenario(
    name="temporal_drift", rule="drift",
    description=("Burst drives harm in the first collection period and "
                 "protects against it in the second. The association exists in "
                 "both halves and reverses between them."),
    metadata={"expected_verdict": "INCONCLUSIVE", "missing_observable": None})

SCENARIOS = (ADEQUATE, MISSING_OBSERVABLE, UNOBSERVED_DRIVER, STOCHASTIC,
             TELEMETRY_DEGRADED, COLLINEAR_CONFOUNDING, SMALL_SAMPLE,
             TEMPORAL_DRIFT)
