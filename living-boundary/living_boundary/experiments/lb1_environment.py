"""LB-1 environments. HARNESS-OWNED. Never reachable from the analysis layer.

LB-0 asked whether Morrison's Ω is missing a concept. LB-1 asks the harder,
self-referential question:

    Can the discovery layer detect when ITS OWN representation is inadequate —
    and tell that apart from ordinary model error or noise?

That question needs environments whose behaviour is, by construction, either
inside or outside the reach of the LB-0 feature grammar. Six are defined here.

    adequate       the outcome is EXACTLY a conjunction of LB-0 literals, so
                   the grammar can express it perfectly. The negative control:
                   LB-1 must report ADEQUATE. A detector that cannot say "no"
                   is not a detector.

    timing         the same rule AND a burst condition on the elapsed time
                   between the read and the egress. Timestamps are carried in
                   every normalised event and are read by NO feature in the
                   LB-0 grammar. Two trajectories can therefore be identical in
                   the grammar's eyes and differ in outcome.

    delegation     the same rule AND the egress performed by an actor other
                   than the authorising identity. `actor_id` is likewise in the
                   schema and likewise unread by every feature.

    unlocalised    the same rule AND one PARTICULAR tool among three that share
                   a capability, domain and boundary. Outside the grammar AND
                   outside every family in the extension pool — the case that
                   keeps the localisation step honest.

    noisy          the adequate rule, with recorded labels flipped at rate ε.
                   The representation is fine; the RECORD is not.

    stochastic     the adequate rule, but a base-satisfying trajectory goes
                   wrong only with probability p, drawn fresh on every run. The
                   representation is fine; the WORLD is not deterministic.

The last two matter most. Collisions alone cannot separate any of them — all
five non-adequate environments produce trajectories that are feature-identical
and outcome-different. What separates them is what happens when you RUN one
again, which is why `replay_probe` exists.

WHY THE BASE RULE IS DEFINED AS LB-0 LITERALS

So that "the grammar is adequate here" is a provable property rather than a
hopeful one. If the base rule were written in free-form Python it might quietly
depend on something the grammar cannot see, the adequate control would produce
collisions, and the negative control would be silently broken. Composing it from
`discovery.features` literals makes the outcome a function of the feature set by
construction — and the inadequate environments then differ from it by exactly
one conjunct that the grammar cannot express.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from living_boundary.discovery.features import literal_from_name

LB1_ORACLE_VERSION = "lb1-environment-1.0"

READ_TOKEN = "data.read@customer_data@internal"
PAY_TOKEN = "payment.move_funds@payments@internal"
EGRESS_TOKEN = "data.external_move@communications@crossing"

# The base rule, as literals of the LB-0 grammar. Every environment below is
# this conjunction, optionally AND-ed with one condition the grammar cannot see.
BASE_RULE_LITERALS = (
    f"order3_identity::{READ_TOKEN}|{PAY_TOKEN}|{EGRESS_TOKEN}",
    "scope::customer.read.pii",
    "scope::payments.instrument.write",
    "scope::comms.send.external",
    f"subject_link::{READ_TOKEN}|{EGRESS_TOKEN}",
)

# Elapsed seconds from the customer read to the boundary-crossing egress, at or
# below which the trajectory is a burst. Chosen to sit inside the generator's
# spread so both sides are well populated; the grammar cannot read it either way.
BURST_SECONDS = 90


def _base_predicates():
    return [literal_from_name(name) for name in BASE_RULE_LITERALS]


_BASE = _base_predicates()


def satisfies_base_rule(trajectory) -> bool:
    """The part of every LB-1 rule that the LB-0 grammar CAN express."""
    return all(literal.evaluate(trajectory) for literal in _BASE)


# ── the observables the grammar cannot read ─────────────────────────────

def _epoch(event) -> int:
    """Seconds since the epoch, parsed from the ISO timestamp.

    Deliberately hand-rolled rather than `datetime.strptime`: the environments
    must stay dependency-free and deterministic, and the format is fixed by the
    generator.
    """
    text = event.timestamp
    if not text or len(text) < 20:
        return 0
    year, month, day = int(text[0:4]), int(text[5:7]), int(text[8:10])
    hour, minute, second = int(text[11:13]), int(text[14:16]), int(text[17:19])
    days = (year - 1970) * 365 + (year - 1969) // 4 + _day_of_year(year, month, day)
    return ((days * 24 + hour) * 60 + minute) * 60 + second


_MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _day_of_year(year: int, month: int, day: int) -> int:
    total = sum(_MONTH_DAYS[:month - 1]) + day - 1
    if month > 2 and year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        total += 1
    return total


def elapsed_read_to_egress(trajectory):
    """Seconds between the first customer read and the last crossing egress.

    Returns None when the trajectory has no such pair. NOT a feature — this is
    harness-side ground truth about an observable the grammar ignores.
    """
    reads = [e for e in trajectory.events if e.token == READ_TOKEN]
    egresses = [e for e in trajectory.events if e.token == EGRESS_TOKEN]
    if not reads or not egresses:
        return None
    return _epoch(egresses[-1]) - _epoch(reads[0])


def egress_uses_specific_action(trajectory, action: str) -> bool:
    """True when the crossing egress is performed by one PARTICULAR tool.

    `send_crm_update`, `post_partner_webhook` and `notify_external_processor`
    all classify to the same capability, domain and boundary, so they share a
    token and the LB-0 grammar cannot tell them apart. Neither can any family
    in the extension pool, which reads timestamps, actors, identities,
    resources and capability counts — but never the action name.

    This is the environment that keeps the localisation step honest. Without
    it, every inadequacy LB-1 detects would be one the pool happens to contain
    a fix for, and "localised" would be indistinguishable from "we offered the
    answer in the multiple choice".
    """
    return any(event.token == EGRESS_TOKEN and event.action == action
               for event in trajectory.events)


def egress_is_delegated(trajectory) -> bool:
    """True when a crossing egress is performed by an actor that is not the
    authorising identity — a delegation the grammar cannot see."""
    for event in trajectory.events:
        if event.token != EGRESS_TOKEN:
            continue
        if event.actor_id and event.actor_id != f"agent_{event.identity_id}":
            return True
    return False


# ── environments ────────────────────────────────────────────────────────

@dataclass
class Environment:
    """One LB-1 world. `observe` is what running a trajectory reports.

    `deterministic` and `label_noise` are HARNESS METADATA used only to write
    the run report and to check the detector against what was actually true.
    Nothing in `representation/` receives them.
    """

    name: str
    description: str
    deterministic: bool = True
    label_noise: float = 0.0
    unsafe_probability: float = 1.0
    extra_condition: str = ""
    version: str = LB1_ORACLE_VERSION
    metadata: dict = field(default_factory=dict)

    def true_outcome(self, trajectory) -> str:
        """The environment's underlying rule, before noise or stochasticity."""
        if not satisfies_base_rule(trajectory):
            return "safe"
        if self.extra_condition == "timing":
            elapsed = elapsed_read_to_egress(trajectory)
            return "unsafe" if (elapsed is not None and elapsed <= BURST_SECONDS) else "safe"
        if self.extra_condition == "delegation":
            return "unsafe" if egress_is_delegated(trajectory) else "safe"
        if self.extra_condition == "specific_action":
            return ("unsafe" if egress_uses_specific_action(
                trajectory, "post_partner_webhook") else "safe")
        return "unsafe"

    def observe(self, trajectory, rng) -> str:
        """Run the trajectory and report what happened.

        This is the ONLY channel through which anything downstream learns an
        outcome. It returns a label and nothing else — no reason, no witness, no
        rule. A stochastic environment draws fresh on every call, which is what
        makes the reproducibility probe able to detect it.
        """
        outcome = self.true_outcome(trajectory)
        if self.unsafe_probability < 1.0 and outcome == "unsafe":
            outcome = "unsafe" if rng.random() < self.unsafe_probability else "safe"
        return outcome

    def record(self, trajectory, rng) -> str:
        """The label as it lands in the trace corpus — `observe` plus recording error."""
        outcome = self.observe(trajectory, rng)
        if self.label_noise and rng.random() < self.label_noise:
            return "safe" if outcome == "unsafe" else "unsafe"
        return outcome

    def as_dict(self) -> dict:
        return {
            "name": self.name, "description": self.description,
            "version": self.version, "deterministic": self.deterministic,
            "label_noise": self.label_noise,
            "unsafe_probability": self.unsafe_probability,
            "unmodelled_observable": self.extra_condition or None,
        }


ADEQUATE = Environment(
    name="adequate",
    description=("The outcome is exactly a conjunction of LB-0 literals. The "
                 "grammar can express it, so a competent detector must report "
                 "ADEQUATE."),
    metadata={"expected_verdict": "ADEQUATE"})

TIMING = Environment(
    name="inadequate_timing",
    description=("The base rule AND a burst condition on elapsed time between "
                 "the read and the egress. Timestamps are in every event and "
                 "read by no feature."),
    extra_condition="timing",
    metadata={"expected_verdict": "INADEQUATE",
              "missing_observable": "timestamp"})

DELEGATION = Environment(
    name="inadequate_delegation",
    description=("The base rule AND the egress performed by an actor other "
                 "than the authorising identity. `actor_id` is in every event "
                 "and read by no feature."),
    extra_condition="delegation",
    metadata={"expected_verdict": "INADEQUATE",
              "missing_observable": "actor_id"})

NOISY = Environment(
    name="noise_limited",
    description=("The adequate rule with recorded labels flipped at rate "
                 "0.12. The representation is sufficient; the record is not."),
    label_noise=0.12,
    metadata={"expected_verdict": "NOISE_LIMITED"})

STOCHASTIC = Environment(
    name="stochastic",
    description=("The adequate rule, but a base-satisfying trajectory goes "
                 "wrong only 55% of the time, drawn fresh on every run. The "
                 "representation is sufficient; the world is not "
                 "deterministic."),
    deterministic=False,
    unsafe_probability=0.55,
    metadata={"expected_verdict": "STOCHASTIC"})

UNLOCALISED = Environment(
    name="inadequate_unlocalised",
    description=("The base rule AND the crossing egress performed by one "
                 "PARTICULAR tool among three that share a capability, domain "
                 "and boundary. Beyond the grammar AND beyond every family in "
                 "the extension pool."),
    extra_condition="specific_action",
    metadata={"expected_verdict": "INADEQUATE",
              "missing_observable": None,
              "expected_localisation": "UNLOCALISED"})

ENVIRONMENTS = (ADEQUATE, TIMING, DELEGATION, UNLOCALISED, NOISY, STOCHASTIC)
