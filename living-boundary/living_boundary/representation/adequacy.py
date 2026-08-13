"""The LB-1 verdict: is my own representation inadequate, or is this noise?

THE BLUEPRINT'S LB-1 ACCEPTANCE QUESTION

    Can the system distinguish a missing concept from ordinary model error or
    noise?

Collisions alone cannot. Four different worlds produce trajectories that are
feature-identical and outcome-different, and they demand four different
responses:

    ADEQUATE        no collisions worth the name. The representation can
                    express the outcome; residual error is a search problem,
                    not a representation problem. A detector that cannot
                    return this is useless — it would declare every corpus
                    inadequate and nobody would act on it.

    INADEQUATE      the world is reproducible AND the record is faithful, and
                    yet trajectories the grammar calls identical end
                    differently. Everything else has been ruled out; what is
                    left is an observable the representation does not read.

    NOISE_LIMITED   re-running disagrees with the RECORD at a material rate.
                    The representation may be perfectly adequate; the labels
                    are wrong. Extending the grammar here would fit noise.

    STOCHASTIC      re-running the same trajectory twice disagrees with
                    ITSELF. No representation of the trajectory can predict
                    the outcome, because the outcome is not a function of the
                    trajectory. Extending the grammar here is futile.

THE DECISION ORDER IS NOT ARBITRARY

Stochasticity is tested first because it invalidates every other reading: if the
world does not repeat, neither the record nor the representation can be
convicted on this evidence. Record fidelity is tested next because a corrupt
record can manufacture collisions in a perfectly representable world. Only when
both are clean is the representation the remaining explanation — and then the
conclusion follows by elimination, which is why the eliminations have to happen
in that order and have to be reported.

WHAT THIS MODULE MAY SEE

Feature sets, recorded outcomes, and two rates from the probe. It never receives
the environment, its rule, its noise setting or its determinism flag.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── declared thresholds ─────────────────────────────────────────────────
# Stated here, above the code that applies them, and justified individually.

# Below this share of the corpus sitting in unsplittable groups, there is
# nothing to explain. Not zero: a handful of collisions in a corpus of hundreds
# is within what one generator draw produces by chance.
MIN_COLLISION_RATE = 0.02

# A deterministic world repeats ALWAYS. Any self-disagreement above a sampling
# margin is therefore real, and the margin is small on purpose.
MAX_REPRODUCIBLE_SELF_DISAGREEMENT = 0.02

# The same reasoning for the record: a faithful record disagrees with a re-run
# only through sampling accident.
MAX_FAITHFUL_RECORD_DISAGREEMENT = 0.02

# How mixed a colliding group has to be before "the labels are simply noisy"
# stops being a comfortable explanation. Under label noise at rate e the
# expected minority fraction IS e; this asks for materially more than that.
NOISE_EXPLANATION_MARGIN = 2.0


class AdequacyVerdict:
    ADEQUATE = "ADEQUATE"
    INADEQUATE = "INADEQUATE"
    NOISE_LIMITED = "NOISE_LIMITED"
    STOCHASTIC = "STOCHASTIC"


@dataclass
class RepresentationAssessment:
    """The verdict, the reasoning that produced it, and what was ruled out."""

    verdict: str
    reason: str
    representation: str = ""
    collision: dict = field(default_factory=dict)
    probe: dict = field(default_factory=dict)
    eliminations: list = field(default_factory=list)
    residual_beyond_noise: dict = field(default_factory=dict)
    confidence: float = 0.0

    @property
    def is_inadequate(self) -> bool:
        return self.verdict == AdequacyVerdict.INADEQUATE

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "representation": self.representation,
            "confidence": round(self.confidence, 4),
            "collision": dict(self.collision),
            "probe": dict(self.probe),
            "eliminations": list(self.eliminations),
            "residual_beyond_noise": dict(self.residual_beyond_noise),
            "status": "experimental",
        }


def _residual_beyond_noise(collision, noise_rate: float) -> dict:
    """How much of the disagreement the estimated noise rate fails to explain.

    Reported in every verdict, including NOISE_LIMITED. A corpus can be both
    noisy AND missing a concept, and a detector that stopped at "it's noise"
    would hide the second finding behind the first. This does not change the
    verdict — it is evidence a reviewer can act on.
    """
    in_groups = collision.trajectories_in_colliding_groups
    expected = noise_rate * in_groups
    observed = collision.minority_total
    return {
        "estimated_label_noise_rate": round(noise_rate, 4),
        "minority_expected_under_noise": round(expected, 2),
        "minority_observed": observed,
        "ratio": round(observed / expected, 3) if expected > 0 else None,
        "unexplained_by_noise": observed > expected * NOISE_EXPLANATION_MARGIN,
    }


def assess_representation(collision, probe, representation: str = "") -> RepresentationAssessment:
    """Decide whether the representation itself is the limiting factor.

    `collision` is a `CollisionReport`; `probe` is a `ProbeResult`. Both are
    plain measurements — nothing about the world's rule reaches here.
    """
    eliminations = []
    collision_summary = collision.as_dict()
    probe_summary = probe.as_dict()
    residual = _residual_beyond_noise(collision, probe.record_disagreement_rate)

    def _assessment(verdict, reason, confidence):
        return RepresentationAssessment(
            verdict=verdict, reason=reason, representation=representation,
            collision=collision_summary, probe=probe_summary,
            eliminations=eliminations, residual_beyond_noise=residual,
            confidence=confidence)

    # ── 0. is there anything to explain at all? ──
    if collision.collision_rate < MIN_COLLISION_RATE:
        eliminations.append(
            f"collision rate {collision.collision_rate:.4f} is below the "
            f"{MIN_COLLISION_RATE} floor: the representation separates the "
            f"corpus, so no representational claim is available")
        return _assessment(
            AdequacyVerdict.ADEQUATE,
            (f"{collision.colliding_groups} of {collision.groups} feature "
             f"signatures carry more than one outcome, covering "
             f"{collision.collision_rate:.2%} of the corpus. The current "
             f"representation is sufficient to express the observed outcome; "
             f"any remaining error belongs to the search, not to the grammar."),
            1.0 - collision.collision_rate)

    # ── 1. does the world repeat? ──
    if not probe.world_is_reproducible:
        eliminations.append(
            f"re-running the same trajectory disagreed with itself at rate "
            f"{probe.self_disagreement_rate:.4f}, above the "
            f"{MAX_REPRODUCIBLE_SELF_DISAGREEMENT} reproducibility margin")
        return _assessment(
            AdequacyVerdict.STOCHASTIC,
            (f"The outcome is not a function of the trajectory: re-running the "
             f"same trajectory returned a different result "
             f"{probe.self_disagreement_rate:.2%} of the time. Collisions here "
             f"say nothing about the representation, because NO representation "
             f"of the trajectory could predict this outcome. Extending the "
             f"grammar would fit sampling variation."),
            probe.self_disagreement_rate)
    eliminations.append(
        f"the world is reproducible: re-running the same trajectory agreed "
        f"with itself in {1 - probe.self_disagreement_rate:.2%} of "
        f"{probe.sampled} probes")

    # ── 2. is the record faithful? ──
    if not probe.record_is_faithful:
        eliminations.append(
            f"re-running disagreed with the RECORDED outcome at rate "
            f"{probe.record_disagreement_rate:.4f}, above the "
            f"{MAX_FAITHFUL_RECORD_DISAGREEMENT} fidelity margin")
        reason = (
            f"The recorded outcomes are wrong at about "
            f"{probe.record_disagreement_rate:.2%}, which is enough to "
            f"manufacture these collisions in a corpus the representation "
            f"could otherwise express. Extending the grammar here would fit "
            f"the label noise.")
        if residual["unexplained_by_noise"]:
            reason += (
                f" NOTE: the observed disagreement ({residual['minority_observed']}) "
                f"is {residual['ratio']}x what that noise rate predicts "
                f"({residual['minority_expected_under_noise']}), so a "
                f"representational gap may ALSO be present behind the noise.")
        return _assessment(AdequacyVerdict.NOISE_LIMITED, reason,
                           probe.record_disagreement_rate)
    eliminations.append(
        f"the record is faithful: re-running matched the recorded outcome in "
        f"{1 - probe.record_disagreement_rate:.2%} of {probe.sampled} probes")

    # ── 3. by elimination, the representation is the limit ──
    eliminations.append(
        f"{collision.minority_total} trajectories nevertheless sit in feature "
        f"signatures carrying more than one outcome")
    return _assessment(
        AdequacyVerdict.INADEQUATE,
        (f"The representation is the limiting factor. {collision.colliding_groups} "
         f"feature signatures carry more than one outcome, covering "
         f"{collision.collision_rate:.2%} of the corpus, with a mean minority "
         f"fraction of {collision.mean_minority_fraction:.2f} — far from the "
         f"thin minority that label noise produces. The world is reproducible "
         f"and the record is faithful, so the disagreement cannot be blamed on "
         f"either. No predicate over the current feature grammar can separate "
         f"these trajectories: its error is bounded below by "
         f"{collision.irreducible_error_rate:.2%} however the search is "
         f"improved. Something observable in the traces is not being read."),
        collision.collision_rate)
