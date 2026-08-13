"""Shadow synthesis: perturb the RECORD, never the world.

LB-1's falsification battery built a perturbed trajectory and asked the
environment what happened to it. LB-2 may not: the environment is gone, and
re-running a payment or an already-sent email to test a hypothesis is precisely
the thing the safety invariant forbids.

So shadow replay here is strictly weaker, and the weakness must be stated
plainly rather than buried in the method name:

    LB-1 shadow replay   perturb the trajectory, EXECUTE it, observe an outcome
    LB-2 shadow replay   perturb the RECORD, evaluate the HYPOTHESIS on it,
                         observe nothing

What LB-2's version can establish is INTERNAL CONSISTENCY — that the candidate
predicate actually responds to the observable it claims to depend on, and is not
quietly keyed to something that travels with it. What it cannot establish is
whether the world would have behaved differently, and no amount of synthesis
will change that. Truth about outcomes comes only from the observed
counterparts in `cohorts.py`, which are real events that really happened.

A synthesiser exists only for observables that can be perturbed coherently in a
record. Where none exists, the result says `synthesisable: false` rather than
skipping the check silently — an untested claim should look untested.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from living_boundary.observer.trajectory_builder import NormalisedTrajectory


def _rewrite(trajectory, mutate):
    events = tuple(mutate(index, event)
                   for index, event in enumerate(trajectory.events))
    return NormalisedTrajectory(
        sequence_id=trajectory.sequence_id + "-shadow", events=events)


def _shift_timestamps(trajectory, factor: int, offset: int):
    """Compress or stretch the session. Structure, identities and resources are
    untouched, so only the timing observable moves."""
    base = trajectory.events[0].timestamp if trajectory.events else ""
    if not base:
        return None

    def mutate(index, event):
        if index == 0:
            return event
        # Rewriting the seconds field is enough to move a session between the
        # burst and slow regimes without inventing a new calendar.
        seconds = (index * factor + offset) % 60
        minutes = (index * factor + offset) // 60 % 60
        stamp = f"{event.timestamp[:14]}{minutes:02d}:{seconds:02d}Z"
        return replace(event, timestamp=stamp)
    return _rewrite(trajectory, mutate)


def _reassign_actors(trajectory, delegate: bool):
    """Make the acting agent diverge from, or match, the authorising identity."""
    def mutate(_index, event):
        actor = (f"agent_shadow_{event.step_index}" if delegate
                 else f"agent_{event.identity_id}")
        return replace(event, actor_id=actor)
    return _rewrite(trajectory, mutate)


SYNTHESISERS = {
    "timestamp": lambda t, exposed: (
        _shift_timestamps(t, 400, 90) if exposed else _shift_timestamps(t, 3, 1)),
    "actor_id": lambda t, exposed: _reassign_actors(t, not exposed),
}


@dataclass
class ShadowResult:
    """Whether the hypothesis responds to the observable it names."""

    exposure: str
    observable: str
    synthesisable: bool = False
    cases: int = 0
    prediction_flipped: int = 0
    exposure_flipped: int = 0
    notes: str = ""
    examples: list = field(default_factory=list)

    @property
    def flip_rate(self) -> float:
        return self.prediction_flipped / self.cases if self.cases else 0.0

    @property
    def consistent(self) -> bool:
        """The hypothesis must stop firing when the observable it names moves.

        A candidate that keeps its answer after the observable it claims to
        depend on has been perturbed is keyed to something else, and the
        localisation naming that observable is wrong.

        The 0.8 floor rather than 1.0 leaves room for perturbations that land a
        trajectory somewhere the hypothesis still fires for an unrelated reason
        — a real effect on a conjunction with several clauses, and not evidence
        against the observable.
        """
        return self.synthesisable and self.cases > 0 and self.flip_rate >= 0.8

    def as_dict(self) -> dict:
        return {
            "exposure": self.exposure, "observable": self.observable,
            "synthesisable": self.synthesisable, "cases": self.cases,
            "exposure_flipped": self.exposure_flipped,
            "prediction_flipped": self.prediction_flipped,
            "flip_rate": round(self.flip_rate, 4),
            "consistent": self.consistent,
            "notes": self.notes,
            "examples": list(self.examples[:3]),
            "executed_anything": False,
        }


def shadow_consistency(trajectories, name: str, family, predicate,
                       limit: int = 60) -> ShadowResult:
    """Perturb the named observable in the record and watch the hypothesis.

    `predicate` maps a trajectory to the candidate's prediction. Nothing is
    executed; `executed_anything` is reported as False in the artifact so the
    record itself says what was and was not done.
    """
    result = ShadowResult(exposure=name, observable=family.observable)
    synthesiser = SYNTHESISERS.get(family.observable)
    if synthesiser is None:
        result.notes = (
            f"no coherent record-level perturbation exists for "
            f"{family.observable!r}; the candidate's dependence on it is "
            f"UNTESTED by shadow synthesis and rests on matched cohorts alone")
        return result

    result.synthesisable = True
    for trajectory in trajectories:
        if result.cases >= limit:
            break

        # ONLY trajectories the hypothesis currently fires on.
        #
        # An earlier version perturbed everything and measured how often the
        # prediction changed. That is the wrong denominator and it produced a
        # flip rate of 0.38 on a candidate that was entirely correct: most of
        # the archive is trajectories the hypothesis was never going to fire on
        # for reasons that have nothing to do with the observable under test —
        # a reordered chain stays safe whether it took nine seconds or an hour.
        # Counting those as failures to respond measures the base rate, not the
        # dependence.
        #
        # The question worth asking is narrower: where the hypothesis DOES
        # fire, does moving the observable it names stop it?
        if not predicate(trajectory):
            continue

        exposed = name in family.features(trajectory)
        shadow = synthesiser(trajectory, exposed)
        if shadow is None:
            continue
        now_exposed = name in family.features(shadow)
        if now_exposed == exposed:
            # The perturbation did not move the observable, so this case tests
            # nothing. Counted nowhere rather than counted as a pass.
            continue
        result.cases += 1
        result.exposure_flipped += 1
        if not predicate(shadow):
            result.prediction_flipped += 1
        elif len(result.examples) < 5:
            result.examples.append({
                "sequence_id": trajectory.sequence_id,
                "exposure_before": exposed, "exposure_after": now_exposed,
                "still_firing_after_perturbation": True})

    if result.cases == 0:
        result.notes = ("no case could be constructed in which the observable "
                        "actually moved; treated as untested")
    return result
