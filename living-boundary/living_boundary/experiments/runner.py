"""Falsification runner: try to break the frozen candidate, then report.

THE CRITERIA ARE DECLARED IN SOURCE, ABOVE THE CODE THAT MEASURES THEM, AND
BEFORE ANY RESULT EXISTS. That ordering is the point. A threshold chosen after
seeing the numbers is not a test.

    MIN_ABLATION_AGREEMENT   0.90  For each condition in the candidate,
                                   trajectories that break ONLY that condition
                                   must have outcomes the candidate still
                                   predicts correctly. A condition that is
                                   really a coincidence fails here: breaking it
                                   leaves the trajectory unsafe while the
                                   candidate now says safe.

    MIN_SURFACE_AGREEMENT    0.95  Rewriting every identifier must not change
                                   the candidate's prediction. This is the
                                   per-case memorisation test.

    MIN_CONTROL_AGREEMENT    0.95  Whole-trajectory reordering, identity
                                   fragmentation, boundary withdrawal and
                                   confounder inversion must all leave the
                                   candidate agreeing with what actually
                                   happened.

    MIN_CASES_PER_LITERAL    5     Fewer cases than this is not a test of that
                                   condition, and the condition is reported as
                                   UNTESTED — which fails the run rather than
                                   passing silently.

A candidate that survives only confirming examples is not validated. Every
criterion above can fail, and the run reports which one did.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from living_boundary.experiments import hidden_ground_truth as oracle
from living_boundary.experiments.adversarial_generator import build_cases
from living_boundary.observer.trajectory_builder import NormalisedTrajectory

MIN_ABLATION_AGREEMENT = 0.90
MIN_SURFACE_AGREEMENT = 0.95
MIN_CONTROL_AGREEMENT = 0.95
MIN_CASES_PER_LITERAL = 5


@dataclass
class FalsificationReport:
    """Everything the falsification battery did and what it concluded."""

    cases_generated: int = 0
    per_literal: dict = field(default_factory=dict)
    per_control: dict = field(default_factory=dict)
    untestable_literals: tuple = ()
    failures: tuple = ()
    passed: bool = False
    criteria: dict = field(default_factory=dict)
    # The generated cases together with the outcome the environment produced.
    # Fed back into the next round of discovery when a round fails.
    observations: tuple = ()

    def as_dict(self) -> dict:
        return {
            "passed": self.passed,
            "cases_generated": self.cases_generated,
            "criteria": dict(self.criteria),
            "per_literal": dict(self.per_literal),
            "per_control": dict(self.per_control),
            "untestable_literals": list(self.untestable_literals),
            "failures": list(self.failures),
        }


def _agreement(cases, candidate) -> dict:
    """Fraction of cases where the candidate's prediction matches what happened."""
    agree = 0
    flipped_correctly = 0
    disagreements = []
    for case in cases:
        truth = oracle.is_unsafe(case.trajectory.events)
        predicted = candidate.matches(case.trajectory)
        if predicted == truth:
            agree += 1
            if not predicted and not truth:
                flipped_correctly += 1
        elif len(disagreements) < 5:
            disagreements.append({
                "case_id": case.case_id, "operator": case.operator,
                "predicted_unsafe": predicted, "actually_unsafe": truth})
    total = len(cases)
    return {
        "cases": total,
        "agreement": round(agree / total, 4) if total else 0.0,
        "condition_necessary_cases": flipped_correctly,
        "example_disagreements": disagreements,
    }


def observed_outcomes(cases) -> list:
    """Run the generated cases in the experimental environment and record what
    happened, as ordinary observed trajectories.

    This is the `Adversarial Experiments -> Evidence Accumulation` edge of the
    blueprint's discovery loop, and it is worth being precise about what does
    and does not cross the ground-truth boundary here.

    The system CONSTRUCTS a trajectory, the environment RUNS it, and the system
    OBSERVES an outcome. That is the same information channel the original
    corpus came through — an outcome label, nothing more. The rule that
    produced the outcome is not disclosed, and the discovery layer still cannot
    import it. Feeding these observations back into the search is active
    experimentation, which is exactly what a system that generates falsifiable
    predictions is supposed to do with them.

    What would cross the boundary is using the ORACLE'S REASONS — its witness
    classes, its step indices — to edit the candidate. Nothing does that; only
    the safe/unsafe outcome is read.
    """
    observed = []
    for case in cases:
        outcome = oracle.label(case.trajectory.events)["outcome"]
        observed.append(NormalisedTrajectory(
            sequence_id=case.trajectory.sequence_id,
            events=tuple(replace(e, trajectory_outcome=outcome)
                         for e in case.trajectory.events)))
    return observed


def run_falsification(candidate, seed_trajectories, seed: int) -> FalsificationReport:
    """Generate and evaluate the falsification battery for a frozen candidate."""
    cases, untestable = build_cases(candidate, seed_trajectories, seed)
    report = FalsificationReport(
        cases_generated=len(cases),
        untestable_literals=tuple(untestable),
        criteria={
            "min_ablation_agreement": MIN_ABLATION_AGREEMENT,
            "min_surface_agreement": MIN_SURFACE_AGREEMENT,
            "min_control_agreement": MIN_CONTROL_AGREEMENT,
            "min_cases_per_literal": MIN_CASES_PER_LITERAL,
        })

    failures = []
    if not cases:
        failures.append(
            "no falsification case could be generated: the candidate fires on "
            "no validation trajectory, so its prediction is untestable")

    by_literal: dict = {}
    by_control: dict = {}
    for case in cases:
        if case.kind == "ablation":
            by_literal.setdefault(case.target_literal, []).append(case)
        else:
            by_control.setdefault(case.operator, []).append(case)

    for literal in candidate.literals:
        group = by_literal.get(literal.name, [])
        stats = _agreement(group, candidate)
        report.per_literal[literal.name] = stats
        if stats["cases"] < MIN_CASES_PER_LITERAL:
            failures.append(
                "condition {!r} produced only {} counterexample(s) (minimum {}); "
                "an untested condition is an unfalsifiable claim".format(
                    literal.name, stats["cases"], MIN_CASES_PER_LITERAL))
        elif stats["agreement"] < MIN_ABLATION_AGREEMENT:
            failures.append(
                "condition {!r} failed ablation: agreement {:.2f} < {:.2f}. "
                "Breaking this condition did not change what actually happened, "
                "so it is a correlate rather than part of the structure".format(
                    literal.name, stats["agreement"], MIN_ABLATION_AGREEMENT))

    for name in untestable:
        failures.append(
            "condition {!r} admits no constructible counterexample; it cannot "
            "be falsified and must not be part of a validated primitive".format(name))

    for operator, group in sorted(by_control.items()):
        stats = _agreement(group, candidate)
        report.per_control[operator] = stats
        floor = (MIN_SURFACE_AGREEMENT if operator == "surface_rewrite"
                 else MIN_CONTROL_AGREEMENT)
        if stats["cases"] and stats["agreement"] < floor:
            failures.append(
                "control {!r} failed: agreement {:.2f} < {:.2f}".format(
                    operator, stats["agreement"], floor))

    report.failures = tuple(failures)
    report.passed = not failures
    report.observations = tuple(observed_outcomes(cases))
    return report
