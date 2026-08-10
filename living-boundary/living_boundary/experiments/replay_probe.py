"""The reproducibility probe — the active experiment LB-1 turns on.

WHY A PROBE IS NECESSARY

Feature-space collisions prove that the current representation cannot separate
two trajectories. They do NOT say why. Three different worlds produce them:

    a missing observable     the world is deterministic; the grammar is blind
    label noise              the world is deterministic; the RECORD is wrong
    real stochasticity       the world itself is not deterministic

No amount of staring at the corpus separates those, because in the corpus they
look identical: same features, different labels. The only thing that separates
them is RUNNING A TRAJECTORY AGAIN, which is an experiment rather than an
analysis, and which is exactly what the blueprint's discovery loop is for.

    re-run agrees with the record?   re-run twice agrees with itself?
    ─────────────────────────────────────────────────────────────────
    yes                              yes        deterministic + faithful record
    no                               yes        the record is wrong  (noise)
    no                               no         the world is stochastic

WHAT CROSSES THE BOUNDARY

Outcomes, and nothing else. The probe never reads the environment's rule, its
`extra_condition`, its noise rate or its determinism flag — those exist on the
`Environment` object for the harness's report only, and
`tests/test_lb1_isolation.py` asserts no analysis module can reach them. What
the probe returns is a pair of rates.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class ProbeResult:
    """What repeated execution revealed. Rates only — no rule, no reason."""

    sampled: int = 0
    record_disagreements: int = 0
    self_disagreements: int = 0
    per_case: list = field(default_factory=list)

    @property
    def record_disagreement_rate(self) -> float:
        return self.record_disagreements / self.sampled if self.sampled else 0.0

    @property
    def self_disagreement_rate(self) -> float:
        return self.self_disagreements / self.sampled if self.sampled else 0.0

    @property
    def world_is_reproducible(self) -> bool:
        """Does running the same trajectory twice give the same answer?

        The threshold is not 0 because a stochastic world can agree with itself
        by chance on a finite sample; it is low because a deterministic world
        agrees with itself ALWAYS, so any material self-disagreement is real.
        """
        return self.self_disagreement_rate <= 0.02

    @property
    def record_is_faithful(self) -> bool:
        return self.record_disagreement_rate <= 0.02

    def as_dict(self) -> dict:
        return {
            "sampled": self.sampled,
            "record_disagreements": self.record_disagreements,
            "record_disagreement_rate": round(self.record_disagreement_rate, 4),
            "self_disagreements": self.self_disagreements,
            "self_disagreement_rate": round(self.self_disagreement_rate, 4),
            "world_is_reproducible": self.world_is_reproducible,
            "record_is_faithful": self.record_is_faithful,
            "examples": list(self.per_case[:5]),
        }


def run_probe(trajectories, environment, seed: int, sample: int = 240,
              repeats: int = 2) -> ProbeResult:
    """Re-run a sample of trajectories and compare against the record.

    Sampling is deterministic and stratified by stride rather than by random
    choice, so the probe covers the corpus evenly and reproduces exactly.
    """
    result = ProbeResult()
    if not trajectories:
        return result

    rng = random.Random(seed * 90113 + 17)
    stride = max(1, len(trajectories) // sample)
    chosen = trajectories[::stride][:sample]

    for trajectory in chosen:
        recorded = trajectory.outcome
        observations = [environment.observe(trajectory, rng)
                        for _ in range(max(2, repeats))]
        result.sampled += 1
        disagrees_with_record = observations[0] != recorded
        disagrees_with_self = len(set(observations)) > 1
        if disagrees_with_record:
            result.record_disagreements += 1
        if disagrees_with_self:
            result.self_disagreements += 1
        if (disagrees_with_record or disagrees_with_self) \
                and len(result.per_case) < 25:
            result.per_case.append({
                "sequence_id": trajectory.sequence_id,
                "recorded": recorded,
                "observations": observations,
            })
    return result
