"""A candidate that cannot be changed after it leaves the discovery environment.

THE FAILURE THIS PREVENTS

Cross-environment evaluation has one classic way of being worthless: the
candidate, the threshold, or the scoring rule gets nudged after somebody looks
at a transfer number. It rarely happens as a deliberate act — it happens as
"the beam was a bit narrow", "that threshold was arbitrary anyway", "let me just
re-fit with the target vocabulary included". Each of those is defensible on its
own and together they turn a transfer test into a fitting exercise.

So the candidate is sealed. `FrozenCandidate` is immutable, carries a hash over
its own definition AND over the thresholds and scoring rule in force when it was
sealed, and re-verifies that hash on every evaluation. Any drift raises
`FrozenCandidateError` rather than producing a slightly better number.

WHAT IS SEALED

The literal set, the grammar name, the grammar version, the acceptance
thresholds, the scoring rule identifier, the discovery environment id and the
discovery-side metrics. Everything downstream — every transfer environment,
every invariance transform, every falsification case — reads this object and
writes nothing back to it.

The role model is deliberately NOT sealed, because it is the one thing that must
be re-derived per environment; a candidate over roles is meaningless without one.
That is the seam through which environment information legitimately enters, and
it is why `roles.py` never sees a label.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace


class FrozenCandidateError(RuntimeError):
    """Raised when a sealed candidate is mutated, or its seal fails to verify."""


@dataclass(frozen=True)
class FrozenCandidate:
    """A candidate structure, sealed against the transfer evaluation."""

    candidate_id: str
    grammar: str
    grammar_version: str
    literals: tuple
    discovery_env: str
    thresholds: dict = field(default_factory=dict)
    scoring_rule: str = ""
    discovery_metrics: dict = field(default_factory=dict)
    seal: str = ""

    # ── prediction ───────────────────────────────────────────
    def predict(self, names) -> bool:
        """The candidate's prediction over a feature-name set.

        A conjunction, with `NOT ` prefixes read as negation. Total over any
        feature set: a literal whose referent is absent simply fails, which is
        exactly what should happen to a vocabulary-bound literal in a foreign
        environment.
        """
        if not self.literals:
            return False
        for literal in self.literals:
            if literal.startswith("NOT "):
                if literal[4:] in names:
                    return False
            elif literal not in names:
                return False
        return True

    def predict_all(self, trajectories, feature_fn) -> list:
        return [self.predict(feature_fn(t)) for t in trajectories]

    # ── sealing ──────────────────────────────────────────────
    @property
    def structure_hash(self) -> str:
        payload = json.dumps(sorted(self.literals), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def compute_seal(self) -> str:
        payload = json.dumps({
            "grammar": self.grammar,
            "grammar_version": self.grammar_version,
            "literals": sorted(self.literals),
            "discovery_env": self.discovery_env,
            "thresholds": self.thresholds,
            "scoring_rule": self.scoring_rule,
        }, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def verify(self) -> None:
        """Re-derive the seal. Called before every transfer evaluation."""
        if self.seal and self.compute_seal() != self.seal:
            raise FrozenCandidateError(
                f"candidate {self.candidate_id} was altered after it was "
                f"frozen; its transfer results would measure the alteration, "
                f"not the transfer")

    def as_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "grammar": self.grammar,
            "grammar_version": self.grammar_version,
            "literals": list(self.literals),
            "literal_count": len(self.literals),
            "structure_hash": self.structure_hash,
            "discovery_environment": self.discovery_env,
            "thresholds": dict(self.thresholds),
            "scoring_rule": self.scoring_rule,
            "discovery_metrics": dict(self.discovery_metrics),
            "seal": self.seal,
            "production_authority": "none",
        }


def freeze(candidate_id: str, grammar: str, grammar_version: str, literals,
           discovery_env: str, thresholds: dict, scoring_rule: str,
           discovery_metrics: dict) -> FrozenCandidate:
    """Seal a candidate. Nothing downstream may construct one another way."""
    unsealed = FrozenCandidate(
        candidate_id=candidate_id, grammar=grammar,
        grammar_version=grammar_version, literals=tuple(sorted(literals)),
        discovery_env=discovery_env, thresholds=dict(thresholds),
        scoring_rule=scoring_rule, discovery_metrics=dict(discovery_metrics))
    return replace(unsealed, seal=unsealed.compute_seal())
