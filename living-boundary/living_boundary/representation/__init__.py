"""Second-order analysis: is the DISCOVERY LAYER'S OWN representation adequate?

LB-0 asked whether Morrison's Ω was missing a concept, and answered it with a
collision argument: two trajectories indistinguishable in the ontology's
vocabulary but different in outcome prove that no refinement of that vocabulary
can separate them.

LB-1 turns the same argument on the discovery layer itself. The feature grammar
in `discovery/features.py` IS a representation, and LB-0's own documented
weakness was that "a structure outside the grammar is undiscoverable, silently".
This package is the attempt to make it not silent.

    collisions.py   trajectories with identical FEATURE SETS and different
                    outcomes — a proof that no predicate over the current
                    grammar can ever separate them
    adequacy.py     the verdict, which needs more than collisions: a missing
                    concept, a wrong record and a stochastic world all produce
                    collisions and only an experiment tells them apart
    extensions.py   a generic pool of candidate observables, used to LOCALISE
                    an inadequacy once one has been established
    refit.py        a compact conjunction search, used to demonstrate that the
                    localisation was right
    proposal.py     the output: an experimental representation-extension
                    proposal, carrying no authority

NOTHING HERE MAY REACH THE ENVIRONMENT'S RULE. The analysis layer receives
trace features, recorded outcomes, and the two rates the reproducibility probe
reports. `tests/test_lb1_isolation.py` proves that by AST analysis, exactly as
LB-0 does for its own discovery layer.
"""

from __future__ import annotations

from living_boundary.representation.adequacy import (
    AdequacyVerdict, RepresentationAssessment, assess_representation,
)
from living_boundary.representation.collisions import (
    CollisionGroup, CollisionReport, find_collisions,
)
from living_boundary.representation.extensions import (
    EXTENSION_POOL, ExtensionFamily, localise_inadequacy,
)
from living_boundary.representation.proposal import RepresentationProposal

__all__ = [
    "AdequacyVerdict", "RepresentationAssessment", "assess_representation",
    "CollisionGroup", "CollisionReport", "find_collisions",
    "EXTENSION_POOL", "ExtensionFamily", "localise_inadequacy",
    "RepresentationProposal",
]
