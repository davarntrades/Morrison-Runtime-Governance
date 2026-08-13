"""The ontology the Living Boundary is testing, and the shape of a candidate.

`baseline.py`          what the CURRENT ontology can express and predict
`candidate_schema.py`  the machine-readable form of a proposed new primitive
`versions.py`          the version registry, read-only

Nothing here can modify Morrison's production policy. `versions.py` is a
read-only record of which ontology version an LB-0 run evaluated against; it
does not and cannot write to `morrison_governance`.
"""

from __future__ import annotations

from living_boundary.ontology.baseline import (
    BASELINE_ONTOLOGY, STRENGTHENED_ONTOLOGY, BaselineDecision,
    BaselineOntology, BaselinePrimitive,
)
from living_boundary.ontology.candidate_schema import (
    CandidatePrimitive, CandidateStatus, Literal, TERMINAL_LB0_STATUS,
)
from living_boundary.ontology.versions import (
    BASELINE_ONTOLOGY_VERSION, ontology_record,
)

__all__ = [
    "BASELINE_ONTOLOGY", "STRENGTHENED_ONTOLOGY", "BaselineDecision",
    "BaselineOntology", "BaselinePrimitive", "CandidatePrimitive",
    "CandidateStatus", "Literal", "TERMINAL_LB0_STATUS",
    "BASELINE_ONTOLOGY_VERSION", "ontology_record",
]
