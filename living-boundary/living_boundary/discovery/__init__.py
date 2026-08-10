"""Discovery: gap detection, structure search, candidate generation.

NOTHING IN THIS PACKAGE KNOWS THE HIDDEN RULE.

Every module here is written against the trace vocabulary alone. The feature
grammar in `features.py` is instantiated from whatever tokens the observed
traces happen to contain — it has no hand-written feature for the structure
under test, and it would generate exactly the same families for a corpus about
a completely different failure mode.

`tests/test_ground_truth_isolation.py` enforces this by AST analysis: no module
under this package may import `experiments.hidden_ground_truth`, directly or
transitively.
"""

from __future__ import annotations

from living_boundary.discovery.features import (
    FEATURE_FAMILIES, build_literals, feature_set, predicate_for,
)
from living_boundary.discovery.gap_detector import OntologyGap, detect_gap
from living_boundary.discovery.primitive_generator import generate_candidate
from living_boundary.discovery.structure_discovery import (
    DiscoveredStructure, search_structures,
)

__all__ = [
    "FEATURE_FAMILIES", "build_literals", "feature_set", "predicate_for",
    "OntologyGap", "detect_gap", "generate_candidate", "DiscoveredStructure",
    "search_structures",
]
