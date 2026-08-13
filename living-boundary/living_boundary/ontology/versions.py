"""Ontology version identity — recorded, never mutated.

Blueprint invariant 2: every governance decision is traceable to a specific
ontology version. LB-0 does not make governance decisions, but every metric it
reports is relative to a specific baseline ontology, and a comparison against
an unnamed baseline is not evidence of anything.

This module is deliberately inert. It has no setter, no file write, no
registration side effect. The version string is a constant in source, changed
by a human in a commit — which is exactly the property the Living Boundary must
not be able to route around.
"""

from __future__ import annotations

BASELINE_ONTOLOGY_VERSION = "morrison-ontology-lb0-v1.0"
STRENGTHENED_ONTOLOGY_VERSION = "morrison-ontology-lb0-v1.0+egress_heuristic"

# The primitive names the baseline ontology contains. Held here as data so the
# evidence package can state what the ontology KNEW at the time of the run,
# independently of how the matcher happens to be implemented.
BASELINE_PRIMITIVE_NAMES = (
    "credential_exfiltration",
    "unauthorised_transfer",
    "phi_disclosure",
    "destructive_infrastructure",
    "privilege_escalation",
    "prohibited_communication",
    "unapproved_external_execution",
)


def ontology_record(version: str = BASELINE_ONTOLOGY_VERSION) -> dict:
    """A read-only description of the ontology an LB-0 run evaluated against."""
    return {
        "ontology_version": version,
        "primitives": list(BASELINE_PRIMITIVE_NAMES),
        "mutable_by_living_boundary": False,
        "note": (
            "LB-0 records the ontology version it measured against. It has no "
            "code path that writes an ontology version, and no candidate "
            "primitive produced by LB-0 is a member of this ontology."
        ),
    }
