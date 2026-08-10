"""Turn a discovered structure into a falsifiable candidate primitive.

The hypothesis and the prediction are GENERATED FROM THE LITERALS, mechanically.
No wording is authored for this particular result, and nothing in the sentence
is decorative: every clause corresponds to a literal that can be ablated, and
the falsification runner ablates each of them in turn.

This matters because of the blueprint's sixth invariant — explanatory elegance
is not evidence. A description written by hand (or by a model) after the fact
can be made to sound inevitable for any structure at all. A description
generated from the predicate can only say what the predicate does.
"""

from __future__ import annotations

from living_boundary.discovery.features import (
    SURFACE_FAMILIES, literal_from_name,
)
from living_boundary.ontology.candidate_schema import (
    CandidatePrimitive, CandidateStatus,
)

# Which observable each feature family reads. Reported as the candidate's
# `observed_variables`, so a reviewer can see what the primitive depends on
# without reading the literal grammar.
_FAMILY_VARIABLES = {
    "has_token": ("capability", "domain", "trust_boundary"),
    "has_cap": ("capability",),
    "has_domain": ("domain",),
    "has_boundary": ("trust_boundary",),
    "scope": ("permission_scope",),
    "order2": ("action_sequence", "capability", "domain"),
    "order3": ("action_sequence", "capability", "domain", "trust_boundary"),
    "order3_identity": ("action_sequence", "capability", "domain",
                        "trust_boundary", "identity_id"),
    "same_identity": ("identity_id", "action_sequence"),
    "subject_link": ("resource", "action_sequence"),
    "single_identity": ("identity_id",),
    "transition": ("trust_boundary",),
    "crosses_boundary": ("trust_boundary",),
    "steps_ge": ("trajectory_length",),
    "provider": ("provider",),
    "region": ("region",),
    "session_tag": ("session_tag",),
}


def _variables(literal_names) -> tuple:
    out: set = set()
    for name in literal_names:
        family = name.replace("NOT ", "").partition("::")[0]
        out.update(_FAMILY_VARIABLES.get(family, (family,)))
    return tuple(sorted(out))


def _slug(literal_names) -> str:
    """A short, stable, mechanically-derived name for the primitive.

    Built from the families present, not from what the structure "means". A
    primitive called `cross_domain_authority_accumulation` sounds like an
    insight; one called `composition.order3+same_identity+scope` states what it
    reads. The blueprint is explicit that terminology stays provisional until
    the evidence is in.
    """
    families = []
    for name in literal_names:
        family = name.replace("NOT ", "").partition("::")[0]
        if family not in families:
            families.append(family)
    return f"composition.{'+'.join(sorted(families))}"


def _hypothesis(literals) -> str:
    clauses = [lit.description for lit in literals]
    return ("Unsafe outcomes concentrate in trajectories where all of the "
            "following hold simultaneously: " + "; ".join(clauses) + ".")


def _prediction(literals) -> str:
    return (
        "PREDICTION (falsifiable): a trajectory satisfying all {n} conditions "
        "will end unsafe, and a trajectory that satisfies all of them except "
        "one will not. Removing any single condition must therefore change the "
        "outcome; if the outcome is unchanged when a condition is removed, that "
        "condition is not part of the governing structure and this candidate is "
        "wrong. The conditions are: {clauses}.".format(
            n=len(literals),
            clauses="; ".join(f"({i + 1}) {lit.description}"
                              for i, lit in enumerate(literals))))


def generate_candidate(structure, fit_trajectories, fit_labels,
                       candidate_id: str = "CP-LB0-001",
                       ontology_version: str = "") -> CandidatePrimitive:
    """Build the machine-readable candidate from a discovered structure.

    `source_evidence` is the list of sequence ids the structure actually fires
    on among the fitted positives — real provenance back to source traces, not a
    restatement of the corpus.
    """
    literals = tuple(literal_from_name(name) for name in structure.literal_names)

    supporting = []
    for trajectory, is_positive in zip(fit_trajectories, fit_labels):
        if is_positive and all(lit.evaluate(trajectory) for lit in literals):
            supporting.append(trajectory.sequence_id)

    surface = tuple(sorted(
        name for name in structure.literal_names
        if name.replace("NOT ", "").partition("::")[0] in SURFACE_FAMILIES))

    description = (
        "A trajectory-level structure, discovered from observed traces, in "
        "which individually permitted actions combine into an unsafe outcome. "
        "The structure is stated as a conjunction of {} conditions over "
        "observable trace fields ({}). EXPERIMENTAL: it is not a governance "
        "policy, carries no enforcement authority, and is not a member of any "
        "ontology version.".format(
            len(literals), ", ".join(_variables(structure.literal_names))))
    if surface:
        description += (
            " WARNING: {} of its conditions read session metadata rather than "
            "governed structure ({}), which is a signal that the search may "
            "have fitted a correlate.".format(len(surface), ", ".join(surface)))

    candidate = CandidatePrimitive(
        candidate_id=candidate_id,
        name=_slug(structure.literal_names),
        description=description,
        literals=literals,
        observed_variables=_variables(structure.literal_names),
        hypothesis=_hypothesis(literals),
        falsifiable_prediction=_prediction(literals),
        source_evidence=tuple(supporting),
        supporting_traces=len(supporting),
        discovery_metrics={
            "fit_f1": round(structure.fit_f1, 4),
            "fit_precision": round(structure.fit_precision, 4),
            "fit_recall": round(structure.fit_recall, 4),
            "fit_support": structure.fit_support,
            "uses_surface_features": bool(surface),
            "surface_literals": list(surface),
        },
        validation_metrics=dict(structure.selection_metrics),
        ontology_version_observed=ontology_version)
    candidate.advance(CandidateStatus.HYPOTHESISED)
    return candidate
