"""Three representations of the same trajectory, and what each one can survive.

LB-3 does not test "the" representation. It tests three, arranged as a ladder of
increasing abstraction, because the interesting result is not whether transfer
happens but WHICH LEVEL OF ABSTRACTION IS THE ONE THAT TRANSFERS.

    surface      the LB-0 feature grammar, unchanged. Atoms are spelled with
                 capability, domain, boundary, permission scope, provider,
                 region and session tag. Reused, not reimplemented — this is
                 literally the representation LB-0 discovered in.

    typed        the same grammar with the four vocabulary-bound families
                 removed (`scope`, `provider`, `region`, `session_tag`). Atoms
                 are capability@domain@boundary triples: ontology labels, not
                 tool names. Survives a tool rename, and should not survive a
                 change of capability taxonomy.

    relational   atoms are INDUCED ROLE @ boundary class, where the role comes
                 from `roles.py` and is derived per environment from unlabelled
                 structure. Contains no vocabulary at all.

A prediction, recorded before the run: `surface` cannot transfer anywhere,
because a literal whose referent does not exist in the target environment never
fires; `typed` transfers exactly as far as the ontology labels do; `relational`
transfers as far as the role alignment holds and no further. LB-3 exists to find
out where that "no further" actually falls.

WHY THE RELATIONAL FAMILIES ARE WHAT THEY ARE

They are the relations the LB-0 grammar already had — occurrence, ordering,
identity continuity, subject continuity, length — restated over roles instead of
tokens, plus one that LB-0 lacked and LB-1 showed was needed: a triple that
carries identity continuity AND subject continuity at once. Nothing here is
shaped around a particular hazard; the same families would be instantiated over
any corpus.
"""

from __future__ import annotations

from living_boundary.discovery.features import feature_set
from living_boundary.observer.normalizer import BOUNDARY_INTERNAL

SEP = "::"
ARG = "|"

# Families of the LB-0 grammar that name environment-local vocabulary rather
# than governance structure. `typed` drops these and keeps the rest.
VOCABULARY_BOUND_FAMILIES = frozenset({
    "scope", "provider", "region", "session_tag",
})

RELATIONAL_FAMILIES = (
    "rr_has", "rr_ord2", "rr_ord3", "rr_ord3i", "rr_ord3is",
    "rr_same_ident", "rr_subj", "rr_single_identity", "rr_steps_ge",
)

_MAX_STEPS_FEATURE = 8


# ═══════════════════════════════════════════════════════════════════════
# surface  /  typed
# ═══════════════════════════════════════════════════════════════════════

def surface_features(trajectory) -> set:
    """The LB-0 grammar, unmodified."""
    return feature_set(trajectory)


def typed_features(trajectory) -> set:
    """The LB-0 grammar minus every family that names local vocabulary."""
    return {name for name in feature_set(trajectory)
            if name.partition(SEP)[0] not in VOCABULARY_BOUND_FAMILIES}


# ═══════════════════════════════════════════════════════════════════════
# relational
# ═══════════════════════════════════════════════════════════════════════

def _atoms(trajectory, role_model):
    """`role@boundary_class` for each step, in order.

    The boundary class rides along inside the atom rather than sitting in its
    own family, so an ordering literal can require "…and the last of the three
    left the perimeter" without a family invented for that purpose.
    """
    out = []
    for event in trajectory.events:
        boundary = ("internal" if event.trust_boundary == BOUNDARY_INTERNAL
                    else "crossing")
        out.append(f"{role_model.role_of(event)}@{boundary}")
    return out


def relational_features(trajectory, role_model) -> set:
    """Occurrence, order, identity continuity and subject continuity over roles."""
    events = trajectory.events
    atoms = _atoms(trajectory, role_model)
    names = set()
    for atom in atoms:
        names.add(f"rr_has{SEP}{atom}")

    count = len(events)
    for i in range(count):
        for j in range(i + 1, count):
            left, right = atoms[i], atoms[j]
            names.add(f"rr_ord2{SEP}{left}{ARG}{right}")
            same_identity = events[i].identity_id == events[j].identity_id
            if same_identity:
                names.add(f"rr_same_ident{SEP}{left}{ARG}{right}")
            if events[i].subject and events[i].subject == events[j].subject:
                names.add(f"rr_subj{SEP}{left}{ARG}{right}")
            for k in range(j + 1, count):
                third = atoms[k]
                names.add(f"rr_ord3{SEP}{left}{ARG}{right}{ARG}{third}")
                one_identity = (same_identity
                                and events[j].identity_id == events[k].identity_id)
                if one_identity:
                    names.add(f"rr_ord3i{SEP}{left}{ARG}{right}{ARG}{third}")
                    if (events[i].subject
                            and events[i].subject == events[k].subject):
                        names.add(f"rr_ord3is{SEP}{left}{ARG}{right}{ARG}{third}")

    if len({e.identity_id for e in events}) == 1:
        names.add(f"rr_single_identity{SEP}")
    for k in range(2, _MAX_STEPS_FEATURE):
        if count >= k:
            names.add(f"rr_steps_ge{SEP}{k!s}")
    return names


def relational_feature_fn(role_model):
    """Bind a role model to produce a one-argument feature function.

    The role model is the ONLY thing that differs between environments. A
    candidate is a set of literal names over roles; evaluating it somewhere else
    means swapping the role model and changing nothing about the candidate,
    which is what makes "the candidate was not tuned on the target" a
    structural fact rather than a promise.
    """
    def _features(trajectory):
        return relational_features(trajectory, role_model)
    return _features


# ═══════════════════════════════════════════════════════════════════════
# registry
# ═══════════════════════════════════════════════════════════════════════

GRAMMARS = ("surface", "typed", "relational")


def grammar_fn(name: str, role_model=None):
    if name == "surface":
        return surface_features
    if name == "typed":
        return typed_features
    if name == "relational":
        if role_model is None:
            raise ValueError("the relational grammar needs a role model")
        return relational_feature_fn(role_model)
    raise ValueError(f"unknown grammar {name!r}")


def grammar_version(name: str) -> str:
    """Version string recorded in provenance beside every candidate."""
    return {
        "surface": "lb0-feature-grammar-1.1",
        "typed": "lb3-typed-grammar-1.0",
        "relational": "lb3-relational-grammar-1.0",
    }[name]
