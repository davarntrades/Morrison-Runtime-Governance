"""Transformations that should not change a structural claim, and ones that must.

WHAT IS MEASURED, AND WHY IT IS NOT ACCURACY

These transformations are applied by the analysis layer, which has no oracle. It
cannot re-label a transformed trajectory, so it cannot measure accuracy on one.
What it CAN measure is the candidate's own behaviour:

    semantics-preserving   AGREEMENT — does the candidate make the same call on
                           the trajectory and on its transform?
    destructive            EXTINCTION — of the trajectories the candidate fired
                           on, how many does it stop firing on once the relation
                           it claims to depend on has been broken?

A candidate that survives the first set and ignores the second has learned
something that travels; a candidate that survives BOTH has learned something
that is not about the structure at all, and the second set is the one that
catches it. Both numbers are reported for every grammar, so "the candidate is
invariant" is never asserted without "and here is what makes it stop".

WHY THE ROLE MODEL IS RE-INDUCED AFTER A TRANSFORM

A transform that renames tools produces, as far as the relational grammar is
concerned, a new environment — and the honest thing is to treat it as one:
re-induce roles from the transformed corpus, re-align to the discovery role
model, and evaluate the untouched candidate through the new mapping. Anything
else would let the analysis keep a mapping it should have had to re-earn.
"""

from __future__ import annotations

import zlib
from dataclasses import replace

from living_boundary.observer.normalizer import BOUNDARY_INTERNAL
from living_boundary.observer.trajectory_builder import NormalisedTrajectory


def _stable(text: str, modulus: int) -> int:
    """A deterministic surrogate for `hash`.

    `hash` over strings is salted per process, so a transform built on it would
    make the run irreproducible — which is the one property every phase of this
    experiment has been built to keep.
    """
    return zlib.crc32(text.encode("utf-8")) % modulus


def _rebuild(trajectory, events):
    return NormalisedTrajectory(sequence_id=trajectory.sequence_id,
                                events=tuple(events))


# ═══════════════════════════════════════════════════════════════════════
# Semantics-preserving
# ═══════════════════════════════════════════════════════════════════════

def alpha_rename_identities(trajectory):
    """Rename identities by order of first appearance. Relations untouched."""
    mapping = {}
    for event in trajectory.events:
        mapping.setdefault(event.identity_id, f"anon_id_{len(mapping):03d}")
    return _rebuild(trajectory, [
        replace(e, identity_id=mapping[e.identity_id],
                actor_id=mapping.get(e.actor_id, e.actor_id))
        for e in trajectory.events])


def rename_tools(trajectory):
    """Rewrite every action name. The step type inventory is preserved."""
    return _rebuild(trajectory, [
        replace(e, action=f"tool_{_stable(e.action, 9973):04d}")
        for e in trajectory.events])


def substitute_provider(trajectory):
    return _rebuild(trajectory, [
        replace(e, provider="substituted-provider", region="substituted-region",
                session_tag="substituted-tag")
        for e in trajectory.events])


def translate_timestamps(trajectory):
    """Move the whole session forward. Intervals and order are preserved."""
    return _rebuild(trajectory, [
        replace(e, timestamp=("2031" + e.timestamp[4:]) if e.timestamp else "")
        for e in trajectory.events])


def substitute_vocabulary(trajectory):
    """Rewrite capability and domain labels, keeping the boundary structure."""
    return _rebuild(trajectory, [
        replace(e, capability=f"cap_{_stable(e.capability, 997):03d}",
                domain=f"dom_{_stable(e.domain, 997):03d}",
                permission_scope=tuple(
                    f"scope_{_stable(s, 997):03d}" for s in e.permission_scope))
        for e in trajectory.events])


def perturb_irrelevant_fields(trajectory):
    """Rewrite the free-form provenance dict, which no grammar reads."""
    return _rebuild(trajectory, [
        replace(e, provenance=dict(e.provenance, perturbed="yes",
                                   batch_hint="rewritten"))
        for e in trajectory.events])


def _fresh_internal_step(trajectory, index: int, suffix: str):
    """A step that cannot participate in any relation: new identity, new
    subject, inside the perimeter."""
    template = trajectory.events[0]
    return replace(
        template, step_index=index,
        trace_id=f"{template.trace_id}-{suffix}",
        identity_id=f"filler_identity_{suffix}",
        actor_id=f"filler_identity_{suffix}",
        resource=f"filler/filler_subject_{suffix}",
        trust_boundary=BOUNDARY_INTERNAL)


def insert_irrelevant_event(trajectory):
    """Insert a step whose identity and subject occur nowhere else."""
    events = list(trajectory.events)
    position = len(events) // 2
    events.insert(position, _fresh_internal_step(trajectory, position, "ins"))
    return _rebuild(trajectory, [replace(e, step_index=i)
                                 for i, e in enumerate(events)])


def pad_trace(trajectory):
    """Append two unrelated steps after everything that mattered."""
    events = list(trajectory.events)
    events.append(_fresh_internal_step(trajectory, len(events), "pad1"))
    events.append(_fresh_internal_step(trajectory, len(events) + 1, "pad2"))
    return _rebuild(trajectory, [replace(e, step_index=i)
                                 for i, e in enumerate(events)])


def reorder_independent_steps(trajectory):
    """Swap the first adjacent pair sharing neither identity nor subject.

    That pair is independent under any relation expressible in these grammars —
    ordering literals over them are the only thing that can move, and a
    candidate resting on the order of two unrelated steps has not found the
    partial order that matters.
    """
    events = list(trajectory.events)
    for index in range(len(events) - 1):
        left, right = events[index], events[index + 1]
        if left.identity_id == right.identity_id:
            continue
        if left.subject and left.subject == right.subject:
            continue
        if left.trust_boundary != right.trust_boundary:
            continue
        events[index], events[index + 1] = right, left
        break
    return _rebuild(trajectory, [replace(e, step_index=i)
                                 for i, e in enumerate(events)])


# ═══════════════════════════════════════════════════════════════════════
# Destructive
# ═══════════════════════════════════════════════════════════════════════

def reverse_order(trajectory):
    return _rebuild(trajectory, [
        replace(e, step_index=i)
        for i, e in enumerate(reversed(trajectory.events))])


def fragment_identities(trajectory):
    """Give every step its own identity. All continuity is destroyed."""
    return _rebuild(trajectory, [
        replace(e, identity_id=f"split_identity_{i:03d}",
                actor_id=f"split_identity_{i:03d}")
        for i, e in enumerate(trajectory.events)])


def fragment_subjects(trajectory):
    """Give every step its own data subject."""
    return _rebuild(trajectory, [
        replace(e, resource=f"{e.resource_type or 'thing'}/split_subject_{i:03d}")
        for i, e in enumerate(trajectory.events)])


def collapse_boundary(trajectory):
    """Pull every step back inside the perimeter."""
    return _rebuild(trajectory, [
        replace(e, trust_boundary=BOUNDARY_INTERNAL) for e in trajectory.events])


def hoist_crossing_to_front(trajectory):
    """Move the earliest perimeter-crossing step to position 0.

    Every relation these grammars can express that ends at a crossing is
    destroyed by this, and nothing else about the trajectory changes: the same
    steps, the same identities, the same subjects, the same boundaries.
    """
    events = list(trajectory.events)
    for index, event in enumerate(events):
        if event.trust_boundary != BOUNDARY_INTERNAL and index > 0:
            events.insert(0, events.pop(index))
            break
    return _rebuild(trajectory, [replace(e, step_index=i)
                                 for i, e in enumerate(events)])


def drop_last_step(trajectory):
    if len(trajectory.events) < 2:
        return trajectory
    return _rebuild(trajectory, list(trajectory.events[:-1]))


PRESERVING = (
    ("alpha_rename_identities", alpha_rename_identities),
    ("rename_tools", rename_tools),
    ("substitute_provider", substitute_provider),
    ("translate_timestamps", translate_timestamps),
    ("substitute_vocabulary", substitute_vocabulary),
    ("perturb_irrelevant_fields", perturb_irrelevant_fields),
    ("insert_irrelevant_event", insert_irrelevant_event),
    ("pad_trace", pad_trace),
    ("reorder_independent_steps", reorder_independent_steps),
)

DESTRUCTIVE = (
    ("reverse_order", reverse_order),
    ("fragment_identities", fragment_identities),
    ("fragment_subjects", fragment_subjects),
    ("collapse_boundary", collapse_boundary),
    ("hoist_crossing_to_front", hoist_crossing_to_front),
)

# MEASURED, REPORTED, AND DELIBERATELY NOT GATED.
#
# `drop_last_step` began in `DESTRUCTIVE` and produced an extinction of 0.7266
# against a declared floor of 0.80, which would have failed the run. Inspecting
# the misses showed the transform is not destructive: a hazard whose crossing is
# not the final step — one followed by a verification, or by a padding step —
# still contains the whole relation after its last step is removed, and the
# candidate is CORRECT to keep firing on it. The failing number was a property
# of the transform, not of the candidate.
#
# Removing a check because it failed is the exact move the earlier phases of
# this project warn about, so it has not been removed. It is measured on every
# run and printed beside the gated ones; what changed is that it no longer
# decides a verdict it was never able to decide, and `hoist_crossing_to_front`
# — which destroys the ordering relation for every trajectory rather than for
# most of them — took its place in the gate.
PARTIALLY_DESTRUCTIVE = (
    ("drop_last_step", drop_last_step),
)


def agreement(before, after) -> float:
    if not before:
        return 1.0
    return sum(1 for a, b in zip(before, after) if a == b) / len(before)


def extinction(before, after) -> float:
    """Of the trajectories the candidate fired on, how many stopped firing?"""
    fired = [index for index, value in enumerate(before) if value]
    if not fired:
        return 0.0
    return sum(1 for index in fired if not after[index]) / len(fired)
