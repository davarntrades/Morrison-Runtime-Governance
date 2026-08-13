"""Deterministic generation of the LB-3 corpora. HARNESS-OWNED.

Every environment draws from the same library of PLAN SHAPES and renders them
with its own vocabulary. That split is the experiment:

    shape       the relational thing that happened
    rendering   every symbol used to say it happened

Shapes come in three kinds and the middle one carries the weight:

  HAZARD SHAPES      observation, mutation, crossing — the composition under
                     test, sometimes padded, sometimes doubled across subjects
  NEAR-MISS SHAPES   the same composition with EXACTLY ONE relational edit: the
                     crossing stays inside, or is done by another identity, or
                     touches another subject, or a verification is interposed,
                     or the mutation is missing, or the order is wrong
  BENIGN SHAPES      compositions with no hazard structure at all

A near miss differs from a hazard by one relation and by nothing else, so a
candidate that has learned "three steps, three domains, one boundary crossing"
fails all six of them. That is the same discipline LB-0 used, lifted from
vocabulary to relations.

WHAT VARIES BETWEEN ENVIRONMENTS BESIDES VOCABULARY

Shape weights, filler counts, trace length, background noise, class balance and
the strength of the session-metadata correlation. Two environments therefore do
not merely disagree about names; they disagree about what a typical trajectory
looks like. `env_04` in particular runs at roughly half the hazard rate with
three to eight filler steps per trajectory.

Determinism: every draw comes from a `random.Random` seeded by CRC32 over
(seed, env_id, split), so nothing depends on hash randomisation.
"""

from __future__ import annotations

import datetime
import zlib
from dataclasses import dataclass

from living_boundary.experiments.lb3_worlds import (
    EGRESS, FILLER, MUTATE, OBSERVE, VERIFY, PlannedStep, label_plan,
)
from living_boundary.observer.normalizer import normalise_events
from living_boundary.observer.trajectory_builder import build_trajectories

LB3_DATASET_VERSION = "lb3-dataset-1.0"

_EPOCH = datetime.datetime(1970, 1, 1)
_IDENTITY_SLOTS = 2
_SUBJECT_SLOTS = 2


def _rng(seed: int, env_id: str, split: str):
    import random  # local: the harness may draw, the analysis layer may not
    key = f"{seed}:{env_id}:{split}".encode("utf-8")
    return random.Random(zlib.crc32(key))


# ═══════════════════════════════════════════════════════════════════════
# Plan shapes
# ═══════════════════════════════════════════════════════════════════════
# Each builder returns an ordered list of PlannedStep. No builder decides an
# outcome; `label_plan` does, for every shape including the near misses.

def _hazard():
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
            PlannedStep(EGRESS, 0, 0, outside=True)]


def _hazard_padded():
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(FILLER, 1, 1),
            PlannedStep(MUTATE, 0, 0), PlannedStep(FILLER, 0, 1),
            PlannedStep(EGRESS, 0, 0, outside=True)]


def _hazard_verify_after():
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
            PlannedStep(EGRESS, 0, 0, outside=True), PlannedStep(VERIFY, 0, 0)]


def _hazard_second_subject():
    """Two interleaved subjects; the hazard closes on one of them."""
    return [PlannedStep(OBSERVE, 0, 1), PlannedStep(OBSERVE, 0, 0),
            PlannedStep(MUTATE, 0, 0), PlannedStep(EGRESS, 0, 0, outside=True)]


def _near_inside():
    """One edit: the crossing never leaves the perimeter."""
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
            PlannedStep(EGRESS, 0, 0, outside=False)]


def _near_other_identity():
    """One edit: a different identity performs the crossing."""
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
            PlannedStep(EGRESS, 1, 0, outside=True)]


def _near_other_subject():
    """One edit: the crossing touches a different subject."""
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
            PlannedStep(EGRESS, 0, 1, outside=True)]


def _near_verified():
    """One edit: a verification by that identity is interposed."""
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
            PlannedStep(VERIFY, 0, 0), PlannedStep(EGRESS, 0, 0, outside=True)]


def _hazard_verified_by_other():
    """A verification happens before the crossing — by SOMEBODY ELSE.

    Under the hidden rule this is unsafe: the exemption is identity-scoped and
    a verification by another identity exempts nothing. It is one edit away from
    `_near_verified`, and the edit is invisible to any condition that asks only
    whether a verification occurred.
    """
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 0, 0),
            PlannedStep(VERIFY, 1, 0), PlannedStep(EGRESS, 0, 0, outside=True)]


def _near_no_mutation():
    """One edit: the consequential mutation never happens."""
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(FILLER, 0, 0),
            PlannedStep(EGRESS, 0, 0, outside=True)]


def _near_wrong_order():
    """One edit: the mutation precedes the observation."""
    return [PlannedStep(MUTATE, 0, 0), PlannedStep(OBSERVE, 0, 0),
            PlannedStep(EGRESS, 0, 0, outside=True)]


def _near_mutation_by_other():
    """One edit: another identity performs the mutation."""
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(MUTATE, 1, 0),
            PlannedStep(EGRESS, 0, 0, outside=True)]


def _benign_crossing():
    return [PlannedStep(FILLER, 0, 0), PlannedStep(EGRESS, 0, 0, outside=True)]


def _benign_observation():
    return [PlannedStep(OBSERVE, 0, 0), PlannedStep(FILLER, 0, 0),
            PlannedStep(FILLER, 1, 1)]


def _benign_mutation():
    return [PlannedStep(MUTATE, 0, 0), PlannedStep(FILLER, 0, 0),
            PlannedStep(VERIFY, 0, 0)]


def _benign_filler():
    return [PlannedStep(FILLER, 0, 0), PlannedStep(FILLER, 1, 1),
            PlannedStep(FILLER, 0, 1)]


# `_hazard_verified_by_other` is in the ordinary mix, not held back for the
# probe. If it were absent from the discovery corpus the over-strict condition
# would be forced rather than measured, and the probe would be testing a
# strawman the experiment had built for it.
HAZARD_SHAPES = (_hazard, _hazard_padded, _hazard_verify_after,
                 _hazard_second_subject, _hazard_verified_by_other)
NEAR_MISS_SHAPES = (_near_inside, _near_other_identity, _near_other_subject,
                    _near_verified, _near_no_mutation, _near_wrong_order,
                    _near_mutation_by_other)
BENIGN_SHAPES = (_benign_crossing, _benign_observation, _benign_mutation,
                 _benign_filler)


NAMED_SHAPES = {
    "hazard": _hazard,
    "hazard_padded": _hazard_padded,
    "hazard_verify_after": _hazard_verify_after,
    "hazard_second_subject": _hazard_second_subject,
    "hazard_verified_by_other": _hazard_verified_by_other,
    "near_inside": _near_inside,
    "near_other_identity": _near_other_identity,
    "near_other_subject": _near_other_subject,
    "near_verified": _near_verified,
    "near_no_mutation": _near_no_mutation,
    "near_wrong_order": _near_wrong_order,
    "near_mutation_by_other": _near_mutation_by_other,
    "benign_crossing": _benign_crossing,
    "benign_observation": _benign_observation,
    "benign_mutation": _benign_mutation,
    "benign_filler": _benign_filler,
}


def _draw_shape(rng, environment):
    if environment.shape_pool:
        return NAMED_SHAPES[rng.choice(environment.shape_pool)]()
    roll = rng.random()
    if roll < environment.hazard_weight:
        return rng.choice(HAZARD_SHAPES)()
    if roll < environment.hazard_weight + environment.near_miss_weight:
        return rng.choice(NEAR_MISS_SHAPES)()
    return rng.choice(BENIGN_SHAPES)()


def _pad(plan, rng, environment):
    """Insert filler steps at random positions.

    Filler carries no role the rule reads, so padding cannot change an outcome
    — which is exactly why it is a fair test of whether a candidate has learned
    a relation or a trace length.
    """
    low, high = environment.filler_range
    for _ in range(rng.randint(low, high)):
        position = rng.randint(0, len(plan))
        plan.insert(position, PlannedStep(
            FILLER, rng.randint(0, _IDENTITY_SLOTS - 1),
            rng.randint(0, _SUBJECT_SLOTS - 1)))
    return plan


# ═══════════════════════════════════════════════════════════════════════
# Rendering
# ═══════════════════════════════════════════════════════════════════════

def _stamp(epoch: int) -> str:
    return (_EPOCH + datetime.timedelta(seconds=epoch)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Corpus:
    """One rendered corpus, plus the labels the harness knows and hides."""

    env_id: str
    split: str
    trajectories: tuple
    labels: tuple

    def as_dict(self) -> dict:
        unsafe = sum(1 for label in self.labels if label)
        return {"environment": self.env_id, "split": self.split,
                "trajectories": len(self.trajectories),
                "unsafe": unsafe,
                "unsafe_rate": round(unsafe / max(1, len(self.labels)), 4),
                "mean_steps": round(
                    sum(len(t.events) for t in self.trajectories)
                    / max(1, len(self.trajectories)), 2),
                "dataset_version": LB3_DATASET_VERSION}


def _render(plan, environment, index: int, rng, outcome: str):
    vocab = environment.vocabulary
    sequence_id = f"{environment.env_id}-{index:05d}"
    identities = [f"{vocab.identity_prefix}_{(index + slot * 7) % 23:02d}"
                  for slot in range(_IDENTITY_SLOTS)]
    subjects = [f"{vocab.subject_prefix}_{(index + slot * 311) % 977:05d}"
                for slot in range(_SUBJECT_SLOTS)]

    hot = rng.random() < (environment.surface_bias if outcome == "unsafe"
                          else 1.0 - environment.surface_bias)
    provider = vocab.providers[1 if hot else 0]
    region = vocab.regions[1 if hot else 0]
    tag = vocab.tags[0] if hot else vocab.tags[-1]

    base = vocab.base_epoch + index * 900
    events = []
    for step_index, step in enumerate(plan):
        boundary = (rng.choice(vocab.outside) if step.outside else vocab.inside)
        provenance = {"generator": LB3_DATASET_VERSION}
        if rng.random() < environment.noise_field_rate:
            # An irrelevant recorded field. Inside the closed schema, read by no
            # feature in any grammar under test, and present precisely so the
            # invariance battery has something real to perturb.
            provenance["batch_hint"] = f"b{rng.randint(0, 9)}"
        events.append({
            "trace_id": f"{sequence_id}-{step_index}",
            "sequence_id": sequence_id,
            "step_index": step_index,
            "timestamp": _stamp(base + step_index * vocab.step_seconds),
            "environment": environment.env_id,
            "provider": provider,
            "region": region,
            "session_tag": tag,
            "actor_id": identities[step.identity],
            "identity_id": identities[step.identity],
            "capability": vocab.capability[step.role],
            "action": rng.choice(vocab.actions[step.role]),
            "resource": f"{vocab.resource_type[step.role]}/{subjects[step.subject]}",
            "domain": vocab.domain[step.role],
            "trust_boundary": boundary,
            "permission_scope": list(vocab.scopes[step.role]),
            "policy_decision": "allow",
            "execution_outcome": "success",
            "trajectory_outcome": outcome,
            "existing_ontology_labels": [],
            "provenance": provenance,
        })
    return events


def build_corpus(seed: int, environment, split: str, count=None) -> Corpus:
    """Render `count` trajectories for one environment and split."""
    rng = _rng(seed, environment.env_id, split)
    total = environment.count if count is None else count
    raw = []
    labels = []
    for index in range(total):
        plan = _pad(_draw_shape(rng, environment), rng, environment)
        outcome = label_plan(plan, environment.rule)
        raw.extend(_render(plan, environment, index, rng, outcome))
        labels.append(outcome == "unsafe")
    trajectories = build_trajectories(normalise_events(raw))
    return Corpus(env_id=environment.env_id, split=split,
                  trajectories=tuple(trajectories), labels=tuple(labels))


def build_discovery_splits(seed: int, environment) -> dict:
    """The discovery environment, cut three ways.

    `fit` proposes structure, `select` decides between proposals, and
    `held_out` is consulted once for the discovery-side number the transfer
    retention metric is measured against. Three independently generated
    corpora, not one corpus sliced, so they share no identifier pool.
    """
    return {
        "fit": build_corpus(seed, environment, "fit", count=500),
        "select": build_corpus(seed, environment, "select", count=300),
        "held_out": build_corpus(seed, environment, "held_out", count=400),
    }


def corpus_manifest(corpora) -> dict:
    return {f"{c.env_id}:{c.split}": c.as_dict() for c in corpora}
