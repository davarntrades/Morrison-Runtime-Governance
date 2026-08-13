"""Experiment generator: build cases designed to BREAK the frozen candidate.

The generator reads the CANDIDATE, never the oracle. That separation is what
makes this a falsification attempt rather than a rigged confirmation: the cases
are constructed to violate the candidate's own stated conditions, one at a time,
and only afterwards does the oracle say what actually happened.

Three kinds of case are produced.

  ABLATIONS      For every literal in the candidate, trajectories that satisfy
                 all the other conditions but not that one. This is the direct
                 test of the candidate's own prediction ("remove any single
                 condition and the outcome changes"). A literal that is really
                 a confounder fails here loudly: ablating `session_tag` leaves a
                 genuinely unsafe trajectory that the candidate now calls safe.

  SURFACE-ONLY   Trajectories with every identifier rewritten — identities,
                 actors, data subjects, timestamps, provider, region, tag —
                 and no structural change at all. The candidate must be
                 unmoved. This is the memorisation test at the individual-case
                 level.

  GLOBAL         Whole-trajectory reorderings, identity fragmentation, boundary
                 withdrawal and confounder inversion, applied without reference
                 to any particular literal.

Every case is derived from a REAL seed trajectory taken from the validation
split, so no case is a shape that the world could not produce.
"""

from __future__ import annotations

import random
import zlib
from dataclasses import dataclass, replace

from living_boundary.experiments.world import CATALOGUE, INTERNAL, PARTNER
from living_boundary.observer.trajectory_builder import NormalisedTrajectory

SEP = "::"
ARG = "|"


@dataclass(frozen=True)
class PerturbedCase:
    """One generated experiment case."""

    case_id: str
    kind: str                    # ablation | surface | global
    operator: str                # what was changed
    target_literal: str          # "" for surface/global cases
    seed_sequence_id: str
    trajectory: NormalisedTrajectory

    def as_dict(self) -> dict:
        return {
            "case_id": self.case_id, "kind": self.kind,
            "operator": self.operator, "target_literal": self.target_literal,
            "seed_sequence_id": self.seed_sequence_id,
            "steps": len(self.trajectory.events),
        }


# Token -> a catalogue action that produces it. Used when a NEGATED literal has
# to be made true, which means introducing a step that was not there.
def _token_of(spec) -> str:
    boundary = "internal" if spec.trust_boundary == INTERNAL else "crossing"
    return f"{spec.capability}@{spec.domain}@{boundary}"


_ACTION_FOR_TOKEN = {}
_ACTION_FOR_CAPABILITY = {}
_ACTION_FOR_DOMAIN = {}
_ACTION_FOR_BOUNDARY = {}
for _spec in CATALOGUE.values():
    _ACTION_FOR_TOKEN.setdefault(_token_of(_spec), _spec)
    _ACTION_FOR_CAPABILITY.setdefault(_spec.capability, _spec)
    _ACTION_FOR_DOMAIN.setdefault(_spec.domain, _spec)
    _ACTION_FOR_BOUNDARY.setdefault(_spec.trust_boundary, _spec)


def _rebuild(events, sequence_id: str) -> NormalisedTrajectory:
    """Re-index and re-id a mutated event list into a coherent trajectory."""
    rebuilt = []
    for index, event in enumerate(events):
        rebuilt.append(replace(
            event, step_index=index, sequence_id=sequence_id,
            trace_id=f"{sequence_id}-s{index}",
            trajectory_outcome=""))
    return NormalisedTrajectory(sequence_id=sequence_id, events=tuple(rebuilt))


def _indices_with_token(events, token) -> list:
    return [i for i, e in enumerate(events) if e.token == token]


def _parse(name: str):
    bare = name[4:] if name.startswith("NOT ") else name
    family, _, rest = bare.partition(SEP)
    args = [a for a in rest.split(ARG) if a != ""] if rest else []
    return name.startswith("NOT "), family, args


# ── operators that make a POSITIVE literal false ────────────────────────

def _break_order(events, args):
    """Move the last participating step in front of the first one."""
    first = _indices_with_token(events, args[0])
    last = _indices_with_token(events, args[-1])
    if not first or not last:
        return None
    i, k = first[0], last[-1]
    if k <= i:
        return None
    reordered = list(events)
    moved = reordered.pop(k)
    reordered.insert(i, moved)
    return reordered


def _break_same_identity(events, args, rng):
    later = _indices_with_token(events, args[1])
    if not later:
        return None
    index = later[-1]
    out = list(events)
    out[index] = replace(out[index],
                         identity_id=out[index].identity_id + "_alt{}".format(
                             rng.randrange(90)))
    return out


def _break_subject_link(events, args, rng):
    later = _indices_with_token(events, args[1])
    if not later:
        return None
    index = later[-1]
    event = events[index]
    new_subject = f"{event.subject or 'subject'}_x{rng.randrange(9000)}"
    out = list(events)
    out[index] = replace(event, resource="{}/{}".format(
        event.resource_type or "resource", new_subject))
    return out


def _break_scope(events, args):
    token = args[0]
    out = []
    touched = False
    for event in events:
        if token in event.permission_scope:
            touched = True
            out.append(replace(event, permission_scope=tuple(
                s for s in event.permission_scope if s != token)))
        else:
            out.append(event)
    return out if touched else None


def _break_presence(events, predicate):
    """Drop every step matching `predicate`."""
    out = [e for e in events if not predicate(e)]
    return out if out and len(out) != len(events) else None


def _break_single_identity(events, rng):
    if len(events) < 2:
        return None
    out = list(events)
    index = len(out) - 1
    out[index] = replace(out[index],
                         identity_id=out[index].identity_id + "_alt{}".format(
                             rng.randrange(90)))
    return out


def _break_crossing(events):
    out = [replace(e, trust_boundary=INTERNAL) if e.trust_boundary != INTERNAL else e
           for e in events]
    return out if any(e.trust_boundary != INTERNAL for e in events) else None


def _break_steps_ge(events, args):
    limit = int(args[0])
    if len(events) < limit:
        return None
    return list(events[:max(1, limit - 1)])


def _break_surface_value(events, field_name, rng):
    replacement = f"{field_name}_ablated_{rng.randrange(900)}"
    return [replace(e, **{field_name: replacement}) for e in events]


# ── operators that make a NEGATED literal true ──────────────────────────

def _satisfy_order3(events, args):
    """Insert the missing middle step between the first and last participants."""
    spec = _ACTION_FOR_TOKEN.get(args[1])
    if spec is None:
        return None
    first = _indices_with_token(events, args[0])
    last = _indices_with_token(events, args[2])
    if not first or not last or last[-1] <= first[0]:
        return None
    anchor = events[first[0]]
    inserted = replace(
        anchor, capability=spec.capability, action=spec.action,
        domain=spec.domain, trust_boundary=spec.trust_boundary,
        permission_scope=spec.permission_scope,
        resource=f"{spec.resource_type}/{anchor.subject}")
    out = list(events)
    out.insert(first[0] + 1, inserted)
    return out


def _step_like(anchor, spec, subject=None, identity=None):
    """A new step running `spec`, borrowing session metadata from `anchor`."""
    return replace(
        anchor, capability=spec.capability, action=spec.action,
        domain=spec.domain, trust_boundary=spec.trust_boundary,
        permission_scope=spec.permission_scope,
        identity_id=identity or anchor.identity_id,
        resource="{}/{}".format(spec.resource_type,
                                subject if subject is not None else anchor.subject))


def _satisfy_token(events, token):
    spec = _ACTION_FOR_TOKEN.get(token)
    if spec is None or not events:
        return None
    return list(events) + [_step_like(events[-1], spec)]


def _satisfy_from(events, lookup, key):
    spec = lookup.get(key)
    if spec is None or not events:
        return None
    return list(events) + [_step_like(events[-1], spec)]


def _satisfy_pair(events, args, share_subject: bool, share_identity: bool):
    """Make `A before B` true, sharing whatever the literal says they share.

    Generic satisfier for the negated pair families (`NOT order2`,
    `NOT same_identity`, `NOT subject_link`). Two routes, because the literal
    can be false for two different reasons:

      · An A step exists but no B step follows it  -> append a B step.
      · No A step exists at all                    -> insert an A step in front
                                                      of the first B step.

    The second route is not an edge case. `NOT order2::reverify|egress` — "no
    identity re-verification before the egress" — is almost always true because
    the trajectory contains NO re-verification at all, and without this route
    the condition would be reported as untestable and would fail the run for the
    wrong reason.
    """
    spec_b = _ACTION_FOR_TOKEN.get(args[1])
    spec_a = _ACTION_FOR_TOKEN.get(args[0])
    anchors = _indices_with_token(events, args[0])

    if anchors and spec_b is not None:
        anchor = events[anchors[0]]
        return list(events) + [_step_like(
            anchor, spec_b,
            subject=anchor.subject if share_subject else "unlinked-subject",
            identity=anchor.identity_id if share_identity else None)]

    targets = _indices_with_token(events, args[1])
    if targets and spec_a is not None:
        target = events[targets[0]]
        inserted = _step_like(
            target, spec_a,
            subject=target.subject if share_subject else "unlinked-subject",
            identity=target.identity_id if share_identity else None)
        out = list(events)
        out.insert(targets[0], inserted)
        return out
    return None


def _satisfy_steps_ge(events, args):
    limit = int(args[0])
    if not events or len(events) >= limit:
        return None
    spec = _ACTION_FOR_TOKEN.get(events[-1].token)
    if spec is None:
        return None
    out = list(events)
    while len(out) < limit:
        out.append(_step_like(out[-1], spec, subject=f"padding-{len(out)}"))
    return out


def _satisfy_transition(events, args):
    if len(events) < 2:
        return None
    out = list(events)
    out[-2] = replace(out[-2], trust_boundary=args[0])
    out[-1] = replace(out[-1], trust_boundary=args[1])
    return out


def _satisfy_scope(events, scope):
    if not events:
        return None
    out = list(events)
    out[0] = replace(out[0], permission_scope=tuple(
        sorted(set(out[0].permission_scope) | {scope})))
    return out


def _satisfy_single_identity(events):
    if not events:
        return None
    identity = events[0].identity_id
    return [replace(e, identity_id=identity) for e in events]


def ablate(literal_name: str, trajectory, rng):
    """Produce an event list that violates `literal_name`, or None.

    Returning None is a real outcome, not a shrug: it means the candidate
    contains a condition this generator cannot construct a counterexample for,
    and the falsification runner reports that literal as UNTESTED rather than
    quietly passing it.
    """
    negated, family, args = _parse(literal_name)
    events = list(trajectory.events)

    if not negated:
        if family in ("order2", "order3", "order3_identity"):
            return _break_order(events, args)
        if family == "same_identity":
            return _break_same_identity(events, args, rng)
        if family == "subject_link":
            return _break_subject_link(events, args, rng)
        if family == "scope":
            return _break_scope(events, args)
        if family == "has_token":
            return _break_presence(events, lambda e, t=args[0]: e.token == t)
        if family == "has_cap":
            return _break_presence(events, lambda e, c=args[0]: e.capability == c)
        if family == "has_domain":
            return _break_presence(events, lambda e, d=args[0]: e.domain == d)
        if family == "has_boundary":
            return _break_presence(events, lambda e, b=args[0]: e.trust_boundary == b)
        if family == "single_identity":
            return _break_single_identity(events, rng)
        if family in ("crosses_boundary", "transition"):
            return _break_crossing(events)
        if family == "steps_ge":
            return _break_steps_ge(events, args)
        if family in ("provider", "region", "session_tag"):
            return _break_surface_value(events, family, rng)
        return None

    if family in ("order3", "order3_identity"):
        return _satisfy_order3(events, args)
    if family == "has_token":
        return _satisfy_token(events, args[0])
    if family == "has_cap":
        return _satisfy_from(events, _ACTION_FOR_CAPABILITY, args[0])
    if family == "has_domain":
        return _satisfy_from(events, _ACTION_FOR_DOMAIN, args[0])
    if family == "has_boundary":
        return _satisfy_from(events, _ACTION_FOR_BOUNDARY, args[0])
    if family == "order2":
        return _satisfy_pair(events, args, share_subject=False, share_identity=False)
    if family == "same_identity":
        return _satisfy_pair(events, args, share_subject=False, share_identity=True)
    if family == "subject_link":
        return _satisfy_pair(events, args, share_subject=True, share_identity=False)
    if family == "scope":
        return _satisfy_scope(events, args[0])
    if family == "single_identity":
        return _satisfy_single_identity(events)
    if family == "steps_ge":
        return _satisfy_steps_ge(events, args)
    if family == "transition":
        return _satisfy_transition(events, args)
    if family in ("provider", "region", "session_tag"):
        return _break_surface_value(events, family, rng)
    if family == "crosses_boundary":
        return [replace(e, trust_boundary=PARTNER) if i == len(events) - 1 else e
                for i, e in enumerate(events)]
    return None


# ── surface-only and global controls ────────────────────────────────────

def surface_rewrite(trajectory, rng):
    """Rewrite every identifier while preserving structure exactly."""
    identity_map = {}
    subject_map = {}
    out = []
    for event in trajectory.events:
        identity_map.setdefault(
            event.identity_id, f"identity_fz_{rng.randrange(1000):03d}")
        if event.subject:
            subject_map.setdefault(
                event.subject, f"subj_fz_{rng.randrange(1000000):06d}")
        out.append(replace(
            event,
            identity_id=identity_map[event.identity_id],
            actor_id=f"agent_fz_{rng.randrange(1000):03d}",
            resource="{}/{}".format(event.resource_type or "resource",
                                    subject_map.get(event.subject, event.subject)),
            timestamp=f"2031-01-01T00:00:{event.step_index % 60:02d}Z",
            provider="provider-fz", region="region-fz", session_tag="tag_fz"))
    return out


def fragment_identity(trajectory, rng):
    out = []
    for index, event in enumerate(trajectory.events):
        out.append(replace(event, identity_id="{}_frag{}".format(
            event.identity_id, index + rng.randrange(2))))
    return out


def reverse_all(trajectory):
    return list(reversed(trajectory.events))


def invert_confounders(trajectory):
    return [replace(e, provider="provider-a", region="eu-west",
                    session_tag="tag_alpha") for e in trajectory.events]


def build_cases(candidate, seed_trajectories, seed: int,
                per_literal: int = 12, per_control: int = 25):
    """Generate the full falsification battery for a frozen candidate."""
    rng = random.Random(seed * 31337 + 11)
    firing = [t for t in seed_trajectories if candidate.matches(t)]
    cases = []
    untestable = []

    if not firing:
        return cases, tuple(lit.name for lit in candidate.literals)

    for literal in candidate.literals:
        made = 0
        for offset in range(len(firing)):
            if made >= per_literal:
                break
            seed_trajectory = firing[(offset * 7 + 3) % len(firing)]
            mutated = ablate(literal.name, seed_trajectory, rng)
            if not mutated:
                continue
            # CRC32, not hash(): a `hash()`-derived case id changes with
            # PYTHONHASHSEED, and case ids appear in the sealed evidence.
            case_id = f"abl-{zlib.crc32(literal.name.encode('utf-8')):08x}-{made:03d}"
            cases.append(PerturbedCase(
                case_id=case_id, kind="ablation", operator="ablate",
                target_literal=literal.name,
                seed_sequence_id=seed_trajectory.sequence_id,
                trajectory=_rebuild(mutated, f"lb0-falsify-{case_id}")))
            made += 1
        if made == 0:
            untestable.append(literal.name)

    controls = (
        ("surface", "surface_rewrite", lambda t: surface_rewrite(t, rng)),
        ("global", "reverse_all", reverse_all),
        ("global", "fragment_identity", lambda t: fragment_identity(t, rng)),
        ("global", "invert_confounders", invert_confounders),
    )
    for kind, operator, fn in controls:
        for index in range(min(per_control, len(firing))):
            seed_trajectory = firing[(index * 5 + 1) % len(firing)]
            mutated = fn(seed_trajectory)
            if not mutated:
                continue
            case_id = f"{operator}-{index:03d}"
            cases.append(PerturbedCase(
                case_id=case_id, kind=kind, operator=operator,
                target_literal="", seed_sequence_id=seed_trajectory.sequence_id,
                trajectory=_rebuild(mutated, f"lb0-falsify-{case_id}")))

    return cases, tuple(untestable)
