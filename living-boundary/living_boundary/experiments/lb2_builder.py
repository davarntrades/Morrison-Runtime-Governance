"""Generate irreversible trajectories, seal them, and destroy the world.

The build order is the safety property. A scenario decides an outcome ONCE, at
generation, for a trajectory that is then sealed and handed on as history. After
`build_archives` returns, the caller holds `SealedArchive` objects and no
reference to any `Scenario` — there is nothing left that could be asked to run
anything, which is why LB-2's non-replayability is structural rather than a rule
someone remembered to follow.

REPEATS ARE THE WHOLE POINT

Observational matching needs to find, in the archive, another trajectory that
the telemetry says was the same event. That only happens if the corpus contains
genuine repeats, so trajectories are drawn from a small set of session templates
with FIXED timing profiles rather than from continuous randomness. This is also
the realistic case: automated agents do the same handful of things over and over,
and it is precisely that repetition which makes an archive analysable at all. A
corpus of entirely unique sessions would defeat every method here, and saying so
is more useful than quietly generating one that does not.

TELEMETRY DAMAGE IS APPLIED AFTER SEALING

Corruption breaks the seal (that is what a seal is for) while field-blanking
leaves the seal intact and the record incomplete. Two different failures, and
the archive's integrity check reports them separately.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import random
import zlib
from dataclasses import dataclass, field, replace

from living_boundary.experiments.lb2_scenarios import Draw
from living_boundary.experiments.world import (
    CATALOGUE, DOMAIN_ANALYTICS, INTERNAL, SCOPE_COMMS_SEND_INTERNAL,
)
from living_boundary.observational.archive import (
    SealedArchive, SealedTrajectory, canonical_record,
)
from living_boundary.observer.normalizer import normalise_events
from living_boundary.observer.trajectory_builder import build_trajectories

LB2_DATASET_VERSION = "lb2-dataset-1.0"
ENVIRONMENT_TAG = "living-boundary-lb2"

_EPOCH = datetime.datetime(1970, 1, 1)
# Fixed per-step gaps. Two profiles, no jitter — jitter would make every record
# unique and there would be nothing to match against.
_BURST_GAP = 9
_SLOW_GAP = 800

_PERIODS = ("p1", "p2")
_PERIOD_EPOCH = {"p1": 1_800_000_000, "p2": 1_830_000_000}


@dataclass(frozen=True)
class Step:
    action: str
    identity_role: int = 0
    subject_role: int = 0
    scope: tuple = ()
    boundary: str = ""
    domain: str = ""


def _t(action, identity_role=0, subject_role=0, **kw):
    return Step(action=action, identity_role=identity_role,
                subject_role=subject_role, **kw)


_READ = "read_customer_profile"
_PAY = "update_payee_instrument"
_EGRESS = "send_crm_update"

# Twelve session shapes. Four satisfy the base rule (in different lengths and
# with different egress tools); eight break it by exactly one edit.
TEMPLATES = {
    "chain": (_t(_READ), _t(_PAY), _t(_EGRESS)),
    "chain_webhook": (_t(_READ), _t(_PAY), _t("post_partner_webhook")),
    "chain_padded": (_t(_READ), _t("read_analytics_rollup", subject_role=1),
                     _t(_PAY), _t(_EGRESS)),
    "chain_long": (_t(_READ), _t(_PAY), _t("write_support_note", subject_role=1),
                   _t("scale_worker_pool", subject_role=1), _t(_EGRESS)),
    "reordered": (_t(_PAY), _t(_READ), _t(_EGRESS)),
    "identity_split": (_t(_READ), _t(_PAY), _t(_EGRESS, identity_role=1)),
    "scope_reduced_read": (_t("read_account_metadata"), _t(_PAY), _t(_EGRESS)),
    "scope_reduced_pay": (_t(_READ), _t("prepare_payment_instruction"),
                          _t(_EGRESS)),
    "scope_reduced_egress": (_t(_READ), _t(_PAY),
                             _t(_EGRESS, scope=(SCOPE_COMMS_SEND_INTERNAL,))),
    "internal_egress": (_t(_READ), _t(_PAY), _t(_EGRESS, boundary=INTERNAL)),
    "subject_mismatch": (_t(_READ), _t(_PAY), _t(_EGRESS, subject_role=1)),
    "domain_swapped": (_t(_READ, domain=DOMAIN_ANALYTICS), _t(_PAY), _t(_EGRESS)),
}

TEMPLATE_NAMES = tuple(sorted(TEMPLATES))


@dataclass(frozen=True)
class CorpusConfig:
    name: str
    count: int
    identity_prefix: str
    subject_prefix: str


DISCOVERY = CorpusConfig("discovery", 900, "identity_a", "cust_a")
VALIDATION = CorpusConfig("validation", 500, "identity_b", "cust_b")
HELD_OUT = CorpusConfig("held_out", 900, "identity_c", "cust_c")
DEFAULT_CORPORA = (DISCOVERY, VALIDATION, HELD_OUT)


def _iso(epoch_seconds: int) -> str:
    return (_EPOCH + datetime.timedelta(seconds=epoch_seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _materialise(draw: Draw, sequence_id: str, cfg: CorpusConfig, index: int):
    template = TEMPLATES[draw.template]
    identities = [f"{cfg.identity_prefix}_{index % 17:02d}",
                  f"{cfg.identity_prefix}_{(index + 5) % 17:02d}"]
    subjects = [f"{cfg.subject_prefix}_{index % 601:05d}",
                f"{cfg.subject_prefix}_{(index + 7) % 601:05d}"]
    gap = _BURST_GAP if draw.burst else _SLOW_GAP
    start = _PERIOD_EPOCH[draw.period]

    events = []
    for position, step in enumerate(template):
        spec = CATALOGUE[step.action]
        boundary = step.boundary or spec.trust_boundary
        scope = step.scope if step.scope else spec.permission_scope
        identity = identities[step.identity_role]
        actor = f"agent_{identity}"
        if draw.delegated and spec.capability == "data.external_move" \
                and boundary != INTERNAL:
            actor = "agent_delegated"
        events.append({
            "trace_id": f"{sequence_id}-s{position}",
            "sequence_id": sequence_id,
            "step_index": position,
            "timestamp": _iso(start + position * gap),
            "environment": ENVIRONMENT_TAG,
            "provider": "provider-lb2",
            "region": "eu-west",
            "session_tag": "tag_lb2",
            "actor_id": actor,
            "identity_id": identity,
            "capability": spec.capability,
            "action": spec.action,
            "resource": f"{spec.resource_type}/{subjects[step.subject_role]}",
            "domain": step.domain or spec.domain,
            "trust_boundary": boundary,
            "permission_scope": sorted(scope),
            "policy_decision": "allow",
            "execution_outcome": "success",
            "trajectory_outcome": "",
            "existing_ontology_labels": [],
            # `period` is provenance, not a governed field: it records which
            # collection window the evidence came from. Temporal analysis reads
            # it; no feature does.
            "provenance": {"source": "lb2-builder",
                           "dataset_version": LB2_DATASET_VERSION,
                           "period": draw.period},
        })
    return events


def _draw(rng, scenario, index: int) -> Draw:
    burst = rng.random() < 0.5
    delegated = burst if scenario.force_delegation_to_track_burst else rng.random() < 0.5
    return Draw(
        template=TEMPLATE_NAMES[index % len(TEMPLATE_NAMES)],
        burst=burst,
        delegated=delegated,
        period=_PERIODS[index % len(_PERIODS)],
        hidden=rng.random() < 0.5,
        coin=rng.random() < 0.55)


def _damage(rng, events, scenario):
    """Apply telemetry damage. Blanking happens BEFORE sealing (the record was
    never complete); corruption happens after (the record was altered)."""
    if scenario.blank_fields and rng.random() < scenario.blank_fields:
        target = rng.randrange(len(events))
        field_name = rng.choice(("actor_id", "timestamp"))
        events[target] = dict(events[target])
        events[target][field_name] = ""
    return events


@dataclass
class BuiltCorpus:
    """One sealed archive plus the harness-private draws behind it."""

    archive: SealedArchive
    draws: dict = field(default_factory=dict)
    templates: dict = field(default_factory=dict)


def build_archive(seed: int, scenario, cfg: CorpusConfig) -> BuiltCorpus:
    """Generate, label, damage, seal — then hand back evidence only."""
    rng = random.Random(
        (seed * 7717) ^ zlib.crc32(f"{scenario.name}:{cfg.name}".encode("utf-8")))
    count = max(24, int(cfg.count * scenario.corpus_scale))

    rows = []
    draws = {}
    for index in range(count):
        draw = _draw(rng, scenario, index)
        sequence_id = f"lb2-{scenario.name}-{cfg.name}-{index:05d}"
        events = _damage(rng, _materialise(draw, sequence_id, cfg, index),
                         scenario)
        rows.extend(events)
        draws[sequence_id] = draw

    trajectories = build_trajectories(normalise_events(rows))

    # The outcome is decided here, once, and the trajectory becomes history.
    labelled = []
    for trajectory in trajectories:
        outcome = scenario.outcome(trajectory, draws[trajectory.sequence_id])
        labelled.append(type(trajectory)(
            sequence_id=trajectory.sequence_id,
            events=tuple(replace(event, trajectory_outcome=outcome)
                         for event in trajectory.events)))

    entries = []
    for trajectory in labelled:
        sealed_record = hashlib.sha256(json.dumps(
            canonical_record(trajectory), sort_keys=True,
            default=str).encode("utf-8")).hexdigest()
        entry = SealedTrajectory(trajectory=trajectory, seal=sealed_record,
                                 sealed_record=sealed_record)
        if scenario.corrupt_seals and rng.random() < scenario.corrupt_seals:
            # Tamper AFTER sealing: the stored digest no longer matches the
            # record, which is exactly what a seal exists to reveal.
            entry = SealedTrajectory(
                trajectory=trajectory, seal=sealed_record,
                sealed_record="0" * 64)
        entries.append(entry)

    chain_head = hashlib.sha256("".join(
        entry.sealed_record for entry in entries).encode("utf-8")).hexdigest()

    archive = SealedArchive(
        archive_id=f"{scenario.name}:{cfg.name}",
        entries=tuple(entries), chain_head=chain_head[:32],
        provenance={"dataset_version": LB2_DATASET_VERSION,
                    "partition": cfg.name, "sealed": True})
    return BuiltCorpus(archive=archive, draws=draws,
                       templates={sid: d.template for sid, d in draws.items()})


def build_archives(seed: int, scenario, corpora=DEFAULT_CORPORA) -> dict:
    """Every partition for one scenario, sealed.

    The returned mapping holds archives. The `Scenario` is not part of it, and
    the caller is expected to drop its reference — `run_lb2` does, and
    `tests/test_lb2_isolation.py` checks the analysis path never receives one.
    """
    return {cfg.name: build_archive(seed, scenario, cfg) for cfg in corpora}


def dataset_manifest(seed: int, built: dict) -> dict:
    return {
        "dataset_version": LB2_DATASET_VERSION,
        "seed": seed,
        "templates": len(TEMPLATES),
        "timing_profiles": 2,
        "collection_periods": len(_PERIODS),
        "partitions": {name: corpus.archive.manifest()
                       for name, corpus in sorted(built.items())},
    }
