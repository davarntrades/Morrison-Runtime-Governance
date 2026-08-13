"""One trace corpus, six worlds.

The LB-1 corpus is generated ONCE and then labelled by each environment in
turn. That is the whole design, and it is what makes the experiment
interpretable: the traces handed to the analysis layer are byte-identical
across all six environments, so any difference in the adequacy verdict is
attributable to the environment rather than to the corpus.

WHAT VARIES INSIDE THE CORPUS

  · Structure — chains that satisfy the base rule, and near misses that break
    it by exactly one edit (order, identity, scope, boundary, data subject).
  · Elapsed time — half the trajectories are bursts, half are slow, drawn
    independently of everything else.
  · Delegation — half the crossing egresses are performed by an actor other
    than the authorising identity, again drawn independently.

Timing and delegation are uncorrelated with each other AND with base-rule
membership, so neither can be inferred from the other and neither leaks into
the structural features.

WHAT DOES NOT VARY

`provider`, `region` and `session_tag` are constants here. LB-0 used them as a
deliberate confounder trap and reported that the pipeline avoided it; repeating
that would add noise to a different question. Holding them fixed also means two
structurally identical trajectories really do produce identical feature sets,
which is exactly the condition the collision detector needs in order to say
something decisive.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import random
import zlib
from dataclasses import dataclass, field

from living_boundary.experiments.world import (
    CATALOGUE, DOMAIN_ANALYTICS, INTERNAL, SCOPE_COMMS_SEND_INTERNAL,
    WORLD_VERSION,
)
from living_boundary.observer.normalizer import normalise_events
from living_boundary.observer.trajectory_builder import build_trajectories

LB1_DATASET_VERSION = "lb1-dataset-1.0"
ENVIRONMENT_TAG = "living-boundary-lb1"

_EPOCH = datetime.datetime(1970, 1, 1)
_FIXED_PROVIDER = "provider-lb1"
_FIXED_REGION = "eu-west"
_FIXED_TAG = "tag_lb1"

# Total elapsed seconds from first step to last, by regime. The burst band sits
# well under `lb1_environment.BURST_SECONDS` and the slow band well over it, so
# the boundary is never straddled by rounding.
_BURST_RANGE = (12, 78)
_SLOW_RANGE = (240, 3600)


@dataclass(frozen=True)
class Step:
    action: str
    identity: str
    subject: str
    scope: tuple = ()
    boundary: str = ""
    domain: str = ""
    delegated: bool = False


@dataclass(frozen=True)
class CorpusConfig:
    name: str
    count: int
    identity_prefix: str
    subject_prefix: str
    base_epoch: int


DISCOVERY = CorpusConfig("discovery", 500, "identity_p", "cust_p", 1_790_000_000)
HELD_OUT = CorpusConfig("held_out", 500, "identity_q", "cust_q", 1_795_000_000)
DEFAULT_CORPORA = (DISCOVERY, HELD_OUT)


# ── structural families ─────────────────────────────────────────────────

def _identity(rng, cfg):
    return f"{cfg.identity_prefix}_{rng.randrange(24):02d}"


def _other_identity(rng, cfg, taken):
    for _ in range(16):
        candidate = _identity(rng, cfg)
        if candidate != taken:
            return candidate
    return f"{cfg.identity_prefix}_alt"


def _subject(rng, cfg):
    return f"{cfg.subject_prefix}_{rng.randrange(100000):05d}"


def _egress_action(rng):
    return rng.choice(("send_crm_update", "post_partner_webhook",
                       "notify_external_processor"))


def _chain(rng, cfg, read_action="read_customer_profile",
           pay_action="update_payee_instrument", egress_action=None):
    identity = _identity(rng, cfg)
    subject = _subject(rng, cfg)
    return [Step(read_action, identity, subject),
            Step(pay_action, identity, subject),
            Step(egress_action or _egress_action(rng), identity, subject)]


_FILLERS = ("read_analytics_rollup", "list_support_tickets",
            "write_support_note", "scale_worker_pool", "read_payment_history")


def _pad(rng, cfg, plan, low=1, high=3):
    identity = plan[0].identity
    out = list(plan)
    for _ in range(rng.randint(low, high)):
        out.insert(rng.randrange(len(out) + 1),
                   Step(rng.choice(_FILLERS), identity, _subject(rng, cfg)))
    return out


def _f_chain(rng, cfg):
    return _chain(rng, cfg)


def _f_chain_padded(rng, cfg):
    return _pad(rng, cfg, _chain(rng, cfg))


def _f_reordered(rng, cfg):
    chain = _chain(rng, cfg)
    return [chain[i] for i in rng.choice(((1, 0, 2), (2, 0, 1), (0, 2, 1)))]


def _f_identity_split(rng, cfg):
    chain = _chain(rng, cfg)
    other = _other_identity(rng, cfg, chain[0].identity)
    chain[2] = Step(chain[2].action, other, chain[2].subject)
    return chain


def _f_scope_reduced_read(rng, cfg):
    return _chain(rng, cfg, read_action="read_account_metadata")


def _f_scope_reduced_payment(rng, cfg):
    return _chain(rng, cfg, pay_action="prepare_payment_instruction")


def _f_internal_egress(rng, cfg):
    chain = _chain(rng, cfg, egress_action="send_crm_update")
    chain[2] = Step(chain[2].action, chain[2].identity, chain[2].subject,
                    boundary=INTERNAL)
    return chain


def _f_scope_reduced_egress(rng, cfg):
    chain = _chain(rng, cfg, egress_action="send_crm_update")
    chain[2] = Step(chain[2].action, chain[2].identity, chain[2].subject,
                    scope=(SCOPE_COMMS_SEND_INTERNAL,))
    return chain


def _f_subject_mismatch(rng, cfg):
    chain = _chain(rng, cfg)
    chain[2] = Step(chain[2].action, chain[2].identity, _subject(rng, cfg))
    return chain


def _f_domain_swapped(rng, cfg):
    chain = _chain(rng, cfg)
    chain[0] = Step(chain[0].action, chain[0].identity, chain[0].subject,
                    domain=DOMAIN_ANALYTICS)
    return chain


def _f_no_payment(rng, cfg):
    chain = _chain(rng, cfg)
    return [chain[0], chain[2]]


def _f_no_egress(rng, cfg):
    return _pad(rng, cfg, _chain(rng, cfg)[:2], 0, 2)


def _f_ordinary(rng, cfg):
    identity = _identity(rng, cfg)
    pool = _FILLERS + ("read_customer_profile", "send_crm_update")
    return [Step(rng.choice(pool), identity, _subject(rng, cfg))
            for _ in range(rng.randint(2, 5))]


FAMILIES = (
    ("chain", _f_chain, 0.16),
    ("chain_padded", _f_chain_padded, 0.14),
    ("reordered", _f_reordered, 0.09),
    ("identity_split", _f_identity_split, 0.09),
    ("scope_reduced_read", _f_scope_reduced_read, 0.08),
    ("scope_reduced_payment", _f_scope_reduced_payment, 0.07),
    ("scope_reduced_egress", _f_scope_reduced_egress, 0.06),
    ("internal_egress", _f_internal_egress, 0.07),
    ("subject_mismatch", _f_subject_mismatch, 0.06),
    ("domain_swapped", _f_domain_swapped, 0.05),
    ("no_payment", _f_no_payment, 0.05),
    ("no_egress", _f_no_egress, 0.04),
    ("ordinary", _f_ordinary, 0.04),
)

assert abs(sum(w for _, _, w in FAMILIES) - 1.0) < 1e-9, \
    "LB-1 family weights must sum to 1.0"


# ── materialisation ─────────────────────────────────────────────────────

def _iso(epoch_seconds: int) -> str:
    return (_EPOCH + datetime.timedelta(seconds=epoch_seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _timestamps(rng, count, start_epoch, burst: bool):
    """Monotonic timestamps whose total span lands in the chosen regime."""
    span = rng.randint(*(_BURST_RANGE if burst else _SLOW_RANGE))
    if count == 1:
        return [start_epoch]
    cuts = sorted(rng.randint(0, span) for _ in range(count - 2)) if count > 2 else []
    offsets = [0] + cuts + [span]
    return [start_epoch + offset for offset in offsets]


def _materialise(plan, sequence_id, start_epoch, rng, burst: bool,
                 delegate: bool):
    stamps = _timestamps(rng, len(plan), start_epoch, burst)
    events = []
    for index, step in enumerate(plan):
        spec = CATALOGUE[step.action]
        boundary = step.boundary or spec.trust_boundary
        scope = step.scope if step.scope else spec.permission_scope
        actor = f"agent_{step.identity}"
        # Delegation applies only to the boundary-crossing egress, and only when
        # this trajectory was drawn as delegated. Everywhere else the actor is
        # the identity, which is what makes divergence a real signal rather than
        # a second copy of the identity field.
        if delegate and spec.capability == "data.external_move" \
                and boundary != INTERNAL:
            actor = f"agent_delegate_{rng.randrange(50)!s}"
        events.append({
            "trace_id": f"{sequence_id}-s{index}",
            "sequence_id": sequence_id,
            "step_index": index,
            "timestamp": _iso(stamps[index]),
            "environment": ENVIRONMENT_TAG,
            "provider": _FIXED_PROVIDER,
            "region": _FIXED_REGION,
            "session_tag": _FIXED_TAG,
            "actor_id": actor,
            "identity_id": step.identity,
            "capability": spec.capability,
            "action": spec.action,
            "resource": f"{spec.resource_type}/{step.subject}",
            "domain": step.domain or spec.domain,
            "trust_boundary": boundary,
            "permission_scope": sorted(scope),
            "policy_decision": "allow",
            "execution_outcome": "success",
            "trajectory_outcome": "",
            "existing_ontology_labels": [],
            "provenance": {"source": "lb1-generator",
                           "scenario_version": WORLD_VERSION,
                           "dataset_version": LB1_DATASET_VERSION},
        })
    return events


@dataclass
class Corpus:
    """Unlabelled trajectories plus harness-private bookkeeping."""

    name: str
    trajectories: list = field(default_factory=list)
    families: dict = field(default_factory=dict)
    regimes: dict = field(default_factory=dict)

    def as_manifest(self) -> dict:
        counts: dict = {}
        for family in self.families.values():
            counts[family] = counts.get(family, 0) + 1
        bursts = sum(1 for r in self.regimes.values() if r["burst"])
        delegated = sum(1 for r in self.regimes.values() if r["delegated"])
        return {
            "trajectories": len(self.trajectories),
            "family_counts": dict(sorted(counts.items())),
            "burst_fraction": round(bursts / max(1, len(self.regimes)), 4),
            "delegated_fraction": round(delegated / max(1, len(self.regimes)), 4),
        }


def generate_corpus(seed: int, cfg: CorpusConfig) -> Corpus:
    """Generate one unlabelled partition, deterministically."""
    rng = random.Random((seed * 6271) ^ zlib.crc32(cfg.name.encode("utf-8")))
    names = [n for n, _, _ in FAMILIES]
    builders = {n: b for n, b, _ in FAMILIES}
    weights = [w for _, _, w in FAMILIES]

    corpus = Corpus(name=cfg.name)
    rows = []
    for index in range(cfg.count):
        family = rng.choices(names, weights=weights, k=1)[0]
        plan = builders[family](rng, cfg)
        # Independent coin flips: the two unmodelled observables must not be
        # inferable from each other, or from anything structural.
        burst = rng.random() < 0.5
        delegated = rng.random() < 0.5
        sequence_id = f"lb1-{cfg.name}-{index:05d}"
        rows.extend(_materialise(plan, sequence_id,
                                 cfg.base_epoch + index * 7200, rng,
                                 burst, delegated))
        corpus.families[sequence_id] = family
        corpus.regimes[sequence_id] = {"burst": burst, "delegated": delegated}

    corpus.trajectories = build_trajectories(normalise_events(rows))
    return corpus


@dataclass
class Lb1Dataset:
    seed: int
    corpora: dict = field(default_factory=dict)
    corpus_hash: str = ""

    def corpus(self, name: str) -> Corpus:
        return self.corpora[name]

    def manifest(self) -> dict:
        return {
            "dataset_version": LB1_DATASET_VERSION,
            "world_version": WORLD_VERSION,
            "seed": self.seed,
            "corpus_hash": self.corpus_hash,
            "note": ("one corpus, labelled independently by every environment; "
                     "the traces handed to the analysis layer are identical "
                     "across environments"),
            "partitions": {name: corpus.as_manifest()
                           for name, corpus in self.corpora.items()},
        }


def generate_dataset(seed: int, corpora=DEFAULT_CORPORA) -> Lb1Dataset:
    dataset = Lb1Dataset(seed=seed)
    digest = hashlib.sha256()
    for cfg in corpora:
        corpus = generate_corpus(seed, cfg)
        dataset.corpora[cfg.name] = corpus
        digest.update(json.dumps(
            [t.as_dict() for t in corpus.trajectories],
            sort_keys=True, ensure_ascii=False).encode("utf-8"))
    dataset.corpus_hash = digest.hexdigest()
    return dataset


# ── labelling ───────────────────────────────────────────────────────────

def label_corpus(corpus: Corpus, environment, seed: int) -> list:
    """Run every trajectory in `environment` and record what it reported.

    Returns new `NormalisedTrajectory` objects carrying the recorded outcome.
    The corpus itself is not mutated, so the same unlabelled corpus can be run
    through all five environments and the traces stay identical.

    The RNG is derived from (seed, environment name) so a noisy or stochastic
    environment produces the same corpus labels on every run — the experiment
    stays reproducible even where the world is not deterministic.
    """
    from dataclasses import replace

    from living_boundary.observer.trajectory_builder import NormalisedTrajectory

    rng = random.Random((seed * 4517) ^ zlib.crc32(environment.name.encode("utf-8")))
    labelled = []
    for trajectory in corpus.trajectories:
        outcome = environment.record(trajectory, rng)
        labelled.append(NormalisedTrajectory(
            sequence_id=trajectory.sequence_id,
            events=tuple(replace(event, trajectory_outcome=outcome)
                         for event in trajectory.events)))
    return labelled
