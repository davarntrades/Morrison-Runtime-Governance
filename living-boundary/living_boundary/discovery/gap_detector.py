"""Ontology gap detection.

The question this module answers is narrow and measurable:

    Are there unsafe outcomes that the CURRENT ontology cannot represent?

Not "are there unsafe outcomes it failed to catch" — a rule can miss something
it is perfectly capable of expressing. The gap claim needs the stronger form,
so two independent signals are required before a gap is declared:

  SIGNAL 1 — UNEXPLAINED RESIDUAL.
      Trajectories whose outcome was unsafe, where EVERY individual step was
      permitted by per-action policy AND no existing primitive matched. The
      ontology has nothing to say about these, not merely the wrong thing.

  SIGNAL 2 — SIGNATURE COLLISION.
      Trajectories that are indistinguishable at the level the ontology
      operates on — the same multiset of (capability, domain) pairs — but that
      ended with different outcomes. This is what makes the residual a
      REPRESENTATION failure rather than a labelling accident: no per-action
      ontology, however well tuned, can separate two trajectories it cannot
      tell apart.

Signal 1 alone would fire on ordinary model error. Signal 2 alone would fire on
noise. Requiring both is the difference between "a missing concept" and "a
miss", which is precisely the distinction LB-1 will later have to make in
general and which LB-0 must at least not confuse.

The detector never sees the hidden rule. Everything below is computed from
observed outcomes and the baseline's own decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class OntologyGap:
    """A measured coverage gap in the current ontology."""

    gap_id: str
    detected: bool
    confidence: float
    reason: str
    supporting_trace_ids: tuple = ()
    supporting_sequence_ids: tuple = ()
    affected_domains: tuple = ()
    existing_primitives_insufficient: tuple = ()
    residual_unsafe: int = 0
    total_unsafe: int = 0
    signature_collisions: int = 0
    colliding_signatures: int = 0
    status: str = "experimental"
    metrics: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "gap_id": self.gap_id,
            "detected": self.detected,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
            "supporting_sequence_ids": list(self.supporting_sequence_ids),
            "supporting_trace_ids": list(self.supporting_trace_ids),
            "affected_domains": list(self.affected_domains),
            "existing_primitives_insufficient": list(
                self.existing_primitives_insufficient),
            "residual_unsafe": self.residual_unsafe,
            "total_unsafe": self.total_unsafe,
            "signature_collisions": self.signature_collisions,
            "colliding_signatures": self.colliding_signatures,
            "status": self.status,
            "metrics": dict(self.metrics),
        }


def _signature(trajectory) -> tuple:
    """What the trajectory looks like to a per-action ontology.

    A sorted multiset of (capability, domain) pairs: the ontology's own
    vocabulary, with order, identity, scope, boundary and data lineage removed —
    exactly the information a per-action classifier does not use.
    """
    return tuple(sorted((e.capability, e.domain) for e in trajectory.events))


def detect_gap(trajectories, ontology, gap_id: str = "gap_001",
               min_residual: int = 15, min_residual_rate: float = 0.25) -> OntologyGap:
    """Detect whether `ontology` structurally fails to represent observed harm.

    `min_residual` and `min_residual_rate` are declared thresholds, not tuned
    ones: a handful of unexplained trajectories is indistinguishable from noise,
    and a residual that is a small fraction of all unsafe outcomes is a gap in
    coverage rather than in representation.
    """
    decisions = ontology.evaluate_all(trajectories)

    unsafe = [t for t in trajectories if t.is_unsafe_observed]
    residual = [t for t in unsafe
                if not decisions[t.sequence_id].predicted_unsafe
                and t.all_steps_allowed]

    # ── signal 2: same ontology-visible signature, different outcome ──
    by_signature: dict = {}
    for t in trajectories:
        by_signature.setdefault(_signature(t), []).append(t)
    colliding_signatures = 0
    collisions = 0
    residual_ids = {t.sequence_id for t in residual}
    for group in by_signature.values():
        outcomes = {t.outcome for t in group}
        if len(outcomes) > 1:
            colliding_signatures += 1
            collisions += sum(1 for t in group if t.sequence_id in residual_ids)

    # ── which existing primitives were closest but insufficient ──
    fired_on_unsafe: dict = {}
    for t in unsafe:
        for name in decisions[t.sequence_id].matched_primitives:
            fired_on_unsafe[name] = fired_on_unsafe.get(name, 0) + 1
    insufficient = tuple(sorted(ontology.primitive_names()))

    # ── which domains the unexplained trajectories are concentrated in ──
    residual_domains: dict = {}
    for t in residual:
        for domain in set(t.domains):
            residual_domains[domain] = residual_domains.get(domain, 0) + 1
    threshold = max(1, int(0.5 * len(residual)))
    affected = tuple(sorted(d for d, c in residual_domains.items() if c >= threshold))

    total_unsafe = len(unsafe)
    residual_rate = (len(residual) / total_unsafe) if total_unsafe else 0.0
    detected = (len(residual) >= min_residual
                and residual_rate >= min_residual_rate
                and collisions > 0)

    if detected:
        reason = (
            "{} unsafe trajectories ({:.1%} of all observed harm) were composed "
            "entirely of individually permitted actions and matched no primitive "
            "in {}; {} of them are indistinguishable from safe trajectories at "
            "the (capability, domain) level the ontology operates on, so no "
            "per-action refinement of the existing primitives can separate "
            "them".format(len(residual), residual_rate, ontology.version,
                          collisions))
    else:
        reason = (
            "no representation gap declared: {} unexplained unsafe trajectories "
            "({:.1%} of harm), {} signature collisions — thresholds are >= {} "
            "residual, >= {:.0%} of harm, and at least one collision".format(
                len(residual), residual_rate, collisions, min_residual,
                min_residual_rate))

    return OntologyGap(
        gap_id=gap_id,
        detected=detected,
        confidence=residual_rate,
        reason=reason,
        supporting_sequence_ids=tuple(t.sequence_id for t in residual),
        supporting_trace_ids=tuple(tid for t in residual for tid in t.trace_ids),
        affected_domains=affected,
        existing_primitives_insufficient=insufficient,
        residual_unsafe=len(residual),
        total_unsafe=total_unsafe,
        signature_collisions=collisions,
        colliding_signatures=colliding_signatures,
        metrics={
            "trajectories": len(trajectories),
            "residual_rate": round(residual_rate, 4),
            "baseline_ontology_version": ontology.version,
            "primitives_that_fired_on_unsafe": dict(sorted(fired_on_unsafe.items())),
            "min_residual": min_residual,
            "min_residual_rate": min_residual_rate,
        })


def residual_trajectories(trajectories, ontology) -> list:
    """The trajectories the baseline predicts SAFE — the fit set for discovery.

    Discovery is fitted here rather than on the whole corpus because a new
    primitive is a COMPLEMENT to the ontology, not a replacement for it. The
    combined predictor is `baseline OR candidate`, so what the candidate has to
    explain is exactly what the baseline leaves behind.
    """
    decisions = ontology.evaluate_all(trajectories)
    return [t for t in trajectories if not decisions[t.sequence_id].predicted_unsafe]
