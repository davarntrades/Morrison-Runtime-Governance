"""Competing explanations, fitted and transferred on exactly the same terms.

THE QUESTION THESE ANSWER

If the structural candidate transfers, the immediate objection is that something
cheaper would have transferred too — that the environments, for all their
renaming, left some simpler regularity intact. An experiment that only tests its
preferred representation cannot answer that objection, so ten alternatives are
fitted here, each one a story somebody could reasonably tell about why a
trajectory went wrong:

    token_literal        a particular capability@domain@boundary step occurred
    tool_identity        a particular TOOL was used, and in a particular order
    provider_identity    the provider or region
    session_metadata     provider, region and session tag together — the
                         surface correlation LB-0 was built to be trapped by
    domain_identity      which governance domains were touched
    capability_domain    capability and domain combinations
    event_frequency      how many times a capability occurred
    trace_length         how long the trajectory was
    positional           what happened first and what happened last
    nearest_neighbour    the outcome of the most similar discovery trajectory

Every one of them is fitted on the discovery environment with the same search,
frozen the same way, and evaluated on the same corpora. If any of them retains
as much as the structural candidate, LB-3 must not claim structural invariance,
because the evidence is equally consistent with the cheaper story.

WHY `nearest_neighbour` IS INCLUDED EVEN THOUGH IT CANNOT WIN

It is the strongest form of "the target environment just looks like the source
one". Its retention across a genuine vocabulary change should be zero by
construction — Jaccard similarity between two disjoint vocabularies is zero —
and if it is NOT zero somewhere, that is a leak in the environment construction
and needs finding before any other number is believed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.discovery.features import feature_set
from living_boundary.observer.normalizer import BOUNDARY_INTERNAL
from living_boundary.representation.refit import fit_conjunction

SEP = "::"
ARG = "|"


def _family(name: str) -> str:
    return name.partition(SEP)[0]


def _restricted(families):
    keep = frozenset(families)

    def _features(trajectory):
        return {name for name in feature_set(trajectory) if _family(name) in keep}
    return _features


def _tool_identity(trajectory) -> set:
    actions = [e.action for e in trajectory.events]
    names = {f"tool{SEP}{action}" for action in actions}
    for index, left in enumerate(actions):
        for right in actions[index + 1:]:
            names.add(f"tool_ord2{SEP}{left}{ARG}{right}")
    return names


def _event_frequency(trajectory) -> set:
    counts: dict = {}
    for event in trajectory.events:
        counts[event.capability] = counts.get(event.capability, 0) + 1
    names = set()
    for capability, count in counts.items():
        for threshold in range(1, min(count, 4) + 1):
            names.add(f"freq{SEP}{capability}{ARG}{threshold}")
    return names


def _trace_length(trajectory) -> set:
    count = len(trajectory.events)
    return {f"len_ge{SEP}{k}" for k in range(2, 10) if count >= k} | {
        f"len_le{SEP}{k}" for k in range(2, 10) if count <= k}


def _positional(trajectory) -> set:
    events = trajectory.events
    if not events:
        return set()

    def _slot(event):
        return ("internal" if event.trust_boundary == BOUNDARY_INTERNAL
                else "crossing")
    names = {f"first{SEP}{_slot(events[0])}", f"last{SEP}{_slot(events[-1])}"}
    names.add(f"first_cap{SEP}{events[0].capability}")
    names.add(f"last_cap{SEP}{events[-1].capability}")
    names.add(f"ends_outside{SEP}{_slot(events[-1]) == 'crossing'}")
    return names


class _NearestNeighbour:
    """1-NN over Jaccard similarity of the surface feature set.

    Deliberately the crudest possible "this looks like something I have seen"
    model. Ties break towards `safe`, so it cannot win a tie by luck.
    """

    def __init__(self, trajectories, labels):
        self.reference = [(feature_set(t), label)
                          for t, label in zip(trajectories, labels)]

    def __call__(self, trajectory) -> bool:
        target = feature_set(trajectory)
        best_score, best_label = -1.0, False
        for names, label in self.reference:
            union = len(target | names)
            score = (len(target & names) / union) if union else 0.0
            if score > best_score:
                best_score, best_label = score, label
        return bool(best_label)


@dataclass
class Hypothesis:
    """One competing explanation and how to fit it."""

    name: str
    description: str
    feature_fn: object = None
    instance_based: bool = False
    literals: tuple = field(default_factory=tuple)

    def fit(self, trajectories, labels):
        """Return `(predictor, literals)` for this hypothesis."""
        if self.instance_based:
            return _NearestNeighbour(trajectories, labels), ()
        refit = fit_conjunction(trajectories, labels, self.feature_fn)

        def _predict(trajectory, _refit=refit, _fn=self.feature_fn):
            return _refit.predict(_fn(trajectory))
        return _predict, tuple(refit.literals)


HYPOTHESES = (
    Hypothesis("token_literal",
               "a particular capability@domain@boundary step occurred",
               feature_fn=_restricted(("has_token", "order2", "order3"))),
    Hypothesis("tool_identity",
               "a particular tool was used, in a particular order",
               feature_fn=_tool_identity),
    Hypothesis("provider_identity", "the provider or region",
               feature_fn=_restricted(("provider", "region"))),
    Hypothesis("session_metadata",
               "provider, region and session tag together",
               feature_fn=_restricted(("provider", "region", "session_tag"))),
    Hypothesis("domain_identity", "which governance domains were touched",
               feature_fn=_restricted(("has_domain",))),
    Hypothesis("capability_domain", "capability and domain combinations",
               feature_fn=_restricted(("has_cap", "has_domain", "has_boundary"))),
    Hypothesis("event_frequency", "how many times a capability occurred",
               feature_fn=_event_frequency),
    Hypothesis("trace_length", "how long the trajectory was",
               feature_fn=_trace_length),
    Hypothesis("positional", "what happened first and what happened last",
               feature_fn=_positional),
    Hypothesis("nearest_neighbour",
               "the outcome of the most similar discovery trajectory",
               instance_based=True),
)
