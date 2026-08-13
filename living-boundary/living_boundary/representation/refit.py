"""A compact conjunction search, used to CHECK a localisation rather than to
make a discovery.

WHY THIS EXISTS SEPARATELY FROM `discovery/structure_discovery.py`

Two reasons, and the second is the important one.

  · LB-0's search is frozen. It is the artifact of a completed, reviewed
    experiment, and its beam is hard-wired to the LB-0 feature grammar.
    Threading an alternative feature function through it would edit a module
    whose behaviour a merged experiment depends on.

  · This search answers a different question. LB-0's had to survive
    confounders, ablation and a held-out set; this one only has to answer "if
    the proposed observable really is the missing one, does reading it recover
    the outcome?". It is a MEASUREMENT INSTRUMENT for the localisation, not a
    discovery mechanism, and conflating the two would let a strong refit stand
    in for evidence it has not earned.

It operates over feature-set membership directly, because an extension family
produces names the LB-0 literal grammar cannot parse back into predicates.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.evaluation.metrics import confusion


def _popcount_fallback(value: int) -> int:
    return bin(value).count("1")


_popcount = getattr(int, "bit_count", None) or _popcount_fallback


def _f1(mask: int, positives: int, positive_count: int) -> float:
    tp = _popcount(mask & positives)
    predicted = _popcount(mask)
    if not predicted or not positive_count:
        return 0.0
    precision = tp / predicted
    recall = tp / positive_count
    return (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0


@dataclass
class Refit:
    """A conjunction over feature names, plus how it scored."""

    literals: tuple = ()
    train: dict = field(default_factory=dict)
    held_out: dict = field(default_factory=dict)

    def predict(self, names) -> bool:
        for literal in self.literals:
            if literal.startswith("NOT "):
                if literal[4:] in names:
                    return False
            elif literal not in names:
                return False
        return bool(self.literals)

    def as_dict(self) -> dict:
        return {"literals": list(self.literals), "train": dict(self.train),
                "held_out": dict(self.held_out)}


def _build(sets, min_support: int):
    counts: dict = {}
    for names in sets:
        for name in names:
            counts[name] = counts.get(name, 0) + 1
    total = len(sets)
    masks: dict = {}
    full = (1 << total) - 1
    for name in sorted(counts):
        positive = counts[name]
        if positive < min_support or (total - positive) < min_support:
            continue
        mask = 0
        for index, names in enumerate(sets):
            if name in names:
                mask |= 1 << index
        masks[name] = mask
        masks[f"NOT {name}"] = full ^ mask
    return masks, full


def fit_conjunction(trajectories, labels, feature_fn, min_support: int = 10,
                    beam_width: int = 24, max_depth: int = 6) -> Refit:
    """Greedy beam search for a conjunction separating `labels`.

    Deterministic: candidates are ordered by F1, then length, then name.
    """
    sets = [feature_fn(t) for t in trajectories]
    masks, full = _build(sets, min_support)
    positives = 0
    for index, is_positive in enumerate(labels):
        if is_positive:
            positives |= 1 << index
    positive_count = _popcount(positives)
    if not positive_count or not masks:
        return Refit()

    names = sorted(masks)
    beam = [((), full, 0.0)]
    best = ((), full, 0.0)
    seen = set()

    for _ in range(max_depth):
        grown = []
        for chosen, mask, _previous in beam:
            chosen_set = set(chosen)
            for name in names:
                if name in chosen_set:
                    continue
                counterpart = name[4:] if name.startswith("NOT ") else f"NOT {name}"
                if counterpart in chosen_set:
                    continue
                new_mask = mask & masks[name]
                if new_mask == mask or _popcount(new_mask) < min_support:
                    continue
                key = frozenset(chosen + (name,))
                if key in seen:
                    continue
                seen.add(key)
                score = _f1(new_mask, positives, positive_count)
                if score <= 0.0:
                    continue
                grown.append((tuple(sorted(chosen + (name,))), new_mask, score))
        if not grown:
            break
        grown.sort(key=lambda row: (-row[2], len(row[0]), row[0]))
        if grown[0][2] > best[2]:
            best = grown[0]
        beam = grown[:beam_width]

    refit = Refit(literals=best[0])
    refit.train = _score(refit, trajectories, labels, feature_fn)
    return refit


def _score(refit, trajectories, labels, feature_fn) -> dict:
    predictions = [refit.predict(feature_fn(t)) for t in trajectories]
    return confusion(predictions, list(labels)).as_dict()


def evaluate_refit(refit, trajectories, labels, feature_fn) -> dict:
    return _score(refit, trajectories, labels, feature_fn)
