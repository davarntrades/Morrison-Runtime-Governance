"""Structure search: find an interpretable conjunction that separates outcomes.

METHOD

Beam search over conjunctions of literals from `features.py`, scored by F1
against the observed outcome on the FIT set. Deterministic throughout: no RNG,
no model call, no tie broken by dict order.

WHY THIS AND NOT A MODEL

LB-0's stated failure mode is "candidate primitives are merely linguistic
descriptions". A conjunction of named literals is the opposite of that: it is a
predicate that can be run against trajectories it has never seen, ablated one
literal at a time, and reported in full. There is no LLM anywhere in this
pipeline, so there is no step at which a persuasive explanation could stand in
for a prediction. (If a model is added later, the blueprint's requirement is
that the evidence evaluator stays independent of the generator — which is why
`evaluation/` imports nothing from `discovery/`.)

THE OBJECTIVE IS AGREEMENT ACROSS TWO INDEPENDENT CORPORA

A conjunction is scored by the WORSE of its F1 on the discovery split and its F1
on the validation split, and it must clear the support floor on both. Held-out
is not touched here or anywhere else during generation; it is consulted exactly
once, at the very end.

This is not a convenience. It is forced, and the first implementation of this
module demonstrated why by failing.

`session_tag::tag_hot` is session metadata with no causal relationship to
anything, and in the discovery split it separates safe from unsafe PERFECTLY.
Scored on discovery alone it is not merely competitive with the real structure —
it is strictly better than it, and so is every near-perfect combination built
from it. A beam ordered by discovery F1 fills with confounder variants, evicts
every structural branch, and hands selection a pool that never contained the
answer. Measured: a one-literal candidate, failed falsification, held-out
false-positive rate 0.39.

The general statement is that INSIDE a corpus where a confounder is perfectly
correlated with the outcome, the confounder and the true structure are the same
function, and no amount of searching that corpus can separate them. A second,
independently generated corpus — in which the surface correlations differ — is
the only thing that can. So the second corpus enters at search time rather than
only at selection time.

Two guards keep this from becoming a way to launder the held-out result:

  · The validation split is part of CANDIDATE GENERATION and is described that
    way everywhere in the output. Nothing claims it is an unseen measurement.
  · Held-out is generated from disjoint surface pools and is read once, after
    the candidate is frozen. Every number that supports the verdict comes from
    it.

SOLVED CONJUNCTIONS ARE TERMINAL

A conjunction already scoring a perfect joint F1 is recorded in the pool but
never extended: additional literals can only shrink its coverage. This keeps the
beam spending its budget on branches that are still unsolved.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.discovery.features import (
    SURFACE_FAMILIES, build_literals, literal_from_name, masks_for,
)


_EPSILON = 1e-9


def _popcount_fallback(value: int) -> int:
    return bin(value).count("1")


# `int.bit_count()` is 3.10+ and roughly an order of magnitude faster on the
# 900-bit masks this search manipulates; the repository's lint matrix still
# includes 3.8, so it is selected at import rather than assumed.
_popcount = getattr(int, "bit_count", None)
if _popcount is None:                                  # pragma: no cover - 3.8/3.9
    _popcount = _popcount_fallback


def _f1_from_masks(mask: int, positives: int, positive_count: int):
    """(f1, precision, recall, tp, fp, fn) for a predicted-set bitmask."""
    tp = _popcount(mask & positives)
    predicted = _popcount(mask)
    fp = predicted - tp
    fn = positive_count - tp
    precision = tp / predicted if predicted else 0.0
    recall = tp / positive_count if positive_count else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return f1, precision, recall, tp, fp, fn


@dataclass(frozen=True)
class DiscoveredStructure:
    """One conjunction, with the metrics it achieved where it was measured."""

    literal_names: tuple
    fit_f1: float = 0.0
    fit_precision: float = 0.0
    fit_recall: float = 0.0
    fit_support: int = 0
    guard_f1: float = 0.0
    joint_f1: float = 0.0
    selection_metrics: dict = field(default_factory=dict)

    @property
    def key(self) -> frozenset:
        return frozenset(self.literal_names)

    @property
    def uses_surface_features(self) -> bool:
        """True if any literal reads session metadata rather than structure."""
        return any(name.replace("NOT ", "").partition("::")[0] in SURFACE_FAMILIES
                   for name in self.literal_names)

    def as_dict(self) -> dict:
        return {
            "literals": list(self.literal_names),
            "fit_f1": round(self.fit_f1, 4),
            "fit_precision": round(self.fit_precision, 4),
            "fit_recall": round(self.fit_recall, 4),
            "fit_support": self.fit_support,
            "guard_f1": round(self.guard_f1, 4),
            "joint_f1": round(self.joint_f1, 4),
            "uses_surface_features": self.uses_surface_features,
            "selection_metrics": dict(self.selection_metrics),
        }


@dataclass
class SearchReport:
    """Everything the search did, for the evidence package."""

    pool: list = field(default_factory=list)
    literals_considered: int = 0
    conjunctions_evaluated: int = 0
    min_support: int = 0
    beam_width: int = 0
    max_depth: int = 0

    def as_dict(self) -> dict:
        return {
            "literals_considered": self.literals_considered,
            "conjunctions_evaluated": self.conjunctions_evaluated,
            "pool_size": len(self.pool),
            "min_support": self.min_support,
            "beam_width": self.beam_width,
            "max_depth": self.max_depth,
            "best_on_fit": [s.as_dict() for s in self.pool[:5]],
        }


def _positive_mask(labels):
    mask = 0
    for index, is_positive in enumerate(labels):
        if is_positive:
            mask |= 1 << index
    return mask, _popcount(mask)


def search_structures(trajectories, labels, guard_trajectories=None,
                      guard_labels=None, min_support: int = 12,
                      beam_width: int = 12, max_depth: int = 7) -> SearchReport:
    """Beam-search conjunctions that separate `labels` on BOTH corpora.

    `trajectories` / `labels` is the discovery corpus. `guard_trajectories` /
    `guard_labels` is the validation corpus; when supplied, a conjunction is
    scored by the WORSE of its two F1 values and must clear the support floor on
    both. See the module docstring for why the guard corpus is required rather
    than optional.

    `labels` is a sequence of booleans — True means the observed outcome was
    unsafe. The search sees nothing else about any trajectory.
    """
    literals, masks, _ = build_literals(trajectories, min_support=min_support)
    positives, positive_count = _positive_mask(labels)

    report = SearchReport(literals_considered=len(literals), min_support=min_support,
                          beam_width=beam_width, max_depth=max_depth)
    if not positive_count or not literals:
        return report

    names = [lit.name for lit in literals]
    full = (1 << len(trajectories)) - 1

    use_guard = bool(guard_trajectories) and guard_labels is not None
    if use_guard:
        guard_masks = masks_for(guard_trajectories, names)
        guard_positives, guard_positive_count = _positive_mask(guard_labels)
        guard_full = (1 << len(guard_trajectories)) - 1
    else:
        guard_masks, guard_positives, guard_positive_count = {}, 0, 0
        guard_full = 0

    beam = [((), full, guard_full)]
    seen: dict = {}
    evaluated = 0

    for _ in range(max_depth):
        grown: list = []
        for chosen, mask, guard_mask in beam:
            chosen_set = set(chosen)
            for name in names:
                if name in chosen_set:
                    continue
                # Never conjoin a literal with its own negation: the result is
                # empty by construction and only wastes a beam slot.
                counterpart = name[4:] if name.startswith("NOT ") else f"NOT {name}"
                if counterpart in chosen_set:
                    continue
                new_mask = mask & masks[name]
                if new_mask == mask:
                    # The literal excludes nothing here — it adds length
                    # without adding structure, and would inflate the candidate
                    # with conditions that are not doing any work.
                    continue
                support = _popcount(new_mask)
                if support < min_support:
                    continue
                key = frozenset(chosen + (name,))
                if key in seen:
                    continue
                evaluated += 1
                f1, precision, recall, _, _, _ = _f1_from_masks(
                    new_mask, positives, positive_count)
                if f1 <= 0.0:
                    continue
                new_guard = guard_full
                guard_f1 = f1
                if use_guard:
                    new_guard = guard_mask & guard_masks[name]
                    if _popcount(new_guard) < min_support:
                        # A conjunction that barely fires on the second corpus
                        # has not been tested by it.
                        continue
                    guard_f1 = _f1_from_masks(
                        new_guard, guard_positives, guard_positive_count)[0]
                joint = min(f1, guard_f1)
                if joint <= 0.0:
                    continue
                seen[key] = True
                grown.append((tuple(sorted(chosen + (name,))), new_mask, new_guard,
                              f1, precision, recall, support, guard_f1, joint))
        if not grown:
            break
        # Deterministic ordering: joint quality, then simplicity, then name.
        grown.sort(key=lambda row: (-row[8], len(row[0]), row[0]))

        # A conjunction that already separates both corpora perfectly is
        # terminal: it goes into the pool but does not consume a beam slot,
        # because extending it cannot raise F1 on either corpus.
        solved = [row for row in grown if row[8] >= 1.0 - _EPSILON]
        unsolved = [row for row in grown if row[8] < 1.0 - _EPSILON]
        beam = [(row[0], row[1], row[2]) for row in unsolved[:beam_width]]
        for row in solved[:beam_width] + unsolved[:beam_width]:
            report.pool.append(DiscoveredStructure(
                literal_names=row[0], fit_f1=row[3], fit_precision=row[4],
                fit_recall=row[5], fit_support=row[6], guard_f1=row[7],
                joint_f1=row[8]))
        if not beam:
            break

    report.conjunctions_evaluated = evaluated
    report.pool.sort(key=lambda s: (-s.joint_f1, -s.fit_f1,
                                    len(s.literal_names), s.literal_names))
    return report


def _evaluate_structure(structure, trajectories, labels):
    predicates = [literal_from_name(name) for name in structure.literal_names]
    tp = fp = fn = tn = 0
    for trajectory, is_positive in zip(trajectories, labels):
        predicted = all(lit.evaluate(trajectory) for lit in predicates)
        if predicted and is_positive:
            tp += 1
        elif predicted and not is_positive:
            fp += 1
        elif not predicted and is_positive:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "support": tp + fp}


def select_structure(report, trajectories, labels, min_support: int = 12):
    """Rank the searched pool on a SEPARATE split and return the winner.

    Selection order: validation F1, then fit F1, then fewer literals, then
    lexicographic. Structures whose validation support falls below
    `min_support` are dropped — a conjunction that fires twice on validation
    has not been tested by it.
    """
    scored = []
    for structure in report.pool:
        metrics = _evaluate_structure(structure, trajectories, labels)
        if metrics["support"] < min_support:
            continue
        scored.append(DiscoveredStructure(
            literal_names=structure.literal_names,
            fit_f1=structure.fit_f1, fit_precision=structure.fit_precision,
            fit_recall=structure.fit_recall, fit_support=structure.fit_support,
            guard_f1=structure.guard_f1, joint_f1=structure.joint_f1,
            selection_metrics=metrics))
    if not scored:
        return None
    scored.sort(key=lambda s: (-min(s.selection_metrics["f1"], s.fit_f1),
                               -s.selection_metrics["f1"], -s.fit_f1,
                               len(s.literal_names), s.literal_names))
    return scored[0]


def prune_structure(structure, trajectories, labels):
    """Drop literals that do not pay for themselves on the selection split.

    A literal stays only if removing it lowers F1 there. This is what keeps the
    reported primitive minimal — an unnecessary literal is not merely untidy,
    it is an unfalsifiable claim, because ablating it changes nothing and the
    falsification runner has nothing to test.
    """
    names = list(structure.literal_names)
    if len(names) <= 1:
        return structure
    base = _evaluate_structure(structure, trajectories, labels)["f1"]
    changed = True
    while changed and len(names) > 1:
        changed = False
        for name in list(names):
            trial = DiscoveredStructure(
                literal_names=tuple(n for n in names if n != name))
            score = _evaluate_structure(trial, trajectories, labels)["f1"]
            if score >= base:
                names = list(trial.literal_names)
                base = score
                changed = True
                break
    pruned = DiscoveredStructure(literal_names=tuple(sorted(names)))
    return DiscoveredStructure(
        literal_names=pruned.literal_names, fit_f1=structure.fit_f1,
        fit_precision=structure.fit_precision, fit_recall=structure.fit_recall,
        fit_support=structure.fit_support, guard_f1=structure.guard_f1,
        joint_f1=structure.joint_f1,
        selection_metrics=_evaluate_structure(pruned, trajectories, labels))
