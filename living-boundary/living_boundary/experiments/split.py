"""Dataset partitioning guarantees and the memorisation control.

The three partitions are generated independently rather than carved out of one
pool, so "held-out" means *generated from a disjoint surface vocabulary*, not
merely *sampled last*. This module states and checks the properties the
experiment relies on, and builds the label-shuffle control.
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class SplitIntegrity:
    """Result of checking the properties held-out evaluation depends on."""

    sequence_ids_disjoint: bool
    identities_disjoint: bool
    subjects_disjoint: bool
    families_present_in_all_splits: bool
    shared_families: tuple
    problems: tuple

    @property
    def ok(self) -> bool:
        return not self.problems

    def as_dict(self) -> dict:
        return {
            "sequence_ids_disjoint": self.sequence_ids_disjoint,
            "identities_disjoint": self.identities_disjoint,
            "subjects_disjoint": self.subjects_disjoint,
            "families_present_in_all_splits": self.families_present_in_all_splits,
            "shared_family_count": len(self.shared_families),
            "problems": list(self.problems),
            "ok": self.ok,
        }


def check_integrity(dataset) -> SplitIntegrity:
    """Verify partition disjointness and structural coverage.

    Two failure modes this catches:

      · SURFACE LEAKAGE — an identity or data subject appearing in more than
        one split would let a candidate that memorised an identifier score on
        held-out, and the "does it generalise?" question would be unanswerable.

      · FAMILY LEAKAGE, THE OTHER WAY ROUND — a structural family present only
        in held-out would make held-out a test of extrapolation to unseen
        structure, which is a different (and much harder) question than the one
        LB-0 asks. Every family must appear in every split.
    """
    problems = []
    names = list(dataset.splits)

    def _sets(attr):
        return {n: attr(dataset.splits[n]) for n in names}

    seq_ids = _sets(lambda s: {t.sequence_id for t in s.trajectories})
    identities = _sets(lambda s: {e.identity_id for t in s.trajectories for e in t.events})
    subjects = _sets(lambda s: {e.subject for t in s.trajectories for e in t.events})
    families = _sets(lambda s: set(s.families.values()))

    def _pairwise_disjoint(mapping, what):
        ok = True
        for i, left in enumerate(names):
            for right in names[i + 1:]:
                overlap = mapping[left] & mapping[right]
                if overlap:
                    ok = False
                    problems.append(
                        "{} overlap between {} and {}: {} shared "
                        "({}…)".format(what, left, right, len(overlap),
                                       sorted(overlap)[0]))
        return ok

    seq_ok = _pairwise_disjoint(seq_ids, "sequence id")
    id_ok = _pairwise_disjoint(identities, "identity")
    # `svc-token`, `platform-admin`, `batch-pool-3` and the denylisted
    # destinations are fixed resource names in the KNOWN-BAD classes and are
    # shared by design; only customer subjects must be split-private.
    customer_subjects = {n: {s for s in subjects[n] if s.startswith("cust_")}
                         for n in names}
    subj_ok = _pairwise_disjoint(customer_subjects, "data subject")

    shared = set(families[names[0]])
    for n in names[1:]:
        shared &= families[n]
    all_families = set()
    for n in names:
        all_families |= families[n]
    fam_ok = shared == all_families
    if not fam_ok:
        problems.append(
            "structural families are not present in every split; missing "
            "{}".format(sorted(all_families - shared)))

    return SplitIntegrity(
        sequence_ids_disjoint=seq_ok, identities_disjoint=id_ok,
        subjects_disjoint=subj_ok, families_present_in_all_splits=fam_ok,
        shared_families=tuple(sorted(shared)), problems=tuple(problems))


def shuffled_labels(trajectories, seed: int) -> dict:
    """Permuted labels for the memorisation control.

    The control runs the WHOLE discovery pipeline against labels that have been
    shuffled between trajectories. The label MARGINAL is preserved exactly (it
    is a permutation), so any candidate the search finds is fitting noise. If
    such a candidate still scores well on held-out, the pipeline is memorising
    or the evaluation is leaking, and the real result means nothing. This is
    the cheapest available check on that failure mode, and it is reported
    whether it passes or fails.
    """
    labels = [t.outcome for t in trajectories]
    rng = random.Random(seed * 104729 + 7)
    rng.shuffle(labels)
    return {t.sequence_id: label for t, label in zip(trajectories, labels)}
