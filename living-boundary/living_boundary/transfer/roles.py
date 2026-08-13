"""Label-free structural role induction, and the alignment between environments.

THE PROBLEM THIS EXISTS TO SOLVE

Every atom in the LB-0 grammar is spelled with vocabulary: `data.read`,
`customer_data`, `comms.send.external`. A candidate written in that alphabet
cannot even be EVALUATED in an environment that spells things differently — not
"scores badly", but "never fires", because none of its literals have referents.
So the first question in cross-environment transfer is not whether a structure
survives; it is whether there is a shared alphabet to state the structure in.

WHAT IS AND IS NOT USED

Roles are induced per environment from UNLABELLED traces, using only relational
statistics of a step type — where it sits, whether it crosses the perimeter,
whether its subject shows up again, whether its identity does. No outcome
labels. No cross-environment vocabulary. No harness knowledge. The alignment
between two environments is then a nearest-centroid assignment in the
standardised statistic space.

Every one of those statistics is a modelling choice, and choosing them is the
single largest piece of experimenter freedom in LB-3. Two guards sit against
it, both of them in the experiment rather than in this file:

  · the STRUCTURAL PERTURBATION and NEGATIVE CONTROL environments, where roles
    align perfectly well and the relation underneath has changed. Alignment
    that is doing real work must fail there.
  · the competing hypotheses, several of which are strictly cheaper than role
    induction. If they transfer as well, role induction has explained nothing.

STANDARDISATION IS PER ENVIRONMENT, ON PURPOSE

An environment with longer traces has systematically lower relative positions
and lower crossing rates. Comparing raw statistics across environments would
match roles by trace geometry rather than by function. Z-scoring within an
environment removes the level and keeps the shape — which is itself an
assumption, and the one most likely to break on real telemetry where the
step-type inventory is not roughly balanced.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from living_boundary.observer.normalizer import BOUNDARY_INTERNAL

# How many structural roles to induce. Fixed before any result was examined:
# a governed step is doing one of a small number of things, and five leaves
# room for one role more than the four the LB-1/LB-2 worlds ever needed.
ROLE_COUNT = 5
# k-means iteration cap. Convergence is checked; the cap only bounds runtime.
MAX_ITERATIONS = 40
# Statistic order is fixed here so a centroid is comparable across runs.
STATISTIC_NAMES = (
    "crossing_rate",
    "mean_relative_position",
    "first_step_rate",
    "precedes_crossing_rate",
    "subject_shared_with_crossing",
    "identity_shared_with_crossing",
    "mean_scope_count",
    "subject_recurrence_rate",
)


def _step_type(event) -> str:
    """The environment-local identity of a step. Never compared across
    environments — only its statistics are."""
    return event.action


def _trajectory_facts(trajectory):
    events = trajectory.events
    crossing = [e for e in events
                if e.trust_boundary != BOUNDARY_INTERNAL]
    crossing_subjects = {e.subject for e in crossing if e.subject}
    crossing_identities = {e.identity_id for e in crossing}
    subjects = [e.subject for e in events if e.subject]
    return crossing, crossing_subjects, crossing_identities, subjects


def observe_statistics(trajectories) -> dict:
    """Relational statistics per step type, from unlabelled traces alone."""
    totals: dict = {}
    for trajectory in trajectories:
        events = trajectory.events
        span = max(1, len(events) - 1)
        crossing, cross_subjects, cross_identities, subjects = \
            _trajectory_facts(trajectory)
        first_crossing = events.index(crossing[0]) if crossing else None
        for index, event in enumerate(events):
            row = totals.setdefault(_step_type(event), [0.0] * (
                len(STATISTIC_NAMES) + 1))
            row[0] += 1.0
            row[1] += 1.0 if event.trust_boundary != BOUNDARY_INTERNAL else 0.0
            row[2] += index / span
            row[3] += 1.0 if index == 0 else 0.0
            row[4] += 1.0 if (first_crossing is not None
                              and index < first_crossing) else 0.0
            row[5] += 1.0 if event.subject in cross_subjects else 0.0
            row[6] += 1.0 if event.identity_id in cross_identities else 0.0
            row[7] += float(len(event.permission_scope))
            row[8] += 1.0 if (event.subject
                              and subjects.count(event.subject) > 1) else 0.0
    return {name: tuple(value / row[0] for value in row[1:])
            for name, row in sorted(totals.items()) if row[0]}


# ── standardisation and clustering ──────────────────────────────────────

def _standardise(vectors):
    """Z-score each statistic across the step types of ONE environment."""
    if not vectors:
        return {}
    width = len(STATISTIC_NAMES)
    columns = [[v[i] for v in vectors.values()] for i in range(width)]
    means = [sum(col) / len(col) for col in columns]
    spreads = []
    for index, col in enumerate(columns):
        variance = sum((x - means[index]) ** 2 for x in col) / len(col)
        spreads.append(variance ** 0.5 or 1.0)
    return {name: tuple((value[i] - means[i]) / spreads[i]
                        for i in range(width))
            for name, value in vectors.items()}


def _distance(left, right) -> float:
    return sum((a - b) ** 2 for a, b in zip(left, right))


def _seed_centroids(points, count: int):
    """Deterministic farthest-point initialisation.

    Starts from the step type whose standardised vector is lexicographically
    first — not the largest, not a random draw — so the same corpus always
    produces the same clustering without an RNG anywhere in the analysis path.
    """
    names = sorted(points)
    chosen = [points[names[0]]]
    while len(chosen) < min(count, len(names)):
        best_name, best_gap = None, -1.0
        for name in names:
            gap = min(_distance(points[name], c) for c in chosen)
            if gap > best_gap:
                best_name, best_gap = name, gap
        chosen.append(points[best_name])
    return chosen


def _assign(points, centroids) -> dict:
    return {name: min(range(len(centroids)),
                      key=lambda i, v=vector: (_distance(v, centroids[i]), i))
            for name, vector in points.items()}


def _recentre(points, assignment, count: int, previous):
    width = len(STATISTIC_NAMES)
    centroids = []
    for index in range(count):
        members = [points[name] for name, cluster in assignment.items()
                   if cluster == index]
        if not members:
            centroids.append(previous[index])
            continue
        centroids.append(tuple(
            sum(m[i] for m in members) / len(members) for i in range(width)))
    return centroids


@dataclass
class RoleModel:
    """An environment's induced roles: which step type is which, and where the
    role sits in the standardised statistic space."""

    env_id: str
    assignment: dict = field(default_factory=dict)   # step type -> local index
    centroids: tuple = ()                            # local index -> vector
    statistics: dict = field(default_factory=dict)   # step type -> raw vector
    alignment: dict = field(default_factory=dict)    # local index -> role name

    def role_of(self, event) -> str:
        """The aligned role name for an event, or `role_unmapped`."""
        local = self.assignment.get(_step_type(event))
        if local is None:
            return "role_unmapped"
        return self.alignment.get(local, f"role_{local}")

    def as_dict(self) -> dict:
        members: dict = {}
        for step_type, local in sorted(self.assignment.items()):
            members.setdefault(self.alignment.get(local, f"role_{local}"),
                               []).append(step_type)
        return {
            "environment": self.env_id,
            "roles": ROLE_COUNT,
            "statistics": list(STATISTIC_NAMES),
            "members": {role: sorted(names) for role, names in sorted(members.items())},
            "centroids": {self.alignment.get(index, f"role_{index}"):
                          [round(v, 4) for v in centroid]
                          for index, centroid in enumerate(self.centroids)},
        }


def induce_roles(env_id: str, trajectories) -> RoleModel:
    """Cluster an environment's step types into structural roles. No labels."""
    statistics = observe_statistics(trajectories)
    points = _standardise(statistics)
    if not points:
        return RoleModel(env_id=env_id)

    count = min(ROLE_COUNT, len(points))
    centroids = _seed_centroids(points, count)
    assignment = _assign(points, centroids)
    for _ in range(MAX_ITERATIONS):
        centroids = _recentre(points, assignment, count, centroids)
        updated = _assign(points, centroids)
        if updated == assignment:
            break
        assignment = updated

    model = RoleModel(env_id=env_id, assignment=assignment,
                      centroids=tuple(centroids), statistics=statistics)
    # Before alignment, an environment's roles are named by their own index.
    model.alignment = {index: f"role_{index}" for index in range(count)}
    return model


def align(reference: RoleModel, other: RoleModel) -> dict:
    """Map another environment's local roles onto the reference's role names.

    Greedy nearest-centroid matching over the standardised space, taking the
    globally closest pair first. Greedy rather than optimal because with five
    roles the two agree in every case observed, and a greedy rule is one a
    reviewer can check by hand against the reported centroids.
    """
    pairs = []
    for local, centroid in enumerate(other.centroids):
        for target, reference_centroid in enumerate(reference.centroids):
            pairs.append((_distance(centroid, reference_centroid), local, target))
    pairs.sort()

    used_local, used_target, mapping = set(), set(), {}
    for _, local, target in pairs:
        if local in used_local or target in used_target:
            continue
        used_local.add(local)
        used_target.add(target)
        mapping[local] = reference.alignment.get(target, f"role_{target}")
    for local in range(len(other.centroids)):
        mapping.setdefault(local, f"role_unaligned_{local}")
    return mapping


def alignment_cost(reference: RoleModel, other: RoleModel, mapping) -> float:
    """Mean squared centroid distance under an alignment.

    Reported alongside every transfer number: an alignment that had to stretch
    a long way is weaker evidence than one that snapped into place, and the
    reader should be able to see which happened.
    """
    inverse = {name: index for index, name in reference.alignment.items()}
    total, count = 0.0, 0
    for local, role in mapping.items():
        target = inverse.get(role)
        if target is None or local >= len(other.centroids):
            continue
        total += _distance(other.centroids[local], reference.centroids[target])
        count += 1
    return round(total / count, 4) if count else float("inf")
