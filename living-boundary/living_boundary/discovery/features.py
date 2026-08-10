"""A generic, rule-agnostic feature grammar over governed trajectories.

WHAT A FEATURE IS HERE

Every feature is a boolean property of a trajectory, named as
`family::arg|arg|...`, where the arguments are drawn from the vocabulary the
traces actually contain. Nothing is hand-listed. Point this grammar at a corpus
about credential handling, or supply-chain approvals, or anything else, and it
instantiates the same families over that corpus's vocabulary.

THE FAMILIES, AND WHY EACH ONE EXISTS

    has_token        a capability@domain@boundary step occurred
    has_cap          a capability occurred
    has_domain       a governance domain was touched
    has_boundary     a step ran at a given trust boundary
    scope            a permission-scope token was present on some step
    order2           token A occurred before token B          (sequence)
    order3           tokens A, B, C occurred in that order    (composition)
    same_identity    the A step and the B step shared an identity
    order3_identity  tokens A, B, C in that order, ONE identity throughout
    subject_link     the A step and the B step touched the same data subject
    single_identity  exactly one identity acted in the trajectory
    transition       a consecutive trust-boundary change occurred
    crosses_boundary any step left the internal boundary
    steps_ge         the trajectory had at least k steps
    provider         the session's provider                   (surface)
    region           the session's region                     (surface)
    session_tag      the session's tag                        (surface)

THE LAST THREE ARE INCLUDED ON PURPOSE. They are surface metadata with no
causal relationship to anything, and in the discovery split they are strongly —
in one case perfectly — correlated with the unsafe outcome. Excluding them
would be the experimenter quietly removing the trap before the system walks
into it. They are left in, and whether the pipeline avoids them is a reported
result rather than an assumption.

`order3_identity` is the identity-scoped triple, and it was added to close an
ASYMMETRY rather than to fit a result: the grammar already had identity-scoped
PAIRS (`same_identity`) and unscoped TRIPLES (`order3`), and nothing in between.
Without it, a condition of the form "A, then B, then C, all by one actor" is not
expressible as a single literal, and the closest available approximations are
proper supersets that the falsification runner correctly rejects — which is what
happened, measured, before this family existed.

Every feature also exists in NEGATED form. Negation is what lets a candidate
express "…and no re-verification by that actor happened in between" without any
family dedicated to that idea.

DETERMINISM: extraction and literal construction are pure. Same trajectories in,
byte-identical literal names out, in sorted order.
"""

from __future__ import annotations

from living_boundary.ontology.candidate_schema import Literal

SEP = "::"
ARG = "|"

FEATURE_FAMILIES = (
    "has_token", "has_cap", "has_domain", "has_boundary", "scope",
    "order2", "order3", "order3_identity", "same_identity", "subject_link",
    "single_identity",
    "transition", "crosses_boundary", "steps_ge", "provider", "region",
    "session_tag",
)

# Families whose arguments are session metadata rather than governed structure.
# Recorded so the evidence package can state plainly whether the discovered
# candidate leaned on any of them.
SURFACE_FAMILIES = frozenset({"provider", "region", "session_tag"})

_MAX_STEPS_FEATURE = 10


# ═══════════════════════════════════════════════════════════════════════
# Extraction
# ═══════════════════════════════════════════════════════════════════════

def feature_set(trajectory) -> set:
    """Every positive feature name that holds for this trajectory."""
    events = trajectory.events
    tokens = [e.token for e in events]
    names = set()

    for event in events:
        names.add(f"has_token{SEP}{event.token}")
        names.add(f"has_cap{SEP}{event.capability}")
        names.add(f"has_domain{SEP}{event.domain}")
        names.add(f"has_boundary{SEP}{event.trust_boundary}")
        for scope in event.permission_scope:
            names.add(f"scope{SEP}{scope}")

    count = len(events)
    for i in range(count):
        for j in range(i + 1, count):
            left, right = tokens[i], tokens[j]
            names.add(f"order2{SEP}{left}{ARG}{right}")
            if events[i].identity_id == events[j].identity_id:
                names.add(f"same_identity{SEP}{left}{ARG}{right}")
            if events[i].subject and events[i].subject == events[j].subject:
                names.add(f"subject_link{SEP}{left}{ARG}{right}")
            for k in range(j + 1, count):
                names.add(f"order3{SEP}{left}{ARG}{right}{ARG}{tokens[k]}")
                if (events[i].identity_id == events[j].identity_id
                        == events[k].identity_id):
                    names.add(f"order3_identity{SEP}{left}{ARG}{right}{ARG}{tokens[k]}")

    if len(trajectory.identities) == 1:
        names.add(f"single_identity{SEP}")
    if trajectory.crosses_trust_boundary:
        names.add(f"crosses_boundary{SEP}")
    for source, target in trajectory.boundary_transitions:
        names.add(f"transition{SEP}{source}{ARG}{target}")
    for k in range(2, _MAX_STEPS_FEATURE):
        if count >= k:
            names.add(f"steps_ge{SEP}{k!s}")
    if trajectory.provider:
        names.add(f"provider{SEP}{trajectory.provider}")
    if trajectory.region:
        names.add(f"region{SEP}{trajectory.region}")
    if trajectory.session_tag:
        names.add(f"session_tag{SEP}{trajectory.session_tag}")
    return names


# ═══════════════════════════════════════════════════════════════════════
# Predicate reconstruction
# ═══════════════════════════════════════════════════════════════════════
# A frozen candidate must be evaluable on trajectories that did not exist when
# it was discovered — falsification cases, held-out cases, a future replay. So
# a literal name is parsed back into a predicate rather than carrying a closure
# over the discovery corpus.

def _p_has_token(token):
    def _f(t):
        return token in t.tokens
    return _f


def _p_has_cap(cap):
    def _f(t):
        return cap in t.capabilities
    return _f


def _p_has_domain(domain):
    def _f(t):
        return domain in t.domains
    return _f


def _p_has_boundary(boundary):
    def _f(t):
        return any(e.trust_boundary == boundary for e in t.events)
    return _f


def _p_scope(scope):
    def _f(t):
        return scope in t.cumulative_scope
    return _f


def _p_order2(left, right):
    def _f(t):
        tokens = t.tokens
        for i, tok in enumerate(tokens):
            if tok == left and right in tokens[i + 1:]:
                return True
        return False
    return _f


def _p_order3(first, second, third):
    def _f(t):
        tokens = t.tokens
        count = len(tokens)
        for i in range(count):
            if tokens[i] != first:
                continue
            for j in range(i + 1, count):
                if tokens[j] != second:
                    continue
                if third in tokens[j + 1:]:
                    return True
        return False
    return _f


def _p_order3_identity(first, second, third):
    def _f(t):
        events = t.events
        count = len(events)
        for i in range(count):
            if events[i].token != first:
                continue
            for j in range(i + 1, count):
                if events[j].token != second:
                    continue
                if events[j].identity_id != events[i].identity_id:
                    continue
                for k in range(j + 1, count):
                    if events[k].token == third and \
                            events[k].identity_id == events[i].identity_id:
                        return True
        return False
    return _f


def _p_same_identity(left, right):
    def _f(t):
        events = t.events
        for i, first in enumerate(events):
            if first.token != left:
                continue
            for second in events[i + 1:]:
                if second.token == right and second.identity_id == first.identity_id:
                    return True
        return False
    return _f


def _p_subject_link(left, right):
    def _f(t):
        events = t.events
        for i, first in enumerate(events):
            if first.token != left or not first.subject:
                continue
            for second in events[i + 1:]:
                if second.token == right and second.subject == first.subject:
                    return True
        return False
    return _f


def _p_single_identity():
    def _f(t):
        return len(t.identities) == 1
    return _f


def _p_transition(source, target):
    def _f(t):
        return (source, target) in t.boundary_transitions
    return _f


def _p_crosses_boundary():
    def _f(t):
        return t.crosses_trust_boundary
    return _f


def _p_steps_ge(threshold):
    limit = int(threshold)

    def _f(t):
        return len(t.events) >= limit
    return _f


def _p_provider(value):
    def _f(t):
        return t.provider == value
    return _f


def _p_region(value):
    def _f(t):
        return t.region == value
    return _f


def _p_session_tag(value):
    def _f(t):
        return t.session_tag == value
    return _f


_ZERO_ARG = {
    "single_identity": _p_single_identity,
    "crosses_boundary": _p_crosses_boundary,
}
_ONE_ARG = {
    "has_token": _p_has_token, "has_cap": _p_has_cap,
    "has_domain": _p_has_domain, "has_boundary": _p_has_boundary,
    "scope": _p_scope, "steps_ge": _p_steps_ge, "provider": _p_provider,
    "region": _p_region, "session_tag": _p_session_tag,
}
_TWO_ARG = {
    "order2": _p_order2, "same_identity": _p_same_identity,
    "subject_link": _p_subject_link, "transition": _p_transition,
}


def predicate_for(name: str):
    """Rebuild the predicate for a feature name. Total over the grammar."""
    family, _, rest = name.partition(SEP)
    args = [a for a in rest.split(ARG) if a != ""] if rest else []
    if family in _ZERO_ARG and not args:
        return _ZERO_ARG[family]()
    if family in _ONE_ARG and len(args) == 1:
        return _ONE_ARG[family](args[0])
    if family in _TWO_ARG and len(args) == 2:
        return _TWO_ARG[family](args[0], args[1])
    if family == "order3" and len(args) == 3:
        return _p_order3(args[0], args[1], args[2])
    if family == "order3_identity" and len(args) == 3:
        return _p_order3_identity(args[0], args[1], args[2])
    raise ValueError(f"unparseable feature name: {name!r}")


_DESCRIPTIONS = {
    "has_token": "a {} step occurred",
    "has_cap": "capability {} was exercised",
    "has_domain": "governance domain {} was touched",
    "has_boundary": "a step ran at trust boundary {}",
    "scope": "permission scope {} was held by some step",
    "order2": "a {0} step occurred before a {1} step",
    "order3": "a {0} step, then a {1} step, then a {2} step",
    "order3_identity": ("one identity performed a {0} step, then a {1} step, "
                        "then a {2} step"),
    "same_identity": "the {0} step and the {1} step shared one identity",
    "subject_link": "the {0} step and the {1} step touched the same data subject",
    "single_identity": "exactly one identity acted across the trajectory",
    "transition": "the trust boundary changed from {0} to {1}",
    "crosses_boundary": "some step left the internal trust boundary",
    "steps_ge": "the trajectory had at least {} steps",
    "provider": "the session ran on provider {}",
    "region": "the session ran in region {}",
    "session_tag": "the session carried tag {}",
}


def describe(name: str) -> str:
    family, _, rest = name.partition(SEP)
    args = [a for a in rest.split(ARG) if a != ""] if rest else []
    template = _DESCRIPTIONS.get(family, f"{family} {rest}")
    try:
        return template.format(*args) if args else template
    except (IndexError, KeyError):
        return name


def make_literal(name: str, negated: bool = False) -> Literal:
    family = name.partition(SEP)[0]
    text = describe(name)
    return Literal(
        name=f"NOT {name}" if negated else name,
        family=family,
        description=f"it is NOT the case that {text}" if negated else text,
        negated=negated,
        predicate=predicate_for(name))


def literal_from_name(name: str) -> Literal:
    """Rebuild a `Literal` (including its predicate) from its stored name."""
    if name.startswith("NOT "):
        return make_literal(name[4:], negated=True)
    return make_literal(name, negated=False)


# ═══════════════════════════════════════════════════════════════════════
# Literal construction with support filtering
# ═══════════════════════════════════════════════════════════════════════

def masks_for(trajectories, names):
    """Bitmask coverage of an EXISTING literal name set over new trajectories.

    Used to score a conjunction on a second corpus without re-deriving the
    vocabulary from it: the literals stay exactly the ones the first corpus
    produced, so the two scores are comparable literal for literal.
    """
    sets = [feature_set(t) for t in trajectories]
    total = len(trajectories)
    full = (1 << total) - 1
    base = sorted({name[4:] if name.startswith("NOT ") else name
                   for name in names})
    masks: dict = {}
    for name in base:
        mask = 0
        for index, present in enumerate(sets):
            if name in present:
                mask |= 1 << index
        masks[name] = mask
        masks[f"NOT {name}"] = full ^ mask
    return masks


def build_literals(trajectories, min_support: int = 12):
    """Build the searchable literal set with bitmask coverage over `trajectories`.

    Returns `(literals, masks, feature_sets)` where `masks[name]` is an integer
    whose bit i is set when literal `name` holds for `trajectories[i]`.

    SUPPORT FILTERING. A literal is kept only when both it and its negation
    cover at least `min_support` trajectories. A literal true for three
    trajectories out of nine hundred cannot support a claim about structure —
    it can only memorise those three — and admitting it would let the search
    manufacture a perfect fit out of coincidences.
    """
    sets = [feature_set(t) for t in trajectories]
    total = len(trajectories)

    counts: dict = {}
    for names in sets:
        for name in names:
            counts[name] = counts.get(name, 0) + 1

    masks: dict = {}
    literals: list = []
    for name in sorted(counts):
        positive = counts[name]
        if positive < min_support or (total - positive) < min_support:
            continue
        mask = 0
        for index, names in enumerate(sets):
            if name in names:
                mask |= 1 << index
        full = (1 << total) - 1
        masks[name] = mask
        masks[f"NOT {name}"] = full ^ mask
        literals.append(make_literal(name, negated=False))
        literals.append(make_literal(name, negated=True))
    return literals, masks, sets
