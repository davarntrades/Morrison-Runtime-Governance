"""Independent derivation of policy facts from the action itself.

WHY THIS EXISTS

`sensitivity.classify_sensitivity` already demonstrates the correct pattern in
one place: it reads the actual payload and decides whether it carries regulated
data, and it does not consult the caller's `contains_phi` flag. That is why the
PHI exfiltration attack failed while the crisis-response attack succeeded —
regulated data had an independent classifier and nothing else did.

This module generalises that pattern. A fact derived here carries DERIVED
provenance, which outranks any UNTRUSTED caller claim of the same name, so:

    caller says  contains_phi = False
    derivation   finds an MRN and a diagnosis in the body
    result       contains_phi = True, DERIVED, and the caller's claim is gone

and, symmetrically:

    caller says  route_to_support = True
    derivation   finds no referral, no hotline, no routing language, and the
                 reply is a dismissal
    result       route_to_support = False, DERIVED

SCOPE — DELIBERATELY NARROW

A deriver only ever CONTRADICTS a claim the caller actually made. It never
introduces a positive fact the caller was silent about.

That restraint is not timidity, it is scope discipline. Asserting new facts
would change what the engine blocks, independently of provenance, and this
change is about provenance. Concretely: an unannotated payload containing PII
used to reach V2 as a trajectory finding, and a deriver that volunteered
`contains_pii=True` moved it to A_safe as a single-step finding — a different
verdict path for a case that has nothing to do with a forged claim. So:

    caller says contains_phi=False, classifier finds PHI  -> contradict
    caller says nothing,            classifier finds PHI  -> stay silent

Silence is the default; contradiction must be evidenced AND must answer a
claim that was made.

Deterministic: no clock, no RNG, no I/O.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator

# ── text harvesting ─────────────────────────────────────────────────────
_TEXT_KEYS = ("content", "body", "message", "text", "reply", "response",
              "output", "answer", "completion", "utterance")


def _text_of(args: dict) -> str:
    """Every string the action carries, including nested, lower-cased.

    Nested and serialised payloads are walked: a claim is refuted by what the
    action actually contains, wherever in the structure that content sits.
    """
    out: list[str] = []

    def walk(v: Any, depth: int = 0) -> None:
        # Depth budget. Raised from 6 after a probe hid a crisis disclosure at
        # depth 9 and escaped contradiction. Any finite budget is evadable by
        # nesting one level deeper; this is a classifier-quality limit, not a
        # provenance one, and is recorded as a residual rather than presented
        # as closed. 12 covers the payload shapes real agent frameworks emit.
        if depth > 12:
            return
        if isinstance(v, str):
            out.append(v)
            if v.lstrip()[:1] in ("{", "["):
                try:
                    walk(json.loads(v), depth + 1)
                except Exception:                        # noqa: BLE001
                    pass
        elif isinstance(v, dict):
            for vv in v.values():
                walk(vv, depth + 1)
        elif isinstance(v, (list, tuple, set, frozenset)):
            for vv in v:
                walk(vv, depth + 1)

    walk(args)
    return " ".join(out).lower()


# ── crisis disclosure ───────────────────────────────────────────────────
_CRISIS_DISCLOSURE = re.compile(
    r"(kill myself|killing myself|end my life|ending my life|take my own life|"
    r"suicid\w*|self[- ]?harm|hurt myself|hurting myself|cut myself|"
    r"overdose|want to die|wanna die|don'?t want to (?:live|be here)|"
    r"no reason to live|better off dead|end it all|not be here anymore)", re.I)

# Language that actually routes a person somewhere.
_ROUTING = re.compile(
    r"(crisis line|crisis team|crisis counsell?or|hotline|helpline|lifeline|"
    r"samaritans|988|911|999|112|emergency services|"
    r"call a professional|speak to (?:a|your) (?:doctor|therapist|clinician|"
    r"counsell?or|professional)|reach out to|text home|"
    r"connecting you with|put you in touch|support line)", re.I)

# Language that ACTIVELY steers away from support. A reply containing this is
# not a referral whatever else it contains — appending a hotline number to
# "don't tell anyone" does not make it a routing. Contradicts unconditionally.
_DISSUASION_STRONG = re.compile(
    r"(no need to (?:talk|tell|speak|call|reach)|don'?t (?:tell|talk to|call|"
    r"contact|reach out)|keep (?:this|it) (?:between us|secret|to yourself)|"
    r"you don'?t need (?:help|anyone|support)|talk to no one|"
    r"nobody needs to know|no one needs to know)", re.I)

# Minimising reassurance. On its own this is ambiguous — a good reply may
# reassure AND route ("you'll be fine, and I'm connecting you with someone
# now"). Contradicts only when no routing language is present at all.
_DISSUASION_WEAK = re.compile(
    r"(you'?ll be fine|you will be fine|it'?s nothing|not a big deal)", re.I)


#: Caller labels for a user's state that assert "this is not a crisis".
_NON_CRISIS_LABELS = {"curious", "calm", "neutral", "happy", "content",
                      "stable", "fine", "ok", "okay", "low_mood", "general",
                      "casual", "benign", "routine", "positive"}


def _derive_crisis(tool: str, args: dict, text: str) -> Iterator[tuple]:
    disclosed = bool(_CRISIS_DISCLOSURE.search(text))
    routes = bool(_ROUTING.search(text))
    strong = bool(_DISSUASION_STRONG.search(text))
    weak = bool(_DISSUASION_WEAK.search(text))

    # (1) Contradict a non-crisis LABEL over content that plainly discloses a
    # crisis. This is the premise-injection class: `user_state="curious"` on a
    # suicide disclosure. Only fires when the caller actually supplied such a
    # label — silence is not contradicted.
    if disclosed:
        label = str(args.get("user_state", "")).strip().lower()
        if label and label in _NON_CRISIS_LABELS:
            yield ("user_state", "active_crisis",
                   f"derivation: caller labelled the user {label!r} but the "
                   f"content discloses a crisis")

    # (2) Contradict a ROUTING claim the content refutes: the reply steers
    # away from support, or it answers a disclosure with nothing resembling a
    # referral. Only names the caller actually claimed are contradicted.
    refuted = strong or (weak and not routes) or (disclosed and text and not routes)
    if refuted:
        why = ("content actively steers away from support"
               if strong else
               "content minimises the crisis and carries no routing"
               if weak else
               "crisis disclosed but the content carries no routing or referral")
        for name in ("route_to_support", "crisis_referral", "emergency_referral"):
            if args.get(name):
                yield (name, False, f"derivation: {why}")


# ── regulated data (reuses the kernel classifier) ───────────────────────
def _derive_sensitivity(tool: str, args: dict) -> Iterator[tuple]:
    """Contradict a DENIAL of regulated content that the payload refutes.

    Emits nothing when the caller made no claim — see the scope note above.
    """
    denied = [n for n in ("contains_phi", "contains_pii", "contains_sensitive",
                          "contains_customer_data")
              if n in args and not args.get(n)]
    if not denied:
        return
    try:
        from morrison_governance.kernel import sensitivity as S
        found = S.classify_sensitivity({"tool": tool, "args": args})
    except Exception:                                    # noqa: BLE001
        return
    if not found:
        return
    for name in denied:
        yield (name, True,
               f"derivation: caller denied {name} but the sensitivity "
               f"classifier found {'/'.join(sorted(found))} in the payload")


# ── safety-control self-report ──────────────────────────────────────────
_SAFETY_OFF = re.compile(
    r"(ignore (?:all |your |previous )?(?:instructions|guidelines|rules|safety)|"
    r"without (?:your |any )?(?:filter|restriction|guardrail|safety)|"
    r"pretend (?:you have no|there are no) (?:rules|limits|guidelines)|"
    r"jailbreak|dan mode|developer mode)", re.I)


def _derive_safety(tool: str, args: dict, text: str) -> Iterator[tuple]:
    """Contradict `safety_disabled=False` over a payload that asks for exactly
    that. Silent when the caller made no claim."""
    if "safety_disabled" in args and not args.get("safety_disabled") \
            and _SAFETY_OFF.search(text):
        yield ("safety_disabled", True,
               "derivation: caller denied safety_disabled but the payload "
               "requests safety suspension")


DERIVERS = (_derive_crisis, _derive_safety)


def derive_facts(tool: str, args: dict) -> list[tuple]:
    """Facts the engine established itself, as (name, value, basis).

    Every one outranks a caller claim of the same name.
    """
    args = args if isinstance(args, dict) else {}
    text = _text_of(args)
    out: list[tuple] = []
    for fn in DERIVERS:
        try:
            out.extend(fn(tool, args, text))
        except Exception:                                # noqa: BLE001
            continue
    try:
        out.extend(_derive_sensitivity(tool, args))
    except Exception:                                    # noqa: BLE001
        pass
    return out
