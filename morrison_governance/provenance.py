"""Policy-state provenance.

THE FAILURE THIS MODULE CLOSES
------------------------------
The kernel had a strong provenance boundary for AUTHORITY — an approval is an
HMAC-bound artifact read from the SecurityContext, and a caller cannot mint
one. It had no equivalent boundary for POLICY-STATE FACTS. Ω predicates read a
flat `key -> value` namespace assembled from caller arguments, so a claim like
`crisis_referral=True` was indistinguishable from a fact the deployment had
actually established. Adversarial testing turned that into execution three
times, including with a field name (`coordinator_ceo1_confirmed`) that appears
nowhere in this codebase.

The defect was never the vocabulary. Widening `AUTHORITY_FIELDS` cannot fix a
field the attacker invents, and cannot fix `user_state="curious"` on a suicide
disclosure, because `user_state` is legitimate caller data the deployment needs.

WHAT REPLACES IT
----------------
Every policy-relevant value carries a provenance class, and a read states what
it needs:

    UNTRUSTED   the caller/peer said so. The default for everything in `args`.
    OBSERVED    the caller said so AND no independent derivation contradicts it.
    DERIVED     the engine computed it from content or system state.
    TRUSTED     an authenticated mechanism established it (SecurityContext,
                a verified ApprovalArtifact, deployment-owned context).

Three read modes, and the mode is the contract:

    state.get(name)            subject matter. Ungated — a rule that needs to
                               know what the caller SAID still gets it.
    state.corroborated(name)   a self-description. Honoured unless an
                               independent derivation contradicts it.
    state.attested(name)       an authorisation. TRUSTED provenance only.

`attested` is the important one, and it is name-blind: it asks the provenance
of the fact, never its spelling. An invented `guardian_ack=True` arriving in
`args` is UNTRUSTED, so it is not attested, and no list had to anticipate it.

Conflict resolution is total and deterministic:

    TRUSTED > DERIVED > OBSERVED > UNTRUSTED

An unknown key is UNTRUSTED, not absent — reads fail closed rather than
silently succeeding on a fact nobody established.

Deterministic: no clock, no RNG, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Optional

UNTRUSTED = "untrusted"
OBSERVED = "observed"
DERIVED = "derived"
TRUSTED = "trusted"

#: Total order used for every conflict. Higher wins.
RANK = {UNTRUSTED: 0, OBSERVED: 1, DERIVED: 2, TRUSTED: 3}

ALL_CLASSES = (UNTRUSTED, OBSERVED, DERIVED, TRUSTED)


@dataclass(frozen=True)
class PolicyFact:
    """One policy-relevant value together with where it came from.

    `basis` records WHY the fact holds its class — the deriver that computed
    it, the context channel that supplied it, or the artifact that promoted
    it. It is what makes a provenance failure legible in the audit record.
    """

    name: str
    value: Any
    provenance: str = UNTRUSTED
    issuer: str = ""
    basis: str = ""

    @property
    def rank(self) -> int:
        return RANK.get(self.provenance, 0)

    def as_dict(self) -> dict:
        return {"name": self.name, "provenance": self.provenance,
                "issuer": self.issuer, "basis": self.basis}


@dataclass
class ProvenanceRead:
    """One rule's read of one fact, retained for evidence."""

    name: str
    mode: str                      # "get" | "corroborated" | "attested"
    provenance: str
    required: str
    satisfied: bool
    basis: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "mode": self.mode,
                "provenance": self.provenance, "required": self.required,
                "satisfied": self.satisfied, "basis": self.basis}


class ProvenanceState(dict):
    """The Ω evaluation namespace, with provenance retained.

    Subclasses `dict` deliberately: 96 existing Ω predicates take a plain
    mapping and index it, and every one of them keeps working unchanged. What
    changes is that a predicate MAY now ask for a provenance guarantee, and
    the two attack-relevant read modes refuse to answer from caller data.
    """

    __slots__ = ("facts", "reads")

    def __init__(self, values: Optional[dict] = None,
                 facts: Optional[dict] = None):
        super().__init__(values or {})
        self.facts: dict[str, PolicyFact] = dict(facts or {})
        self.reads: list[ProvenanceRead] = []

    # ── construction ────────────────────────────────────────
    def put(self, name: str, value: Any, provenance: str = UNTRUSTED,
            issuer: str = "", basis: str = "") -> None:
        """Record a fact. A lower-ranked class never displaces a higher one."""
        existing = self.facts.get(name)
        if existing is not None and existing.rank > RANK.get(provenance, 0):
            return
        self.facts[name] = PolicyFact(name, value, provenance, issuer, basis)
        super().__setitem__(name, value)

    def put_all(self, values: dict, provenance: str = UNTRUSTED,
                issuer: str = "", basis: str = "") -> None:
        for k, v in (values or {}).items():
            self.put(str(k), v, provenance, issuer, basis)

    # ── provenance queries ──────────────────────────────────
    def provenance_of(self, name: str) -> str:
        """UNTRUSTED for anything nobody established — reads fail closed."""
        fact = self.facts.get(name)
        return fact.provenance if fact is not None else UNTRUSTED

    def basis_of(self, name: str) -> str:
        fact = self.facts.get(name)
        return fact.basis if fact is not None else ""

    def _log(self, name, mode, required, satisfied) -> None:
        self.reads.append(ProvenanceRead(
            name=name, mode=mode, provenance=self.provenance_of(name),
            required=required, satisfied=bool(satisfied),
            basis=self.basis_of(name)))

    # ── read modes ──────────────────────────────────────────
    def get(self, name, default=None):                   # noqa: A003
        """Subject matter. Ungated, by design.

        A rule that asks "what did the caller say the user's state was?" is
        entitled to the answer. What it must not do is treat that answer as an
        authorisation — that is what `attested` is for.
        """
        return super().get(name, default)

    def attested(self, name: str, default: Any = False) -> Any:
        """An AUTHORISATION. Answered only from TRUSTED provenance.

        This is the read that closes the invented-name class. It never
        inspects the spelling of `name`; a field called `guardian_ack` and a
        field called `admin_approved` are treated identically, and both are
        refused unless something authenticated established them.
        """
        ok = self.provenance_of(name) == TRUSTED
        self._log(name, "attested", TRUSTED, ok)
        return super().get(name, default) if ok else default

    def corroborated(self, name: str, default: Any = None) -> Any:
        """A SELF-DESCRIPTION of the action — "this reply routes to support".

        Honoured when the caller supplies it, because the deployment's own
        response pipeline is a legitimate source for it, EXCEPT where an
        independent derivation contradicts it. A claim the content refutes is
        not an observation; it is a misrepresentation, and it does not hold.
        """
        prov = self.provenance_of(name)
        contradicted = self.facts.get(name) is not None and \
            prov in (DERIVED, TRUSTED) and not super().get(name)
        ok = not contradicted
        self._log(name, "corroborated", OBSERVED, ok)
        return super().get(name, default) if ok else default

    def attested_truthy(self, name: str) -> bool:
        """Is this a TRUSTED fact that asserts something affirmative?

        Accepts the string "true" as well as the boolean: deployment payloads
        stringify flags, and provenance, not transport, is what is being
        tested here.
        """
        v = self.attested(name, default=None)
        return v is True or (isinstance(v, str) and v.strip().lower() == "true")

    def any_attested(self, suffixes: Iterable[str]) -> bool:
        """Is ANY trusted fact a truthy authorisation with one of these shapes?

        The replacement for a whole-state suffix scan. The suffix list still
        describes the SHAPE of an authorisation, but it is applied only to
        facts that already hold TRUSTED provenance, so it can no longer be
        satisfied by a caller inventing a matching name. Shape selects among
        established facts; it never establishes one.
        """
        sufs = tuple(suffixes)
        for name, fact in self.facts.items():
            if fact.provenance != TRUSTED:
                continue
            if not (fact.value is True or
                    (isinstance(fact.value, str)
                     and fact.value.strip().lower() == "true")):
                continue
            if name.endswith(sufs):
                self._log(name, "attested", TRUSTED, True)
                return True
        return False

    # ── evidence ────────────────────────────────────────────
    def provenance_report(self) -> dict:
        """What an auditor needs: every fact's origin and every gated read."""
        return {
            "facts": {n: f.as_dict() for n, f in sorted(self.facts.items())},
            "reads": [r.as_dict() for r in self.reads],
            "refused": [r.as_dict() for r in self.reads if not r.satisfied],
            "counts": {c: sum(1 for f in self.facts.values()
                              if f.provenance == c) for c in ALL_CLASSES},
        }

    # ── dict protocol ───────────────────────────────────────
    def copy(self) -> "ProvenanceState":
        out = ProvenanceState(dict(self), self.facts)
        out.reads = list(self.reads)
        return out

    def __setitem__(self, k, v):
        # A plain assignment by engine code is a DERIVED fact: the engine
        # computed it. It is never a promotion of a caller claim, because
        # `put` refuses to lower an existing higher-ranked class.
        self.put(str(k), v, DERIVED, basis="engine assignment")

    def update(self, *a, **kw):                           # noqa: A003
        merged = dict(*a, **kw)
        for k, v in merged.items():
            self.put(str(k), v, DERIVED, basis="engine update")


def coerce(state: Any) -> ProvenanceState:
    """Treat any mapping as a ProvenanceState.

    A plain dict reaching a provenance-aware predicate — from a test, a
    forward projection built by hand, or third-party code — has no recorded
    provenance, so every field in it is UNTRUSTED. That is the fail-closed
    direction: an unannotated dict cannot attest anything.
    """
    if isinstance(state, ProvenanceState):
        return state
    out = ProvenanceState()
    out.put_all(dict(state or {}), UNTRUSTED, basis="unannotated mapping")
    return out
