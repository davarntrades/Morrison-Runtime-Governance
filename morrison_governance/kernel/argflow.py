"""Runtime-supplied argument provenance.

Where each argument of a proposed call came from, as established by the
RUNTIME (an interpreter or orchestrator that tracks data flow, in the way
CaMeL's interpreter does), never by the call itself. It reaches the kernel as
`GovernanceKernel.authorize(call, argument_provenance=...)`, a parameter that is
not part of the call, so a model-proposed call cannot set or forge it; names
that would carry it inside `args` are quarantined as authority claims.

It is used in two directions:

  CLEARING (utility)   Morrison's read→egress taint is trajectory-level: once
                       anything was read, every later external egress is
                       refused, including one whose content is the user's own
                       words (ARSB TRJ-05: a legitimate email after a
                       confidential read, utility 1/2 where CaMeL had 2/2).
                       When EVERY top-level argument is labelled with a clean
                       source, the call provably carries nothing it read, and
                       the read→egress taint checks do not apply to it. One
                       unlabelled argument is enough to keep the taint.

  TIGHTENING (safety)  An effectful call any of whose arguments derives from
                       untrusted content escalates (ARSB LOC-02: an
                       admissible payment whose payee came from an untrusted
                       document executed).

What it does NOT do: it does not clear content checks (sensitive data in the
payload is still classified), destination policy, denial scrubbing, Ω rules or
capability policy. It is exactly as good as the runtime's labels: a tracker
that labels a derived value `request` re-opens the flow it was meant to close.
And it does not remove the implicit channel of a model that has SEEN the
confidential data choosing whether, when and to whom to send clean content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional

# Sources whose values cannot carry anything the agent read.
CLEAN_SOURCES = frozenset({"request", "user", "policy", "constant", "system"})
# Prefixes marking a value derived from content an adversary may control.
UNTRUSTED_PREFIXES = ("untrusted", "web", "external", "tool_output", "email_body")


@dataclass(frozen=True)
class ArgumentProvenance:
    supplied: bool
    all_clean: bool
    untrusted_args: tuple = ()
    unlabelled_args: tuple = ()
    labels: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"supplied": self.supplied, "all_clean": self.all_clean,
                "untrusted_args": list(self.untrusted_args),
                "unlabelled_args": list(self.unlabelled_args),
                "labels": dict(self.labels)}


def _source(label: object) -> str:
    return str(label or "").strip().lower()


def assess(args: Mapping, provenance: Optional[Mapping]) -> ArgumentProvenance:
    """Assess runtime provenance for a call's TOP-LEVEL arguments."""
    if not provenance:
        return ArgumentProvenance(False, False)
    labels = {str(k): _source(v) for k, v in dict(provenance).items()}
    names = [str(k) for k in (args or {})]
    unlabelled = tuple(n for n in names if n not in labels)
    untrusted = tuple(n for n in names if labels.get(n, "").startswith(UNTRUSTED_PREFIXES))
    clean = bool(names) and not unlabelled and all(
        labels[n] in CLEAN_SOURCES for n in names)
    return ArgumentProvenance(True, clean, untrusted, unlabelled,
                              {n: labels[n] for n in names if n in labels})
