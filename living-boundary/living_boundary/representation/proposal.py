"""The LB-1 output: an experimental representation-extension proposal.

WHAT LB-1 IS ALLOWED TO PRODUCE

A statement that its own representation is insufficient, the evidence for that
statement, a nomination of the observable it appears to be missing, and a
measurement of what reading that observable would recover. That is all.

WHAT IT MAY NOT DO

Adopt the extension. Not into production governance — LB-0 already established
that boundary and LB-1 inherits every one of its checks — and not into its own
grammar either. `discovery/features.FEATURE_FAMILIES` is a source constant, and
`tests/test_lb1_authority.py` asserts it is byte-identical before and after a
full LB-1 run.

That second restriction deserves a justification, because it is not obviously
required by the blueprint. "Discovery is autonomous" would permit a system to
widen its own hypothesis space; nothing about that changes what is enforceable.
The argument against is the threat model: a discovery layer that rewrites its
own representation in response to data is a system whose future findings are
conditioned on its past ones, with no external record of when the space changed
or why. `PRIMITIVE EXPLOSION` and `DISTRIBUTION MANIPULATION` both get easier.
The cost of the restriction is one review step; the cost of removing it is that
no later finding can be audited against a fixed representation. So the proposal
is an artifact, and adopting it is a commit somebody signs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


class ProposalStatus:
    EXPERIMENTAL = "EXPERIMENTAL"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    # Named so the boundary is explicit in source rather than implied by
    # absence. Nothing in LB-1 can produce these.
    ADOPTED = "ADOPTED"
    ENFORCED = "ENFORCED"


_FORBIDDEN = (ProposalStatus.ADOPTED, ProposalStatus.ENFORCED)


class ProposalAuthorityError(RuntimeError):
    """Raised when something tries to adopt a proposal from inside LB-1."""


@dataclass
class RepresentationProposal:
    """A nomination of a missing observable, with the evidence for it."""

    proposal_id: str
    representation: str
    verdict: str
    missing_observable: str = ""
    extension_family: str = ""
    rationale: str = ""
    evidence: dict = field(default_factory=dict)
    localisation: dict = field(default_factory=dict)
    demonstrated_recovery: dict = field(default_factory=dict)
    status: str = ProposalStatus.EXPERIMENTAL

    def advance(self, status: str) -> "RepresentationProposal":
        if status in _FORBIDDEN:
            raise ProposalAuthorityError(
                f"LB-1 cannot move a representation proposal to {status}. "
                f"Widening the discovery layer's own hypothesis space is a "
                f"change to how every future finding is derived; it is "
                f"recorded as a proposal and adopted, if at all, by a human "
                f"commit outside this package.")
        if status not in (ProposalStatus.EXPERIMENTAL,
                          ProposalStatus.REVIEW_REQUIRED):
            raise ValueError(f"unknown proposal status {status!r}")
        self.status = status
        return self

    @property
    def proposal_hash(self) -> str:
        payload = json.dumps(
            {"representation": self.representation,
             "observable": self.missing_observable,
             "family": self.extension_family},
            sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def as_dict(self) -> dict:
        return {
            "proposal_id": self.proposal_id,
            "proposal_hash": self.proposal_hash,
            "representation": self.representation,
            "verdict": self.verdict,
            "missing_observable": self.missing_observable,
            "extension_family": self.extension_family,
            "rationale": self.rationale,
            "evidence": dict(self.evidence),
            "localisation": dict(self.localisation),
            "demonstrated_recovery": dict(self.demonstrated_recovery),
            "status": self.status,
            "production_authority": "none",
            "grammar_mutation_authority": "none",
        }
