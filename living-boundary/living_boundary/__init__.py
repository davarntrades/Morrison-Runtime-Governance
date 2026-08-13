"""Living Boundary — LB-0 composition-discovery prototype.

STATUS: experimental. PRODUCTION AUTHORITY: none.

This package answers exactly one question under controlled conditions:

    Can the Living Boundary discover an unsafe compositional structure that
    was deliberately NOT encoded into the existing governance ontology?

Everything here sits outside the production decision path. It imports three
things from `morrison_governance`, all of them pure and read-only:

    kernel.capabilities   the canonical capability vocabulary (constants)
    kernel.policy         the capability -> authority policy table (read only,
                          never mutated; used to state what the baseline knows)
    kernel.evidence       EvidenceRecord / EvidenceChain, reused to seal LB-0's
                          own experiment log into a SEPARATE chain

It never constructs a `SecurityContext`, never builds a `GovernanceKernel`,
never calls `authorize`/`execute`, never mints an `ApprovalArtifact`, and never
writes to any Morrison module or configuration file. `living_boundary.authority`
states those invariants as executable predicates and
`tests/test_no_production_authority.py` proves them.
"""

from __future__ import annotations

from living_boundary import _repo_paths

# Importing this package must make `morrison_governance` importable regardless
# of the working directory the experiment is launched from — otherwise the
# baseline ontology would be built against whatever happened to be on the path.
_repo_paths.install()

__all__ = ["_repo_paths", "LB0_PHASE", "LB0_STATUS"]

LB0_PHASE = "LB-0"
LB0_STATUS = "experimental"
