"""Morrison governance kernel — the trust boundary around the Ω engine.

The reachability model is unchanged. This package adds what it never had:
an authenticated principal, verified approval artifacts bound to a canonical
action hash, semantic capability classification, trusted destination
resolution, denial-aware trajectory history, and hash-chained evidence.

    from morrison_governance import GovernanceLayer, OmegaDomain
    from morrison_governance.kernel import (
        GovernanceKernel, SecurityContext, Principal, issue_approval,
    )

    kernel = GovernanceKernel(
        layer=GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY]),
        context=SecurityContext(principal=Principal(id="agent", tenant="acme"),
                                signing_key=KEY, trusted_issuers=frozenset({"sec"})),
    )
    decision, executed, out = kernel.submit(call, runtime.execute)
"""

from morrison_governance.kernel.canonical import (
    action_hash, canonical_json, canonicalize,
)
from morrison_governance.kernel.capabilities import (
    ALL_CAPABILITIES, classify, describe,
)
from morrison_governance.kernel.destinations import (
    DestinationVerdict, classify_destination,
)
from morrison_governance.kernel.evidence import (
    EvidenceChain, EvidenceRecord, rule_fingerprint, ruleset_hash,
    ruleset_manifest,
)
from morrison_governance.kernel.gate import (
    BLOCK, ESCALATE, PERMIT, Attempt, Decision, GovernanceKernel,
)
from morrison_governance.kernel.policy import (
    ALLOW, APPROVAL, CAPABILITY_POLICY, DENY, GRANT, requirement_for,
)
from morrison_governance.kernel.trust import (
    ANONYMOUS, AUTHORITY_FIELDS, ApprovalArtifact, Principal, SecurityContext,
    forged_authority_claims, issue_approval, quarantine_authority,
)

__all__ = [
    "action_hash", "canonical_json", "canonicalize",
    "ALL_CAPABILITIES", "classify", "describe",
    "DestinationVerdict", "classify_destination",
    "EvidenceChain", "EvidenceRecord", "rule_fingerprint", "ruleset_hash",
    "ruleset_manifest",
    "BLOCK", "ESCALATE", "PERMIT", "Attempt", "Decision", "GovernanceKernel",
    "ALLOW", "APPROVAL", "CAPABILITY_POLICY", "DENY", "GRANT",
    "requirement_for",
    "ANONYMOUS", "AUTHORITY_FIELDS", "ApprovalArtifact", "Principal",
    "SecurityContext", "forged_authority_claims", "issue_approval",
    "quarantine_authority",
]
