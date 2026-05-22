"""
Morrison Global Governance — meta-governance layer.

The runtime governance core answers a *local* question: can THIS
trajectory reach Ω? "Global" safety (in the sense of the
meta-governance requirements table) needs more than a local check. This
package implements, as concrete deterministic mechanisms on top of the
existing reachability core, the nine additional requirements:

  2. Cross-system trajectory analysis      → cross_system.py
  3. Adaptive Ω evolution                   → adaptive_omega.py
  4. Hierarchical governance layers         → hierarchy.py
  5. Formal interface standards             → interface_standard.py
  6. Continuous adversarial auditing        → continuous_audit.py
  7. Memory-aware governance                → memory_governance.py
  8. Self-verifying controllers             → self_verifying.py
  9. Distributed trust architecture         → distributed_trust.py
 10. Human override / institutional         → institutional.py

(1. Runtime governance is the existing morrison_governance core.)

Bounded honesty: this is a *mechanism-level* implementation that
demonstrates and tests each requirement deterministically. It is NOT a
proof of global safety; two requirements (distributed trust,
institutional legitimacy) are socio-technical / infrastructure
problems for which only the governance-layer-side mechanism is modelled
here. See README.md and the scorecard for the honest status of each.
"""

from global_governance.hierarchy import (
    HierarchicalGovernance, HierarchicalResult, TierVerdict,
)
from global_governance.cross_system import (
    CrossSystemAnalyzer, CrossSystemResult,
)
from global_governance.adaptive_omega import AdaptiveOmega, OmegaVersion
from global_governance.interface_standard import (
    INTERFACE_VERSION, check_conformance, ConformanceReport,
)
from global_governance.continuous_audit import (
    ContinuousAuditor, AuditSnapshot, AuditDiff,
)
from global_governance.memory_governance import (
    MemoryGovernance, MemoryResult,
)
from global_governance.self_verifying import (
    SelfVerifyingController, VerifiedResult,
)
from global_governance.distributed_trust import (
    DistributedGovernance, ConsensusResult,
)
from global_governance.institutional import (
    InstitutionalGovernance, Authorization, InstitutionalResult,
)
from global_governance.scorecard import readiness_scorecard, ScorecardEntry
from global_governance.meta import MetaGovernance, MetaResult

__all__ = [
    "HierarchicalGovernance", "HierarchicalResult", "TierVerdict",
    "CrossSystemAnalyzer", "CrossSystemResult",
    "AdaptiveOmega", "OmegaVersion",
    "INTERFACE_VERSION", "check_conformance", "ConformanceReport",
    "ContinuousAuditor", "AuditSnapshot", "AuditDiff",
    "MemoryGovernance", "MemoryResult",
    "SelfVerifyingController", "VerifiedResult",
    "DistributedGovernance", "ConsensusResult",
    "InstitutionalGovernance", "Authorization", "InstitutionalResult",
    "readiness_scorecard", "ScorecardEntry",
    "MetaGovernance", "MetaResult",
]
