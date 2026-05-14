“””
Governance evaluation results.
“””

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class GovernanceVerdict(Enum):
“””
Verdict from the governance layer.

```
PERMIT  — trajectory does not reach Ω. Execution allowed.
BLOCK   — trajectory reaches Ω. Execution prevented.
NO_VALID_SOLUTION — no admissible trajectory exists for this task.
ENVIRONMENT_SENSITIVE — safe under base conditions, unsafe under perturbation.
"""

PERMIT = "PERMIT"
BLOCK = "BLOCK"
NO_VALID_SOLUTION = "NO_VALID_SOLUTION"
ENVIRONMENT_SENSITIVE = "ENVIRONMENT_SENSITIVE"
```

@dataclass
class GovernanceResult:
“””
Result of a governance evaluation.

```
Attributes:
    verdict: PERMIT, BLOCK, NO_VALID_SOLUTION, or ENVIRONMENT_SENSITIVE
    permitted: convenience boolean — True only if verdict is PERMIT
    layer: enforcement layer that determined the verdict (e.g. "V3", "V5")
    reason: human-readable explanation of why the trajectory was blocked
    omega_domain: which Ω domain was violated, if any
    trajectory_hash: hash of the evaluated trajectory for audit logging
    reachability_distance: estimated distance to nearest Ω boundary
    metadata: additional context for logging and audit
"""

verdict: GovernanceVerdict
layer: str = ""
reason: str = ""
omega_domain: Optional[str] = None
trajectory_hash: str = ""
reachability_distance: Optional[float] = None
metadata: dict = field(default_factory=dict)

@property
def permitted(self) -> bool:
    return self.verdict == GovernanceVerdict.PERMIT

@property
def blocked(self) -> bool:
    return self.verdict in (
        GovernanceVerdict.BLOCK,
        GovernanceVerdict.NO_VALID_SOLUTION,
        GovernanceVerdict.ENVIRONMENT_SENSITIVE,
    )

def to_dict(self) -> dict:
    return {
        "verdict": self.verdict.value,
        "permitted": self.permitted,
        "layer": self.layer,
        "reason": self.reason,
        "omega_domain": self.omega_domain,
        "trajectory_hash": self.trajectory_hash,
        "reachability_distance": self.reachability_distance,
        "metadata": self.metadata,
    }

def __repr__(self) -> str:
    return (
        f"GovernanceResult(verdict={self.verdict.value}, "
        f"layer={self.layer}, reason={self.reason!r})"
    )
```
