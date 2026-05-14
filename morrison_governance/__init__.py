# “””
Morrison Runtime Governance

Pre-execution control layer for tool-using AI systems.
Intercepts executable trajectories and evaluates reachability
into forbidden states (Ω) before any action occurs.

```
from morrison_governance import GovernanceLayer, OmegaDomain

governance = GovernanceLayer(
    domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY]
)

result = governance.evaluate(tool_call)

if result.permitted:
    execute(tool_call)
else:
    log(result.reason)
```

UK Patents: GB2600765.8 · GB2602013.1 · GB2602072.7 · GB2602332.5
© 2026 Davarn Morrison — Resurrection Tech Ltd
“””

from morrison_governance.core import GovernanceLayer
from morrison_governance.domains import OmegaDomain, OmegaRule
from morrison_governance.trajectory import TrajectoryExtractor
from morrison_governance.reachability import ReachabilityEvaluator
from morrison_governance.result import GovernanceResult, GovernanceVerdict

**version** = “0.1.0”
**author** = “Davarn Morrison”
**license** = “Commercial — see LICENSE”

**all** = [
“GovernanceLayer”,
“OmegaDomain”,
“OmegaRule”,
“TrajectoryExtractor”,
“ReachabilityEvaluator”,
“GovernanceResult”,
“GovernanceVerdict”,
]
