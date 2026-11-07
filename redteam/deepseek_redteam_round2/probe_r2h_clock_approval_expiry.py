"""R2-H — caller-supplied clock bypasses approval expiry.

Declared invariant (source):
    kernel/trust.py, `ApprovalArtifact.verify`:
        `issued_at` / `expires_at` are checked against the supplied `now`.
    kernel/gate.py, `_lease_problem` wall-clock clause:
        "a caller-supplied clock cannot extend a lease."
    morrison_governance/test_kernel_redteam.py:test_expired_approval_is_rejected

Observed:
    approval = issue_approval(CALL, ttl_s=10, now=PAST)
               where PAST = time.time() - 100_000

    authorize(CALL)               -> ESCALATE "approval has expired"
    authorize(CALL, now=PAST+5)   -> PERMIT "approval verified"
    execute(decision, now=PAST+5) -> (True, None), effect recorded

    Control: execute(decision, now=time.time()) -> refused
             "decision expired 99_8xx.x s ago" (the decision-freshness
             `issued_wall` cross-check still applies).

So the wall-clock cross-check protects the decision's own lease, but the
approval artifact's `expires_at` is evaluated only on the caller's clock.
A caller that can supply `now` to both authorize and execute resurrects an
expired approval.

Severity: P1/P2 (depends on whether the deployment lets the caller set
`now`; `now` is a public parameter used for model clocks and tests).
Classification: REPRODUCED at the API level.
"""

from __future__ import annotations

import time

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))))
from redteam.deepseek_redteam_round2 import _common as K
from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    GovernanceKernel, Principal, SecurityContext, issue_approval,
)
from morrison_governance.kernel.continuity import InMemoryContinuityStore

DOMAINS = [OmegaDomain.CYBERSECURITY, OmegaDomain.DATA_PRIVACY,
           OmegaDomain.FINANCE]
MANIFEST = {"delete_bucket": ["infra.destructive"]}
CALL = {"tool": "delete_bucket", "args": {"bucket": "prod"}}
PAST = time.time() - 100_000


def _approval():
    return issue_approval(
        CALL, "security-review", K.SIGNING_KEY, ttl_s=10,
        principal="agent", tenant="acme", now=PAST)


def _kernel(art):
    ctx = SecurityContext(
        principal=Principal(id="agent", tenant="acme"),
        signing_key=K.SIGNING_KEY,
        trusted_issuers=K.TRUSTED_ISSUERS,
        tool_manifest=dict(MANIFEST),
        unknown_tool_policy="escalate",
        continuity_store=InMemoryContinuityStore(),
        approvals=(art,),
    )
    return GovernanceKernel(GovernanceLayer(domains=DOMAINS, log_all=False), ctx)


def main() -> dict:
    K.header("R2-H caller-clock approval expiry bypass")
    art = _approval()

    wall_kernel = _kernel(art)
    wall_decision = wall_kernel.authorize(CALL)

    rewind_kernel = _kernel(art)
    rewind_decision = rewind_kernel.authorize(CALL, now=PAST + 5)
    # execute() must be given the same caller clock as authorize().
    rec2 = K.Recorder()
    executed_rewound = rewind_kernel.execute(
        rewind_decision, rec2, now=PAST + 5)

    control_kernel = _kernel(art)
    control_decision = control_kernel.authorize(CALL, now=PAST + 5)
    rec3 = K.Recorder()
    control_exec = control_kernel.execute(control_decision, rec3)  # wall now

    print("wall authorize:", wall_decision.verdict,
          "-", wall_decision.authorization.get("reason"))
    print("rewound authorize:", rewind_decision.verdict,
          "-", rewind_decision.authorization.get("reason"))
    print("rewound execute:", executed_rewound, "effects:", len(rec2.calls))
    print("control execute (wall clock):", control_exec,
          "effects:", len(rec3.calls))

    falsified = (
        wall_decision.verdict == "ESCALATE"
        and rewind_decision.verdict == "PERMIT"
        and executed_rewound[0] is True
        and len(rec2.calls) == 1
        and control_exec[0] is False
        and len(rec3.calls) == 0
    )

    return K.emit({
        "id": "R2-H",
        "title": "Expired approval is accepted under a caller-supplied clock",
        "invariant": ("An approval past its `expires_at` is refused, and a "
                      "caller-supplied clock cannot extend a lease."),
        "source": [
            "morrison_governance/kernel/trust.py:ApprovalArtifact.verify",
            "morrison_governance/kernel/gate.py:verified_approval(now)",
            "morrison_governance/kernel/gate.py:_lease_problem",
        ],
        "severity": "P1/P2",
        "classification": "REPRODUCED (API-level)",
        "falsified": bool(falsified),
        "wall_authorize": {
            "verdict": wall_decision.verdict,
            "reason": wall_decision.authorization.get("reason"),
        },
        "rewound_authorize": {
            "verdict": rewind_decision.verdict,
            "reason": rewind_decision.authorization.get("reason"),
        },
        "rewound_execute": {"executed": executed_rewound[0],
                            "detail": executed_rewound[1],
                            "effects": rec2.calls},
        "wall_execute_control": {"executed": control_exec[0],
                                 "detail": control_exec[1],
                                 "effects": rec3.calls},
        "note": (
            "The decision-freshness wall cross-check still refuses the "
            "wall-clock execution, which is why the exploit must supply the "
            "same rewound `now` to both authorize and execute. The approval "
            "expiry itself has no wall-clock independent check."),
    })


if __name__ == "__main__":
    main()
