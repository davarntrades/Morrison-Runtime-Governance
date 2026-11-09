"""R2-G — caller-supplied clock bypasses the revocation of an earlier PERMIT.

Declared invariant (source):
    kernel/gate.py, `_lease_problem`:
        "this transition was subsequently refused in the same session (...);
         the earlier PERMIT is void"
    kernel/gate.py, `_lease_problem` wall-clock clause:
        "a caller-supplied clock cannot extend a lease"
    kernel/continuity.py, `InMemoryContinuityStore.revoke`:
        `revoked_at = time.time()`  (wall clock)

Observed (fixture: a shared-resource aggregate-outflow rule, limit 25,000):

    T = time.time() + 10_000_000          # caller's model clock
    first  transfer {from: SHARED, to: A1, amount: 20000}
        authorize(now=T) -> PERMIT, reserved
    second identical transfer
        authorize(now=T) -> BLOCK (outflow_SHARED), which revokes the
        semantic hash of the first decision.
    execute(first, now=T + 1)            -> (True, ...)  ** effect recorded **
    execute(first, now=time.time())      -> refused: "the earlier PERMIT is void"

The revocation timestamp is wall time. `_lease_problem` compares it to the
caller's `now`. A caller whose `now` is far ahead of wall time sees
`now - revoked_at > decision_ttl_s`, so the revocation is treated as
expired and the earlier PERMIT executes. The decision-freshness check has a
separate `issued_wall` cross-check; the revocation check does not.

Control: the same sequence on the wall clock refuses execution.

Severity: P1 (executes a transition the session subsequently refused).
Classification: REPRODUCED at the API level. Normal wall-clock deployments
are not affected; the public `now` parameter is what makes it reachable.
"""

from __future__ import annotations

import json
import time

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))))
from redteam.deepseek_redteam_round2 import _common as K
from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule
from morrison_governance.kernel import GovernanceKernel, Principal, SecurityContext
from morrison_governance.kernel.continuity import InMemoryContinuityStore

DOMAINS = [OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY,
           OmegaDomain.DATA_PRIVACY, OmegaDomain.ENTERPRISE,
           OmegaDomain.COMPLIANCE]
LIMIT = 25_000
CALL = {"tool": "transfer",
        "args": {"from": "SHARED", "to": "A1", "amount": 20_000}}


def _outflow_rule():
    def check(state):
        args = state.get("args")
        args = json.loads(args) if isinstance(args, str) else (args or {})
        if state.get("tool") != "transfer" or args.get("from") != "SHARED":
            return False
        total = 0
        for i in range(int(state.get("step", 0))):
            prior = state.get(f"step_{i}_args") or {}
            if (state.get(f"step_{i}_tool") == "transfer"
                    and prior.get("from") == "SHARED"):
                total += int(prior.get("amount", 0))
        return total + int(args.get("amount", 0)) > LIMIT
    return OmegaRule(OmegaDomain.CUSTOM, "outflow_SHARED",
                     "aggregate outflow from SHARED", check)


def _kernel():
    ctx = SecurityContext(
        principal=Principal(id="agent-a", tenant="acme"),
        continuity_store=InMemoryContinuityStore(),
        tool_manifest={"transfer": ["payment.move_funds"]},
        policy_values={"payment_auto_approve_max": LIMIT},
        resource_scopes=lambda call: (["account:SHARED"]
                                      if call.get("tool") == "transfer"
                                      else None),
    )
    layer = GovernanceLayer(domains=DOMAINS, custom_rules=[_outflow_rule()],
                            log_all=False)
    return GovernanceKernel(layer, ctx)


def _sequence(now_auth, now_exec):
    k = _kernel()
    effects = []
    first = k.authorize(CALL, now=now_auth)
    second = k.authorize(CALL, now=now_auth)
    outcome = k.execute(first, lambda a: effects.append(a), now=now_exec)
    return {
        "first_verdict": first.verdict,
        "second_verdict": second.verdict,
        "second_rule": second.rule,
        "revocation": k.store.revocation(k.continuity_key,
                                         first.semantic_hash),
        "execute_result": {"executed": outcome[0], "detail": outcome[1]},
        "effects": effects,
    }


def main() -> dict:
    K.header("R2-G caller-clock revocation bypass")

    model = time.time() + 10_000_000
    far = _sequence(model, model + 1)
    wall = _sequence(time.time(), time.time())

    print("far-future clock:")
    print("  first:", far["first_verdict"], "second:", far["second_verdict"],
          far["second_rule"])
    print("  execute:", far["execute_result"], "effects:", len(far["effects"]))
    print("wall clock:")
    print("  first:", wall["first_verdict"], "second:", wall["second_verdict"],
          wall["second_rule"])
    print("  execute:", wall["execute_result"], "effects:", len(wall["effects"]))

    falsified = (
        far["first_verdict"] == "PERMIT"
        and far["second_verdict"] == "BLOCK"
        and far["second_rule"] == "outflow_SHARED"
        and far["execute_result"]["executed"] is True
        and len(far["effects"]) == 1
        and wall["execute_result"]["executed"] is False
        and len(wall["effects"]) == 0
    )

    return K.emit({
        "id": "R2-G",
        "title": "Caller clock outruns the wall-clock revocation window",
        "invariant": ("A PERMIT is void once the same transition is refused "
                      "in the same session; a caller-supplied clock cannot "
                      "extend a lease."),
        "source": [
            "morrison_governance/kernel/gate.py:_lease_problem (revocation clause)",
            "morrison_governance/kernel/continuity.py:InMemoryContinuityStore.revoke",
        ],
        "severity": "P1",
        "classification": "REPRODUCED (API-level)",
        "falsified": bool(falsified),
        "far_future": far,
        "wall_control": wall,
        "note": (
            "`revoke()` stamps `time.time()`; `_lease_problem` compares the "
            "caller's `now` against that stamp. A caller whose clock is more "
            "than decision_ttl_s ahead of wall time makes the revocation look "
            "ancient. Decision freshness has an `issued_wall` cross-check; "
            "revocation does not. Under a normal wall-clock deployment the "
            "control path refuses."),
    })


if __name__ == "__main__":
    main()
