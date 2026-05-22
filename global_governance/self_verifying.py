"""Self-verifying controller — governance integrity.

A controller you cannot trust to verify itself is a single point of
silent failure. This wrapper checks its own decision against two
invariants before emitting it, and attests the result into a hash
chain:

  1. Determinism — evaluating the same plan twice yields the same
     verdict + layer. (No RNG / clock leaked into the decision path.)
  2. Strict-strengthening monotonicity — if any prefix of the plan is
     blocked, the full plan must also be blocked. A controller that
     permits a superset of a blocked prefix has violated the core
     invariant Safe(local) ⇏ Safe(global).

If either invariant fails, the controller FAILS CLOSED (verdict=BLOCK,
layer=integrity_violation) rather than emit a decision it cannot
vouch for. The attestation is a hash chain so an external reviewer can
verify the decision sequence was not tampered with."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer


@dataclass
class VerifiedResult:
    permitted: bool
    verdict: str
    layer: str
    determinism_ok: bool
    monotonicity_ok: bool
    integrity_ok: bool
    attestation: str
    reason: str = ""

    def as_dict(self) -> dict:
        return {"permitted": self.permitted, "verdict": self.verdict,
                "layer": self.layer,
                "determinism_ok": self.determinism_ok,
                "monotonicity_ok": self.monotonicity_ok,
                "integrity_ok": self.integrity_ok,
                "attestation": self.attestation, "reason": self.reason}


def _attest(prev: str, plan: list, verdict: str, integrity_ok: bool) -> str:
    payload = json.dumps({"prev": prev, "plan": plan, "verdict": verdict,
                          "integrity_ok": integrity_ok}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


class SelfVerifyingController:
    def __init__(self, governance: GovernanceLayer):
        self.governance = governance
        self._chain = "GENESIS"

    def _eval(self, plan: list):
        return (self.governance.evaluate_plan(plan) if len(plan) > 1
                else self.governance.evaluate(plan[0]))

    def evaluate_verified(self, plan: list) -> VerifiedResult:
        r1 = self._eval(plan)
        r2 = self._eval(plan)
        determinism_ok = (r1.verdict.value, r1.layer) == (
            r2.verdict.value, r2.layer)

        # monotonicity: find the first blocked prefix; if one exists the
        # full plan must be blocked too.
        monotonicity_ok = True
        if len(plan) > 1:
            for k in range(1, len(plan)):
                pref = self._eval(plan[:k])
                if not pref.permitted:
                    if r1.permitted:
                        monotonicity_ok = False
                    break

        integrity_ok = determinism_ok and monotonicity_ok
        if integrity_ok:
            verdict, layer = r1.verdict.value, r1.layer
            permitted = r1.permitted
            reason = r1.reason
        else:
            verdict, layer = "BLOCK", "integrity_violation"
            permitted = False
            reason = ("self-verification failed (fail-closed): "
                      f"determinism_ok={determinism_ok}, "
                      f"monotonicity_ok={monotonicity_ok}")

        self._chain = _attest(self._chain, plan, verdict, integrity_ok)
        return VerifiedResult(
            permitted=permitted, verdict=verdict, layer=layer,
            determinism_ok=determinism_ok,
            monotonicity_ok=monotonicity_ok, integrity_ok=integrity_ok,
            attestation=self._chain, reason=reason)
