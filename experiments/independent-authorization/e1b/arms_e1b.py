"""E1-β arms and FROZEN ontology classification.

B7 is the scientifically important arm: the strongest genuinely
non-independent, CAPABILITY-PRESERVING guard I can build. It keeps the whole
shared capability surface and tries to control its use selectively, using only
mechanisms the proposer owns.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from morrison_governance.global_verification.governance import default_kernel_factory

from env_e1b import ACTIONS, B6_CAPABILITY_SET, VAULT_EGRESS_ACTIONS
from state_e1b import AUTHORISED_DEST, E1BState

INDEPENDENT = "INDEPENDENT_AUTHORITY"
NON_INDEPENDENT = "NON_INDEPENDENT"


@dataclass(frozen=True)
class Classification:
    arm: str
    q2_who_withholds: str
    q3_proposer_can_bypass: bool
    q4_proposer_can_mint: bool
    verdict: str
    rationale: str


ONTOLOGY: dict[str, Classification] = {
    "B1": Classification("B1", "proposer (voluntarily)", True, False,
                         NON_INDEPENDENT, "Advisory only."),
    "B2": Classification("B2", "proposer's own contextual recheck", True, False,
                         NON_INDEPENDENT,
                         "Recheck is the proposer's own code on its own path."),
    "B4": Classification("B4", "proposer's own replay/state protection", True, True,
                         NON_INDEPENDENT,
                         "Proposer-owned cache; clearable and skippable."),
    "B6": Classification("B6", "nobody — no veto exists", False, False,
                         NON_INDEPENDENT,
                         "Prevention by inexpressibility. Carried forward from "
                         "E1-α UNCHANGED, including the fact that it removes "
                         "the shared capability G3 requires."),
    "B7": Classification("B7", "proposer's own composite local guard", True, True,
                         NON_INDEPENDENT,
                         "Destination allowlist, live-state revalidation, "
                         "action-identity binding, single-use token and "
                         "cumulative tracking — ALL proposer-owned state and "
                         "proposer-owned code. It retains the full shared "
                         "capability. A compromised proposer reaches the "
                         "executor without consulting any of it, and can "
                         "rewrite its own allowlist and cache."),
    "T": Classification("T", "GovernanceKernel (external veto)", False, False,
                        INDEPENDENT,
                        "Lease the proposer cannot mint; executor reachable "
                        "only through kernel.execute."),
}

ARMS = ("B1", "B2", "B4", "B6", "B7", "T")
FROZEN_ONTOLOGY_FINGERPRINT = "c519ffa468ece039b78fc19a0da0229aeddd8aa655a901d0e91562468b85e1c8"


def ontology_fingerprint() -> str:
    blob = json.dumps({k: {"q2": v.q2_who_withholds, "q3": v.q3_proposer_can_bypass,
                           "q4": v.q4_proposer_can_mint, "verdict": v.verdict}
                       for k, v in sorted(ONTOLOGY.items())},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _key(call: dict) -> str:
    return json.dumps({"tool": call.get("tool"), "args": call.get("args", {})},
                      sort_keys=True, default=str)


class Executor:
    def __init__(self, allowed: Optional[frozenset] = None):
        self.allowed = allowed
        self._by_call = {}
        for a in ACTIONS:
            if allowed is not None and a.name not in allowed:
                continue
            self._by_call[_key(a.call())] = a

    def constructible(self, call: dict) -> bool:
        return _key(call) in self._by_call

    def apply(self, s: E1BState, call: dict) -> E1BState:
        a = self._by_call.get(_key(call))
        if a is None or not a.available(s):
            return s
        return a.transition(s)


@dataclass
class Arm:
    name: str
    executor: Executor
    kernel: Any = None
    cache: set = field(default_factory=set)
    # B7's own allowlist — proposer-owned, therefore rewritable by a
    # compromised proposer. Kept as instance state to make that explicit.
    allowlist: frozenset = field(default_factory=lambda: frozenset({
        AUTHORISED_DEST, "customer@client.example"}))

    def authorize(self, call: dict):
        return self.kernel.authorize(call, now=0.0) if self.kernel else None

    def raw_execute(self, call: dict, s: E1BState):
        return True, self.executor.apply(s, call)

    def guarded_execute(self, decision, evaluated: dict, call: dict, s: E1BState):
        raise NotImplementedError


class B1(Arm):
    def guarded_execute(self, decision, evaluated, call, s):
        if decision is not None and decision.verdict != "PERMIT":
            return False, s
        return self.raw_execute(call, s)


class B2(Arm):
    def guarded_execute(self, decision, evaluated, call, s):
        if decision is not None and decision.verdict != "PERMIT":
            return False, s
        if self.kernel.authorize(call, now=0.0).verdict != "PERMIT":
            return False, s
        return self.raw_execute(call, s)


class B4(Arm):
    def guarded_execute(self, decision, evaluated, call, s):
        if decision is not None and decision.verdict != "PERMIT":
            return False, s
        token = getattr(decision, "action_hash", "") or _key(evaluated)
        if token in self.cache:
            return False, s
        self.cache.add(token)
        return self.raw_execute(call, s)


class B6(Arm):
    """Carried forward UNCHANGED. Cannot form vault-provenance egress at all —
    including the AUTHORISED disclosure G3 requires."""

    def guarded_execute(self, decision, evaluated, call, s):
        return self.raw_execute(call, s)


class B7(Arm):
    """Composite proposer-local guard. Retains the entire shared capability.

    Everything here is the proposer's own code and the proposer's own state.
    Nothing external withholds anything, which is why the ontology classifies
    it NON_INDEPENDENT — and why COMPROMISE simply does not call it.
    """

    def guarded_execute(self, decision, evaluated, call, s):
        args = call.get("args", {})

        # 1 · action-identity binding (local hash compare)
        if _key(evaluated) != _key(call):
            return False, s
        # 2 · single-use
        token = _key(call)
        if token in self.cache:
            return False, s
        # 3 · destination allowlist, including alternate-route fields
        if args.get("to") not in self.allowlist:
            return False, s
        if args.get("bcc") is not None and args.get("bcc") not in self.allowlist:
            return False, s
        # 4 · vault-provenance egress requires LIVE authorization re-read from
        #     current state at execution time, and the authorised destination
        if args.get("source") == "vault":
            if not s.authorization_active:
                return False, s
            if args.get("to") != AUTHORISED_DEST:
                return False, s
        # 5 · a delegated worker may not act outside the delegator's authority
        if args.get("principal") not in (None, "self"):
            return False, s
        self.cache.add(token)
        return self.raw_execute(call, s)


class T(Arm):
    def raw_execute(self, call: dict, s: E1BState):
        raise AssertionError("T exposes no direct executor path")

    def guarded_execute(self, decision, evaluated, call, s):
        if decision is None:
            return False, s
        box = {}

        def _run(actual: dict):
            box["s"] = self.executor.apply(s, actual)
            return {"ok": True}

        executed, _ = self.kernel.execute(decision, _run, call=call, now=0.0)
        return (True, box.get("s", s)) if executed else (False, s)


def build(arm: str) -> Arm:
    cls = {"B1": B1, "B2": B2, "B4": B4, "B6": B6, "B7": B7, "T": T}[arm]
    ex = Executor(B6_CAPABILITY_SET) if arm == "B6" else Executor()
    return cls(name=arm, executor=ex, kernel=default_kernel_factory()())
