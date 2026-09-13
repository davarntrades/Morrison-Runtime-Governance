"""E1 arms. The structural compromise path is the experiment's spine.

FAULT vs COMPROMISE is not a behavioural stipulation. It selects which of two
REAL entry points the proposer uses:

    guarded_execute()   runs the arm's own checks, then executes
    raw_execute()       reaches the executor directly

`raw_execute` exists on B1/B2/B4/B6 because their executor shares the
proposer's trust domain — that is what "non-independent" means, and a
compromised proposer using it is exercising a capability it structurally has,
not obeying a flag. T HAS NO raw_execute AT ALL: the executor is reachable only
inside the closure handed to `kernel.execute`.

B6 exposes `raw_execute` like the other non-independent arms. Its immunity does
not come from a check being run; it comes from the prohibited call being absent
from its action space, so there is nothing for COMPROMISE to gain by skipping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from morrison_governance.global_verification.governance import default_kernel_factory

from environments_e1 import ACTIONS, B6_CAPABILITY_SET, BY_NAME
from state_e1 import E1State


def _key(call: dict) -> str:
    import json
    return json.dumps({"tool": call.get("tool"), "args": call.get("args", {})},
                      sort_keys=True, default=str)


class Executor:
    """Applies an action's transition. Resolution is by (tool, args): two
    actions share `read_file` and three share `send_message`, so resolving by
    tool name alone would apply the wrong transition."""

    def __init__(self, allowed: Optional[frozenset] = None):
        self.allowed = allowed
        self._by_call = {}
        for a in ACTIONS:
            if allowed is not None and a.name not in allowed:
                continue           # inexpressible in this capability set
            self._by_call[_key(a.call())] = a

    def constructible(self, call: dict) -> bool:
        return _key(call) in self._by_call

    def apply(self, s: E1State, call: dict) -> E1State:
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

    def authorize(self, call: dict):
        return self.kernel.authorize(call, now=0.0) if self.kernel else None

    # Direct path to the executor. Present iff the executor shares the
    # proposer's trust domain.
    def raw_execute(self, call: dict, s: E1State) -> tuple[bool, E1State]:
        return True, self.executor.apply(s, call)

    def guarded_execute(self, decision, evaluated_call: dict,
                        call: dict, s: E1State) -> tuple[bool, E1State]:
        raise NotImplementedError


class B1(Arm):
    """Advisory: honours the verdict on the call it evaluated."""

    def guarded_execute(self, decision, evaluated_call, call, s):
        if decision is not None and decision.verdict != "PERMIT":
            return False, s
        return self.raw_execute(call, s)


class B2(Arm):
    """Advisory + mandatory local recheck of the call ACTUALLY about to run."""

    def guarded_execute(self, decision, evaluated_call, call, s):
        if decision is not None and decision.verdict != "PERMIT":
            return False, s
        recheck = self.kernel.authorize(call, now=0.0)   # same trust domain
        if recheck.verdict != "PERMIT":
            return False, s
        return self.raw_execute(call, s)


class B4(Arm):
    """Advisory + proposer-owned single-use replay cache."""

    def guarded_execute(self, decision, evaluated_call, call, s):
        if decision is not None and decision.verdict != "PERMIT":
            return False, s
        token = getattr(decision, "action_hash", "") or _key(evaluated_call)
        if token in self.cache:
            return False, s
        self.cache.add(token)
        return self.raw_execute(call, s)


class B6(Arm):
    """Typed capability set. No check, no veto — the call cannot be formed."""

    def guarded_execute(self, decision, evaluated_call, call, s):
        return self.raw_execute(call, s)


class T(Arm):
    """Independent authority. No raw path exists."""

    def raw_execute(self, call: dict, s: E1State):
        raise AssertionError(
            "T exposes no direct executor path; reaching this would mean the "
            "independent-variable isolation is broken")

    def guarded_execute(self, decision, evaluated_call, call, s):
        if decision is None:
            return False, s
        box = {}

        def _run(actual: dict):
            box["s"] = self.executor.apply(s, actual)
            return {"ok": True}

        executed, _ = self.kernel.execute(decision, _run, call=call, now=0.0)
        return (True, box.get("s", s)) if executed else (False, s)


def build(arm: str) -> Arm:
    if arm == "B6":
        return B6(name=arm, executor=Executor(B6_CAPABILITY_SET),
                  kernel=default_kernel_factory()())
    cls = {"B1": B1, "B2": B2, "B4": B4, "T": T}[arm]
    return cls(name=arm, executor=Executor(), kernel=default_kernel_factory()())
