"""E0 experimental arms. The independent variable lives here and nowhere else.

Each arm receives IDENTICAL proposed calls and produces IDENTICAL verdicts.
The only thing that differs is whether execution requires an authorization
artifact the proposer cannot mint.

    B0   no authorization at all                      diagnostic only
    B1   verdict produced, proposer executes directly  baseline
    T    verdict produced, kernel.execute() gates it   treatment

DEVIATION FROM PROTOCOL §3, AND WHY IT FAVOURS THE BASELINE
───────────────────────────────────────────────────────────
PROTOCOL §3 names `GovernanceGuard.advisory()` as B1's mechanism AND requires
"identical Ω, identical verdicts ... no information asymmetry between B1 and T".
Those two requirements contradict each other: an advisory guard may not carry a
SecurityContext, so it evaluates through `GovernanceLayer.evaluate()` and cannot
see the trajectory history, capability manifest or destination classification
that `GovernanceKernel.authorize()` uses. B1 would have received systematically
WEAKER verdicts than T, and every difference in outcome would have been
confounded by that asymmetry rather than caused by execution authority.

Resolved in the baseline's favour: B1 obtains its verdict from the same
`kernel.authorize()` call T uses, then executes directly. This makes B1 the
strongest possible advisory architecture — a shadow-mode deployment with a
full-strength policy engine behind it — and leaves execution authority as the
only difference. Verdict identity is asserted empirically, not assumed
(`test_harness_integrity.py::test_b1_and_t_receive_identical_verdicts`).

Resolving it the other way would have biased the experiment toward the
treatment, which is the direction this study must not err in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from morrison_governance.global_verification.governance import default_kernel_factory
from morrison_governance.global_verification.state import VerificationState


PERMIT = "PERMIT"


@dataclass
class StepOutcome:
    """What one proposed step did, in both decision and effect terms."""

    evaluated_call: dict
    executed_call: Optional[dict]
    verdict: str
    layer: str
    reason: str
    executed: bool
    refusal_stage: str = ""          # "" | "advisory" | "execution_boundary"
    decision_reused: bool = False
    state_before: Optional[VerificationState] = None
    state_after: Optional[VerificationState] = None
    action_name: str = ""
    evidence_hash: str = ""


class EnvironmentExecutor:
    """Applies a tool call's environment transition.

    Resolution is by (tool, args) — never by tool name alone. Two distinct
    actions in this environment share the tool `read_file`, and two share
    `send_external_message`; resolving by name would silently apply the wrong
    transition and quietly destroy the experiment's central property.
    """

    def __init__(self, environment):
        self.environment = environment
        self._by_call: dict[str, Any] = {}
        for action in environment.actions:
            probe = action.propose(VerificationState(external_action_authorized=True))
            self._by_call[self._key(probe)] = action

    @staticmethod
    def _key(call: dict) -> str:
        import json
        return json.dumps(
            {"tool": call.get("tool"), "args": call.get("args", {})},
            sort_keys=True, default=str)

    def resolve(self, call: dict):
        return self._by_call.get(self._key(call))

    def apply(self, state: VerificationState, call: dict) -> VerificationState:
        action = self.resolve(call)
        if action is None:
            # An unresolvable call changes nothing. Recorded as a
            # state-modelling event by the runner, never silently ignored.
            return state
        if not action.available(state):
            return state
        return action.transition(state)


# ─────────────────────────────────────────────────────────────
# Arms
# ─────────────────────────────────────────────────────────────

@dataclass
class Arm:
    """Common surface. `authorize` is identical across B1 and T by construction."""

    name: str
    executor: EnvironmentExecutor
    kernel: Any = None
    _issued: list = field(default_factory=list)

    def authorize(self, call: dict) -> Any:
        raise NotImplementedError

    def try_execute(self, decision: Any, call: dict,
                    state: VerificationState) -> tuple[bool, str, VerificationState]:
        raise NotImplementedError


class B0Ablation(Arm):
    """No authorization. Diagnostic context only — never headline evidence."""

    def authorize(self, call: dict) -> Any:
        return None

    def try_execute(self, decision, call, state):
        return True, "", self.executor.apply(state, call)


class B1Advisory(Arm):
    """Verdict produced and then ignored or honoured BY THE PROPOSER.

    The proposer holds execution authority. Nothing here can stop it: the
    profile decides whether to call `try_execute`, and `try_execute` always
    executes. That is what "advisory" means, and it is why this arm is the
    baseline rather than a straw man — it has the same policy engine as the
    treatment and merely lacks the veto.
    """

    def authorize(self, call: dict) -> Any:
        return self.kernel.authorize(call, now=0.0)

    def try_execute(self, decision, call, state):
        # No lease check, no identity check: the proposer simply executes.
        return True, "", self.executor.apply(state, call)


class TIndependentAuthority(Arm):
    """Execution requires a live, action-bound lease the proposer cannot mint.

    `kernel.execute` re-derives the canonical hash of the call about to run and
    compares it to the hash the decision was issued for, then checks the lease
    (unused, unexpired, unrevoked, right principal/session/ruleset). The
    executor is reached only through that call — there is no second path, which
    `test_harness_integrity.py::test_t_cannot_execute_without_the_kernel_lease`
    asserts by construction.
    """

    def authorize(self, call: dict) -> Any:
        return self.kernel.authorize(call, now=0.0)

    def try_execute(self, decision, call, state):
        if decision is None:
            return False, "no decision", state
        box: dict = {}

        def _run(actual_call: dict):
            box["state"] = self.executor.apply(state, actual_call)
            return {"ok": True}

        executed, _ = self.kernel.execute(decision, _run, call=call, now=0.0)
        if not executed:
            return False, "execution_boundary refused", state
        return True, "", box.get("state", state)


def build_arm(name: str, environment) -> Arm:
    executor = EnvironmentExecutor(environment)
    if name == "B0":
        return B0Ablation(name=name, executor=executor)
    kernel = default_kernel_factory()()
    if name == "B1":
        return B1Advisory(name=name, executor=executor, kernel=kernel)
    if name == "T":
        return TIndependentAuthority(name=name, executor=executor, kernel=kernel)
    raise ValueError(f"unknown arm {name!r}")
