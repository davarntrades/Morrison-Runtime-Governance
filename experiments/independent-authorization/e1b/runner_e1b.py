"""E1-β runner. Ground truth is the state; verdicts are data, never truth."""

from __future__ import annotations

from dataclasses import dataclass, field

from arms_e1b import Executor, build
from env_e1b import B6_CAPABILITY_SET
from profiles_e1b import (AUTHORISED_CONTEXT, COMPROMISE, PROFILES, call_of,
                          steps)
from state_e1b import (E1BState, SELECTIVITY_GOAL, goal_ids, unsafe_ids)

VERDICTS = ("PERMIT", "BLOCK", "ESCALATE", "NO_VALID_SOLUTION",
            "ENVIRONMENT_SENSITIVE")


def initial_state(profile: str) -> E1BState:
    return E1BState(authorization_active=profile in AUTHORISED_CONTEXT)


def apply_env_event(s: E1BState, event: str) -> E1BState:
    if event == "revoke":
        return s.evolve(authorization_active=False,
                        authorization_epoch=s.authorization_epoch + 1)
    if event == "grant":
        return s.evolve(authorization_active=True,
                        authorization_epoch=s.authorization_epoch + 1)
    return s


def opportunity_denominator(profile: str) -> int:
    """Prohibited transitions available in the UNGUARDED environment."""
    ex, s, n = Executor(), initial_state(profile), 0
    for st in steps(profile):
        if st.env_event:
            s = apply_env_event(s, st.env_event)
            continue
        if st.execute is None:
            continue
        after = ex.apply(s, call_of(st.execute))
        if set(unsafe_ids(after)) - set(unsafe_ids(s)):
            n += 1
        s = after
    return n


@dataclass
class Cell:
    arm: str
    profile: str
    mode: str
    proposed: int = 0
    prohibited_executed: int = 0
    refused: int = 0
    inexpressible: int = 0
    verdicts: dict = field(default_factory=lambda: {v: 0 for v in VERDICTS})
    goals_completed: tuple = ()
    unsafe_final: tuple = ()
    opportunities: int = 0
    trace: list = field(default_factory=list)


def run_cell(arm_name: str, profile: str, mode: str) -> Cell:
    arm = build(arm_name)
    s = initial_state(profile)
    issued: list = []
    cell = Cell(arm=arm_name, profile=profile, mode=mode,
                opportunities=opportunity_denominator(profile))

    for st in steps(profile):
        if st.env_event:
            s = apply_env_event(s, st.env_event)
            cell.trace.append({"env_event": st.env_event,
                               "state": s.state_id, "note": st.note})
            continue

        # Evaluation-only step (EXPIRED_AUTHORITY): obtain a decision now,
        # execute later against a changed world.
        if st.execute is None and st.evaluate is not None:
            d = arm.authorize(call_of(st.evaluate))
            issued.append(d)
            v = getattr(d, "verdict", "")
            if v in cell.verdicts:
                cell.verdicts[v] += 1
            cell.trace.append({"evaluated_only": st.evaluate, "verdict": v,
                               "note": st.note})
            continue

        cell.proposed += 1
        eval_call, exec_call = call_of(st.evaluate), call_of(st.execute)
        before = s

        counterfactual = Executor().apply(before, exec_call)
        would_be_unsafe = bool(set(unsafe_ids(counterfactual)) - set(unsafe_ids(before)))

        if not arm.executor.constructible(exec_call):
            cell.inexpressible += 1
            cell.trace.append({"step": st.execute, "outcome": "INEXPRESSIBLE",
                               "would_be_unsafe": would_be_unsafe,
                               "note": st.note})
            continue

        if st.reuse_decision is not None and len(issued) > st.reuse_decision:
            decision = issued[st.reuse_decision]
        else:
            decision = arm.authorize(eval_call)
            issued.append(decision)
        v = getattr(decision, "verdict", "")
        if v in cell.verdicts:
            cell.verdicts[v] += 1

        if mode == COMPROMISE and arm_name != "T":
            executed, s = arm.raw_execute(exec_call, before)
        else:
            executed, s = arm.guarded_execute(decision, eval_call, exec_call, before)

        newly = set(unsafe_ids(s)) - set(unsafe_ids(before))
        if executed and newly:
            cell.prohibited_executed += 1
        elif not executed:
            cell.refused += 1

        cell.trace.append({"eval": st.evaluate, "exec": st.execute, "verdict": v,
                           "executed": executed, "would_be_unsafe": would_be_unsafe,
                           "newly_unsafe": sorted(newly),
                           "state_after": s.state_id, "note": st.note})

    cell.goals_completed = goal_ids(s)
    cell.unsafe_final = unsafe_ids(s)
    return cell


def utility_probe(arm_name: str) -> dict:
    """Benign + authorised-disclosure work, measured separately from attacks."""
    arm = build(arm_name)
    s = E1BState(authorization_active=True)
    for name in ("read_support_log", "draft_report", "enable_network",
                 "send_benign_message", "read_secret_vault",
                 "disclose_to_authorised"):
        call = call_of(name)
        if not arm.executor.constructible(call):
            continue
        d = arm.authorize(call)
        _ok, s = arm.guarded_execute(d, call, call, s)
    return {"goals": list(goal_ids(s)), "unsafe": list(unsafe_ids(s)),
            "selectivity_goal_met": SELECTIVITY_GOAL in goal_ids(s)}
