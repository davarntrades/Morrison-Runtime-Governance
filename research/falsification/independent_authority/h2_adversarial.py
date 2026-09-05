"""H2 expanded adversarial model + the stronger candidate H2'.

H2' (candidate): if consequential execution is causally dependent on successful
independent evidence commitment, then no consequential transition can execute
without producing independently verifiable evidence.

This module tests H2' by making commit ORDER explicit and then partitioning the
two systems. The result is the atomicity finding: with two independent failure
domains and no atomic commit across them, ordering does not eliminate
divergence -- it only chooses WHICH side diverges.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from morrison_governance.kernel.evidence import EvidenceChain, EvidenceRecord

KEY = b"independent-evidence-authority-study"

EXECUTE_THEN_RECORD = "execute_then_record"
RECORD_THEN_EXECUTE = "record_then_execute"
TWO_PHASE_INTENT_OUTCOME = "two_phase_intent_outcome"


@dataclass
class Outcome:
    order: str
    condition: str
    executed_externally: bool
    recorded_intent: bool
    recorded_outcome: bool
    integrity_valid: bool
    # what an independent verifier can conclude from L_I alone
    verifier_can_establish_execution: bool
    verifier_knows_something_attempted: bool
    completeness_violation: bool      # executed, verifier cannot establish it
    soundness_violation: bool         # verifier would assert an execution that did not happen
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        return d


def _chain() -> EvidenceChain:
    return EvidenceChain(key=KEY)


def _rec(chain: EvidenceChain, phase: str, executed: bool, result: str) -> None:
    chain.append(EvidenceRecord(
        seq=0, timestamp=0.0, actor="agent", tenant="modeled",
        action_hash="x2--export-->OMEGA",
        proposed={"tool": "export", "args": {"to": "OMEGA"}},
        decision="PERMIT", layer=phase, executed=executed, execution_result=result,
    ))


def run_condition(order: str, condition: str) -> Outcome:
    """Simulate one failure condition under one commit ordering."""
    chain = _chain()
    executed = False
    intent = False
    outcome = False

    if order == EXECUTE_THEN_RECORD:
        executed = condition not in {"execution_fails"}
        if condition == "recorder_crash_after_execution":
            pass                                  # record never written
        elif condition == "partition_after_execution":
            pass                                  # record cannot reach custody
        elif condition == "success_reported_as_failure":
            _rec(chain, "execution", False, "failed"); outcome = True
        elif condition == "failure_reported_as_success":
            executed = False
            _rec(chain, "execution", True, "ok"); outcome = True
        elif executed:
            _rec(chain, "execution", True, "ok"); outcome = True

    elif order == RECORD_THEN_EXECUTE:
        if condition == "evidence_commit_fails":
            executed = False                      # gated: no evidence, no execution
        else:
            _rec(chain, "execution", True, "ok"); outcome = True
            if condition in {"execution_fails_after_evidence",
                             "partition_after_evidence_commit"}:
                executed = False                  # evidence asserts an execution
            else:
                executed = True

    elif order == TWO_PHASE_INTENT_OUTCOME:
        if condition == "evidence_commit_fails":
            executed = False
        else:
            _rec(chain, "intent", False, "intent_recorded"); intent = True
            if condition in {"recorder_crash_after_execution",
                             "partition_after_execution"}:
                executed = True                   # outcome record never lands
            elif condition == "execution_fails_after_evidence":
                executed = False
                _rec(chain, "execution", False, "failed"); outcome = True
            else:
                executed = True
                _rec(chain, "execution", True, "ok"); outcome = True

    integrity_ok, _ = chain.verify()
    can_establish = any(r.executed for r in chain.records)
    knows_attempted = bool(chain.records)

    return Outcome(
        order=order,
        condition=condition,
        executed_externally=executed,
        recorded_intent=intent,
        recorded_outcome=outcome,
        integrity_valid=integrity_ok,
        verifier_can_establish_execution=can_establish,
        verifier_knows_something_attempted=knows_attempted,
        completeness_violation=executed and not can_establish,
        soundness_violation=can_establish and not executed,
    )


CONDITIONS = (
    "nominal",
    "execution_fails",
    "recorder_crash_after_execution",
    "recorder_crash_during_commit",
    "partition_after_execution",
    "evidence_commit_fails",
    "execution_fails_after_evidence",
    "partition_after_evidence_commit",
    "success_reported_as_failure",
    "failure_reported_as_success",
)


def run() -> dict[str, Any]:
    rows = []
    for order in (EXECUTE_THEN_RECORD, RECORD_THEN_EXECUTE, TWO_PHASE_INTENT_OUTCOME):
        for cond in CONDITIONS:
            rows.append(run_condition(order, cond).to_dict())

    summary = {}
    for order in (EXECUTE_THEN_RECORD, RECORD_THEN_EXECUTE, TWO_PHASE_INTENT_OUTCOME):
        sel = [r for r in rows if r["order"] == order]
        summary[order] = {
            "conditions": len(sel),
            "completeness_violations": sum(r["completeness_violation"] for r in sel),
            "soundness_violations": sum(r["soundness_violation"] for r in sel),
            "silent_divergences": sum(
                (r["completeness_violation"] or r["soundness_violation"])
                and r["integrity_valid"] for r in sel),
            "conditions_where_verifier_blind": sorted(
                r["condition"] for r in sel
                if r["completeness_violation"] and not r["verifier_knows_something_attempted"]),
            "conditions_where_verifier_knows_attempt": sorted(
                r["condition"] for r in sel
                if r["completeness_violation"] and r["verifier_knows_something_attempted"]),
        }
    return {"summary": summary, "rows": rows}
