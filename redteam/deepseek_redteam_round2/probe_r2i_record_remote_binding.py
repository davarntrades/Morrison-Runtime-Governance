"""R2-I — record_remote_execution records a mutated action, not the authorised one.

Declared invariant (source):
    kernel/gate.py, `execute`:
        "the decision record names the action that actually ran" (F-6).
    kernel/gate.py, `_lease_problem`:
        "decision security binding was mutated after authorization."
    kernel/gate.py, `record_remote_execution`:
        "The trajectory prefix must still advance ..."

Observed:
    decision = authorize(read_file /data/customers.csv)   # PERMIT, reserved
    decision.action = {"tool": "summarize", "args": {"q": "harmless"}}
    record_remote_execution(decision)                      # succeeds

    ledger / executed_history: only the mutated `summarize`
    sealed evidence: still names `read_file`
    chain.verify(): True
    action_hash: still the original read_file hash
    action_hash(decision.action): a different hash

`record_remote_execution` calls `_lease_problem(require_reservation=False)`
then `_commit(decision.decision_id, stamp, decision.action)` / `_file(...)`.
It never re-derives `action_hash(decision.action)` and `_lease_problem` hashes
only the stored `semantic_hash` / `security_binding_hash`, both of which are
decision fields the mutation does not touch.

Control:
    unmutated record_remote_execution -> ledger and evidence agree;
    execute(mutated decision) -> refused "action mutated after authorisation".

Impact: audit/evidence divergence. It does NOT erase read taint, because the
committed attempt keeps the original decision's capability set
(`data.read`), and `_any_read_occurred` reads capabilities, not the action.
If the original decision had no read capability, the mutated read does not
acquire taint either. The defect is that the two authoritative records
disagree about what ran.

Severity: P2 (audit integrity; not a direct safety bypass).
Classification: REPRODUCED.
"""

from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))))
from redteam.deepseek_redteam_round2 import _common as K
from morrison_governance.kernel.canonical import action_hash

READ = {"tool": "read_file", "args": {"path": "/data/customers.csv"}}
MUTATED = {"tool": "summarize", "args": {"q": "harmless"}}


def _mutated_record():
    k = K.make_kernel()
    d = k.authorize(READ)
    original_evidence = d.evidence
    original_hash = d.action_hash
    d.action = dict(MUTATED)
    k.record_remote_execution(d)
    ok, problems = k.chain.verify()
    return {
        "authorized_action": READ,
        "mutated_action": MUTATED,
        "decision_verdict": d.verdict,
        "decision_reserved": d.reserved,
        "stored_action_hash": original_hash,
        "hash_of_mutated_action": action_hash(MUTATED),
        "hashes_differ": original_hash != action_hash(MUTATED),
        "ledger_actions": [a.action for a in k.ledger],
        "executed_history": k.executed_history,
        "evidence_proposed": (original_evidence.proposed
                              if original_evidence else None),
        "evidence_action_hash": (original_evidence.action_hash
                                 if original_evidence else None),
        "chain_verified": ok,
        "chain_problems": problems,
    }


def _control_unmutated():
    k = K.make_kernel()
    d = k.authorize(READ)
    k.record_remote_execution(d)
    return {
        "ledger_actions": [a.action for a in k.ledger],
        "executed_history": k.executed_history,
        "chain_verified": k.chain.verify()[0],
    }


def _control_execute_mutated():
    k = K.make_kernel()
    d = k.authorize(READ)
    d.action = dict(MUTATED)
    rec = K.Recorder()
    result = k.execute(d, rec)
    return {"executed": result[0], "detail": result[1],
            "recorder_calls": rec.calls}


def main() -> dict:
    K.header("R2-I record_remote_execution action binding")
    mutated = _mutated_record()
    unmutated = _control_unmutated()
    execute_control = _control_execute_mutated()

    print("mutated record: ledger=", mutated["ledger_actions"],
          "evidence=", mutated["evidence_proposed"],
          "chain=", mutated["chain_verified"])
    print("unmutated control: ledger=", unmutated["ledger_actions"],
          "evidence agrees, chain=", unmutated["chain_verified"])
    print("execute mutated control:", execute_control["executed"],
          "-", execute_control["detail"])

    falsified = (
        mutated["decision_verdict"] == "PERMIT"
        and mutated["hashes_differ"]
        and mutated["ledger_actions"] == [MUTATED]
        and mutated["evidence_proposed"] == READ
        and mutated["chain_verified"] is True
        and unmutated["ledger_actions"] == [READ]
        and execute_control["executed"] is False
    )

    return K.emit({
        "id": "R2-I",
        "title": "record_remote_execution commits a caller-mutated decision.action",
        "invariant": ("The decision record and sealed evidence name the action "
                       "that actually ran; a decision whose action was mutated "
                       "after authorisation cannot be recorded as executed."),
        "source": [
            "morrison_governance/kernel/gate.py:record_remote_execution",
            "morrison_governance/kernel/gate.py:_lease_problem",
            "morrison_governance/kernel/gate.py:_commit",
            "morrison_governance/kernel/evidence.py:EvidenceChain.verify",
        ],
        "severity": "P2",
        "classification": "REPRODUCED",
        "falsified": bool(falsified),
        "mutated": mutated,
        "unmutated_control": unmutated,
        "execute_mutated_control": execute_control,
        "note": (
            "`execute()` re-derives the hash of the target and refuses the "
            "mutation. `record_remote_execution()` does not. The ledger and "
            "the sealed evidence disagree, and `chain.verify()` still passes "
            "because the evidence record was sealed against the original "
            "action and was never re-derived. Read taint is still retained via "
            "the committed attempt's capability set, so this is an audit "
            "integrity defect rather than a taint-laundering bypass."),
    })


if __name__ == "__main__":
    main()
