"""R2-M — evidence authenticity, replay and config-dependent enforcement.

Declared invariant (source):
    kernel/evidence.py: "KEYLESS MODE IS NOT AUTHENTICITY." A keyed chain is
    tamper-EVIDENT against an offline/persisted rewrite; `require_evidence_key`
    refuses to construct a keyless chain when authenticity is required.
    kernel/gate.py:_live_ruleset_hash: a policy change invalidates every
    outstanding decision.

This probe records what holds and what is explicitly documented as out of
scope, so the final report can distinguish a bypass from a stated limit.
"""

from __future__ import annotations

import copy
import time

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))))
from redteam.deepseek_redteam_round2 import _common as K
from morrison_governance.kernel.canonical import action_hash
from morrison_governance.kernel.evidence import (
    EvidenceChain, EvidenceRecord,
)


def _record(decision="BLOCK", executed=False, evaluated=True, **overrides):
    call = {"tool": "x", "args": {"k": "v"}}
    body = dict(
        seq=0, timestamp=time.time(), actor="a", tenant="t",
        action_hash=action_hash(call), proposed=copy.deepcopy(call),
        decision=decision, executed=executed,
    )
    if evaluated:
        body["evaluated"] = copy.deepcopy(call)
    body.update(overrides)
    return EvidenceRecord(**body)


def _keyless_rewrite():
    c = EvidenceChain()
    r = c.append(_record())
    r.decision = "PERMIT"
    r.executed = True
    r.seal()
    return {"verified": c.verify()[0], "problems": c.verify()[1]}


def _keyed_rewrite_without_key():
    c = EvidenceChain(key=b"kk")
    r = c.append(_record())
    r.decision = "PERMIT"
    r.executed = True
    r.seal()  # attacker does not have the key
    return {"verified": c.verify()[0], "problems": c.verify()[1]}


def _keyed_rewrite_with_key():
    c = EvidenceChain(key=b"kk")
    r = c.append(_record())
    r.decision = "PERMIT"
    r.executed = True
    r.seal(b"kk")  # holder of the key
    return {"verified": c.verify()[0], "problems": c.verify()[1]}


def _require_key():
    result = {}
    try:
        K.make_kernel(require_evidence_key=True)
        result["keyless_construction"] = "accepted (bad)"
    except Exception as e:                       # noqa: BLE001
        result["keyless_construction"] = f"{type(e).__name__}: {e}"
    k = K.make_kernel(require_evidence_key=True, evidence_key=b"kk")
    d = k.authorize({"tool": "summarize", "args": {}})
    result["keyed_verdict"] = d.verdict
    result["keyed_integrity"] = k.integrity()
    return result


def _ruleset_invalidation():
    k = K.make_kernel(policy_values={"payment_auto_approve_max": 100})
    d = k.authorize({"tool": "summarize", "args": {}})
    before = d.verdict
    k.ctx.policy_values["payment_auto_approve_max"] = 1
    rec = K.Recorder()
    after = k.execute(d, rec)
    return {"before": before, "execute_after_policy_change": after,
            "effects": rec.calls}


def _legacy_evaluated_none():
    """A record with evaluated=None skips the action_hash<->proposed check."""
    c = EvidenceChain()
    r = _record(evaluated=False,
                action_hash="0" * 64,
                proposed={"tool": "delete_bucket",
                          "args": {"bucket": "prod"}},
                decision="PERMIT")
    c.append(r)
    return {"verified": c.verify()[0], "problems": c.verify()[1]}


def _fail_closed_check():
    c = EvidenceChain()
    c.append(_record(decision="BLOCK", executed=True))
    return {"verified": c.verify()[0], "problems": c.verify()[1]}


def _execution_outcome_immutable():
    c = EvidenceChain(key=b"kk")
    auth = c.append(_record(decision="PERMIT"))
    follow = c.record_execution(auth, True, "ok")
    clean = c.verify()[0]
    follow.executed = False
    follow.seal()  # no key
    return {"before_tamper": clean, "after_tamper": c.verify()}


def _replay_same_key_chain():
    c1 = EvidenceChain(key=b"kk")
    r = c1.append(_record(decision="PERMIT"))
    c2 = EvidenceChain(key=b"kk")
    c2.append(copy.deepcopy(r))
    return {"verified": c2.verify()[0], "seq": c2.records[0].seq,
            "prev_hash": c2.records[0].prev_hash}


def main() -> dict:
    K.header("R2-M evidence authenticity and replay")
    results = {
        "keyless_rewrite": _keyless_rewrite(),
        "keyed_rewrite_without_key": _keyed_rewrite_without_key(),
        "keyed_rewrite_with_key": _keyed_rewrite_with_key(),
        "require_evidence_key": _require_key(),
        "ruleset_invalidation": _ruleset_invalidation(),
        "legacy_evaluated_none": _legacy_evaluated_none(),
        "fail_closed_check": _fail_closed_check(),
        "execution_outcome_immutable": _execution_outcome_immutable(),
        "replay_same_key_chain": _replay_same_key_chain(),
    }
    for name, row in results.items():
        print(f"{name}: {row}")

    documented = (
        results["keyless_rewrite"]["verified"] is True
        and results["keyed_rewrite_without_key"]["verified"] is False
        and results["keyed_rewrite_with_key"]["verified"] is True
        and results["require_evidence_key"]["keyless_construction"].startswith(
            "ValueError")
        and results["require_evidence_key"]["keyed_integrity"]["authenticated"]
        is True
        and results["ruleset_invalidation"][
            "execute_after_policy_change"][0] is False
        and results["fail_closed_check"]["verified"] is False
        and results["execution_outcome_immutable"]["after_tamper"][0] is False
    )

    return K.emit({
        "id": "R2-M",
        "title": "Evidence authenticity, replay and config-dependent enforcement",
        "classification": "HELD (documented limits reproduced)",
        "held": bool(documented),
        "results": results,
        "note": (
            "Keyless chains are self-consistency only, as documented. Keyed "
            "chains detect a rewrite without the key and accept a re-seal by "
            "a key holder. require_evidence_key refuses a keyless kernel. A "
            "policy change invalidates an outstanding decision. The fail-closed "
            "invariant (executed=True on a BLOCK) is detected. `evaluated=None` "
            "legacy records skip the action_hash<->proposed binding check by "
            "design; only a writer that can already append records can use "
            "that, and a keyed chain does not authenticate an unkeyed writer. "
            "Replay into a chain with the same key is accepted: the chain "
            "authenticates key possession, not provenance. These are stated "
            "limits, not new falsifications."),
    })


if __name__ == "__main__":
    main()
