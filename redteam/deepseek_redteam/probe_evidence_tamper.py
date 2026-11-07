"""Probe: a keyless evidence chain reports intact after a full rewrite.

H-EVID-02
---------
`GovernanceKernel(evidence_key=b"")` is the default. `EvidenceChain.verify()`
with no key checks only that each record's hash matches its content and that
`prev_hash` links are continuous. That is self-consistency, not authenticity:
an attacker who can rewrite the records (in-process, or a persisted JSONL
export the deployment reloads) can change a BLOCK into an executed PERMIT and
recompute every hash, and `verify()` still returns True.

With a non-empty `evidence_key`, the same rewrite fails signature checks. So
the chain is tamper-EVIDENT only when a key is configured; the library default
provides tamper-DETECTION of accidental corruption, not of a deliberate edit.

Run:  python3 redteam/deepseek_redteam/probe_evidence_tamper.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from morrison_governance.kernel.evidence import (
    EvidenceChain, EvidenceRecord, GENESIS,
)


def build_chain(key: bytes) -> EvidenceChain:
    chain = EvidenceChain(key=key)
    chain.append(EvidenceRecord(
        seq=0, timestamp=1.0, actor="agent-a", tenant="acme",
        action_hash="a" * 64,
        proposed={"tool": "delete_logs", "args": {}},
        decision="BLOCK", layer="capability_policy", rule="log.tamper",
        reason="denied", ruleset_hash="r" * 64, engine_version="test"))
    chain.append(EvidenceRecord(
        seq=0, timestamp=2.0, actor="agent-a", tenant="acme",
        action_hash="b" * 64,
        proposed={"tool": "read_file", "args": {"path": "/x"}},
        decision="PERMIT", layer="V4", reason="allowed",
        ruleset_hash="r" * 64, engine_version="test"))
    return chain


def rewrite(chain: EvidenceChain) -> None:
    """Flip record 0 from BLOCK to an executed PERMIT and re-seal the chain."""
    rec0 = chain.records[0]
    rec0.decision = "PERMIT"
    rec0.executed = True
    rec0.reason = "allowed"
    # Recompute the whole chain exactly as an attacker with write access would.
    prev = GENESIS
    for rec in chain.records:
        rec.prev_hash = prev
        rec.record_hash = hashlib.sha256(rec._digest_payload().encode()).hexdigest()
        prev = rec.record_hash


if __name__ == "__main__":
    for label, key in (("keyless (library default)", b""),
                       ("HMAC-keyed", b"a-real-evidence-key")):
        chain = build_chain(key)
        ok_before, problems_before = chain.verify()
        rewrite(chain)
        ok_after, problems_after = chain.verify()
        print(f"--- {label}")
        print(f"    before rewrite: verified={ok_before} problems={problems_before}")
        print(f"    after  rewrite: verified={ok_after} problems={problems_after}")
        print(f"    record 0 now   : decision={chain.records[0].decision} "
              f"executed={chain.records[0].executed}")
