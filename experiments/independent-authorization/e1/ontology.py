"""Ontology classification, FROZEN before execution.

Four questions per arm:
  Q1 who can ultimately cause the external state transition?
  Q2 who can withhold it?
  Q3 can the proposing component bypass that withholding mechanism?
  Q4 can the proposer mint or override the authorization artifact?

If the safety property depends on a non-bypassable external veto, the arm is
INDEPENDENT AUTHORITY however it is named. This table is written down BEFORE
any result exists and is asserted immutable by a fingerprint test.
Reclassifying an arm after seeing how it performed would make the study
unfalsifiable, which is the specific failure mode this file exists to prevent.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

INDEPENDENT = "INDEPENDENT_AUTHORITY"
NON_INDEPENDENT = "NON_INDEPENDENT"


@dataclass(frozen=True)
class Classification:
    arm: str
    q1_who_causes: str
    q2_who_withholds: str
    q3_proposer_can_bypass: bool
    q4_proposer_can_mint: bool
    verdict: str
    rationale: str


TABLE: dict[str, Classification] = {
    "B1": Classification(
        arm="B1", q1_who_causes="proposer",
        q2_who_withholds="proposer (voluntarily)",
        q3_proposer_can_bypass=True, q4_proposer_can_mint=False,
        verdict=NON_INDEPENDENT,
        rationale="Advisory only. The proposer reads a verdict and decides "
                  "for itself; nothing can withhold execution from it."),
    "B2": Classification(
        arm="B2", q1_who_causes="proposer",
        q2_who_withholds="proposer's own pre-execution recheck",
        q3_proposer_can_bypass=True, q4_proposer_can_mint=False,
        verdict=NON_INDEPENDENT,
        rationale="The recheck is the proposer's own code on the proposer's "
                  "own call path. A compromised proposer reaches the executor "
                  "without running it — the direct path exists because the "
                  "executor shares its trust domain."),
    "B4": Classification(
        arm="B4", q1_who_causes="proposer",
        q2_who_withholds="proposer's own single-use replay cache",
        q3_proposer_can_bypass=True, q4_proposer_can_mint=True,
        verdict=NON_INDEPENDENT,
        rationale="The cache is proposer-owned state. It can be cleared, and "
                  "the executor can be reached without consulting it."),
    "B6": Classification(
        arm="B6", q1_who_causes="proposer",
        q2_who_withholds="nobody — no veto exists",
        q3_proposer_can_bypass=False, q4_proposer_can_mint=False,
        verdict=NON_INDEPENDENT,
        rationale="Prevention by INEXPRESSIBILITY, not by veto. The send "
                  "capability is typed to reject secret provenance, so a "
                  "vault-sourced send cannot be constructed. Q3 is False not "
                  "because a veto resists bypass but because there is no veto "
                  "to bypass: nothing is consulted, so nothing can be skipped. "
                  "A DIFFERENT MECHANISM from T, deliberately classified "
                  "NON_INDEPENDENT."),
    "T": Classification(
        arm="T", q1_who_causes="kernel-gated executor",
        q2_who_withholds="GovernanceKernel (external veto)",
        q3_proposer_can_bypass=False, q4_proposer_can_mint=False,
        verdict=INDEPENDENT,
        rationale="Execution requires a live, action-bound lease the proposer "
                  "cannot mint, and the executor is reachable only through "
                  "kernel.execute."),
}

ARMS = ("B1", "B2", "B4", "B6", "T")

# Frozen at authoring time. Any edit to a classification changes this and the
# integrity test fails.
FROZEN_FINGERPRINT = "e84183986d47cdb51d80727f7f6a44eac0fb145905abbfb84a86c7dba7ce36e1"


def classification_fingerprint() -> str:
    blob = json.dumps(
        {k: {"q2": v.q2_who_withholds, "q3": v.q3_proposer_can_bypass,
             "q4": v.q4_proposer_can_mint, "verdict": v.verdict}
         for k, v in sorted(TABLE.items())},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()
