"""H2: independent evidence authority. Integrity vs completeness.

The independent channel L_I is Morrison's REAL `EvidenceChain` /
`EvidenceRecord` (SHA-256 record hashes, prev_hash chaining, HMAC signatures,
fail-closed invariant). The vendor channel L_V is a plain mutable list.

CENTRAL DEFINITIONS

  Executed reality   ordered consequential transitions actually committed to
                     the external world (ground truth, by construction).
  Recorded reality   transitions an independent verifier can reconstruct
                     from L_I.
  Verify(L_I)        Morrison's own chain verification.
  Completeness       every executed consequential transition appears in L_I.
  Soundness          every transition in L_I was actually executed.
  Undetected
  divergence         executed reality != recorded reality AND Verify(L_I)=VALID.

Morrison's `EvidenceChain.verify()` checks per-record integrity, prev_hash
continuity, and the fail-closed invariant. It has NO predicate over records
that were never appended. That is stated in the study as an expressiveness
limit of the CURRENT IMPLEMENTATION, not a defect.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from morrison_governance.kernel.evidence import EvidenceChain, EvidenceRecord


KEY = b"independent-evidence-authority-study"


@dataclass(frozen=True)
class Transition:
    """A consequential transition in ground-truth executed reality."""
    seq: int
    source: str
    action: str
    destination: str
    consequential: bool = True

    def key(self) -> str:
        return f"{self.source}--{self.action}-->{self.destination}"


# ── the six modeled faults ────────────────────────────────────────────────

FAULTS = (
    "vendor_withhold",
    "vendor_delete",
    "vendor_modify",
    "recorder_crash_before_commit",
    "execution_bypasses_recorder",
    "evidence_writer_compromised",
)


@dataclass
class World:
    """One execution of the model under a fault set."""
    executed: list[Transition] = field(default_factory=list)
    vendor: list[dict[str, Any]] = field(default_factory=list)
    independent: EvidenceChain = field(default_factory=lambda: EvidenceChain(key=KEY))
    fabricated: list[str] = field(default_factory=list)


def _append(chain: EvidenceChain, t: Transition, *, executed: bool = True) -> None:
    chain.append(EvidenceRecord(
        seq=0, timestamp=float(t.seq), actor="agent", tenant="modeled",
        action_hash=t.key(), proposed={"tool": t.action, "args": {"to": t.destination}},
        decision="PERMIT", layer="execution", executed=executed,
        execution_result="ok" if executed else "failed",
    ))


def reconstruct(chain: EvidenceChain) -> list[str]:
    """What an independent verifier can establish occurred, from L_I alone."""
    return [r.action_hash for r in chain.records if r.executed]


DEFAULT_HISTORY = (
    Transition(0, "x0", "read", "x1"),
    Transition(1, "x1", "stage", "x2"),
    Transition(2, "x2", "export", "OMEGA"),   # the consequential one
)


def simulate(
    faults: frozenset[str],
    history: tuple[Transition, ...] = DEFAULT_HISTORY,
    *,
    compromise_can_omit: bool = True,
) -> World:
    """Run the model under a fault set.

    `compromise_can_omit` controls the semantics of writer compromise:
      True  -> a compromised writer may OMIT records (breaks completeness)
      False -> a compromised writer may only FABRICATE (breaks soundness only)
    This parameter exists because the 8/64 result is sensitive to it.
    """
    w = World()

    for t in history:
        # --- execution happens in the world ---
        w.executed.append(t)

        # --- vendor channel ---
        if "vendor_withhold" not in faults:
            w.vendor.append({"action": t.action, "dest": t.destination})

        # --- independent channel ---
        skip = False
        # Fault 5: the consequential transition takes a path the recorder does
        # not observe at all.
        if "execution_bypasses_recorder" in faults and t.consequential and t.seq == 2:
            skip = True
        # Fault 4: recorder dies after execution, before the record is durable.
        if "recorder_crash_before_commit" in faults and t.seq == 2:
            skip = True
        # Fault 6: a compromised writer omits the inconvenient record.
        if ("evidence_writer_compromised" in faults and compromise_can_omit
                and t.seq == 2):
            skip = True
        if not skip:
            _append(w.independent, t)

    # vendor-side manipulation, after the fact
    if "vendor_delete" in faults:
        w.vendor = [e for e in w.vendor if e["dest"] != "OMEGA"]
    if "vendor_modify" in faults:
        w.vendor = [{**e, "dest": "x3"} if e["dest"] == "OMEGA" else e for e in w.vendor]

    # a compromised writer can also add records for things that never happened
    if "evidence_writer_compromised" in faults:
        ghost = Transition(99, "x2", "export", "DECOY")
        _append(w.independent, ghost)
        w.fabricated.append(ghost.key())

    return w


def evaluate(w: World) -> dict[str, Any]:
    executed_keys = [t.key() for t in w.executed if t.consequential]
    recorded = reconstruct(w.independent)
    integrity_ok, problems = w.independent.verify()

    missing = [k for k in executed_keys if k not in recorded]
    fabricated = [k for k in recorded if k not in executed_keys]

    complete = not missing
    divergence = (sorted(recorded) != sorted(executed_keys))
    undetected = divergence and integrity_ok

    return {
        "executed_event_count": len(executed_keys),
        "independently_recorded_event_count": len(recorded),
        "missing_event_count": len(missing),
        "fabricated_event_count": len(fabricated),
        "missing_events": missing,
        "fabricated_events": fabricated,
        "integrity_valid": integrity_ok,
        "integrity_problems": problems,
        "evidence_completeness": (
            (len(executed_keys) - len(missing)) / len(executed_keys)
            if executed_keys else 1.0
        ),
        "strong_unhideability": complete and integrity_ok and not fabricated,
        "completeness_holds": complete,
        "soundness_holds": not fabricated,
        "executed_reality_equals_recorded_reality": not divergence,
        "undetected_reality_divergence": undetected,
    }


def enumerate_all(*, compromise_can_omit: bool = True) -> dict[str, Any]:
    """Exhaustive 2^6 = 64 enumeration. No sampling."""
    rows = []
    for r in range(len(FAULTS) + 1):
        for combo in itertools.combinations(FAULTS, r):
            fs = frozenset(combo)
            res = evaluate(simulate(fs, compromise_can_omit=compromise_can_omit))
            rows.append({"faults": sorted(fs), "n_faults": len(fs), **res})

    holds = [r for r in rows if r["strong_unhideability"]]
    undetected = [r for r in rows if r["undetected_reality_divergence"]]

    singles = {}
    for f in FAULTS:
        res = evaluate(simulate(frozenset({f}), compromise_can_omit=compromise_can_omit))
        singles[f] = {
            "strong_unhideability": res["strong_unhideability"],
            "breaks_alone": not res["strong_unhideability"],
            "undetected_divergence": res["undetected_reality_divergence"],
            "integrity_valid": res["integrity_valid"],
            "completeness": res["evidence_completeness"],
        }

    return {
        "total_combinations": len(rows),
        "property_holds": len(holds),
        "property_fails": len(rows) - len(holds),
        "undetected_divergence_count": len(undetected),
        "single_faults_that_break_alone": sorted(
            f for f, v in singles.items() if v["breaks_alone"]),
        "single_fault_detail": singles,
        "compromise_can_omit": compromise_can_omit,
        "rows": rows,
    }
