"""Global-safety readiness scorecard.

Maps the 10 meta-governance requirements to their implementing module
and an honest status:

  core          — pre-existing, the validated runtime governance core
  implemented   — concrete deterministic mechanism, functionally tested
  mechanism     — governance-side mechanism implemented; the full
                  requirement is socio-technical / infra and out of scope

The scorecard does NOT claim global safety. It reports which mechanisms
are present and tested, with explicit caveats."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScorecardEntry:
    requirement: str
    why_it_matters: str
    module: str
    status: str            # core | implemented | mechanism
    evidence: str

    def as_dict(self) -> dict:
        return {"requirement": self.requirement,
                "why_it_matters": self.why_it_matters,
                "module": self.module, "status": self.status,
                "evidence": self.evidence}


_ENTRIES = [
    ScorecardEntry(
        "Runtime governance", "the validated core",
        "morrison_governance.GovernanceLayer", "core",
        "A_safe→V2→V3→V4→V4+→V5→V5+; 171 core cases, 0 FP/FN in suite"),
    ScorecardEntry(
        "Cross-system trajectory analysis", "multi-agent environments",
        "global_governance.cross_system", "implemented",
        "joint flattened trajectory across independent systems; "
        "cross-system exfiltration blocks at V2"),
    ScorecardEntry(
        "Adaptive Ω evolution", "new failure modes emerge",
        "global_governance.adaptive_omega", "implemented",
        "versioned, hash-chained rule ingestion; a case bypassing at "
        "v0 blocks at v1 after ingesting the closing rule"),
    ScorecardEntry(
        "Hierarchical governance layers", "local + regional + global",
        "global_governance.hierarchy", "implemented",
        "ordered tiers; deny-by-default up the hierarchy; any tier "
        "block → BLOCK"),
    ScorecardEntry(
        "Formal interface standards", "shared execution geometry",
        "global_governance.interface_standard", "implemented",
        "versioned ToolCall/Trajectory/Verdict contract + conformance "
        "checker (static + dynamic probe)"),
    ScorecardEntry(
        "Continuous adversarial auditing", "reality changes",
        "global_governance.continuous_audit", "implemented",
        "snapshot + diff surfaces regressions (was-blocked→now-permitted) "
        "deterministically"),
    ScorecardEntry(
        "Memory-aware governance", "long-horizon effects",
        "global_governance.memory_governance", "implemented",
        "bounded decaying per-entity cumulative risk; escalates (never "
        "relaxes) across sessions"),
    ScorecardEntry(
        "Self-verifying controllers", "governance integrity",
        "global_governance.self_verifying", "implemented",
        "determinism + strict-strengthening monotonicity self-checks; "
        "fail-closed on violation; hash-chain attestation"),
    ScorecardEntry(
        "Distributed trust architecture", "no single failure point",
        "global_governance.distributed_trust", "mechanism",
        "deny-by-default quorum over N in-process replicas; one corrupt/"
        "crashed replica cannot flip BLOCK→PERMIT. (Real BFT / "
        "cryptographic distribution is out of scope.)"),
    ScorecardEntry(
        "Human override / institutional governance",
        "political and ethical legitimacy",
        "global_governance.institutional", "mechanism",
        "scoped signed authorizations + tamper-evident audit chain; "
        "permit-override needs explicit accountable signature. (Real "
        "institutional legitimacy is socio-technical, out of scope.)"),
]


def readiness_scorecard() -> list:
    return list(_ENTRIES)


def summary() -> dict:
    counts = {"core": 0, "implemented": 0, "mechanism": 0}
    for e in _ENTRIES:
        counts[e.status] += 1
    total = len(_ENTRIES)
    addressed = counts["core"] + counts["implemented"] + counts["mechanism"]
    return {
        "total_requirements": total,
        "addressed": addressed,
        "core": counts["core"],
        "implemented": counts["implemented"],
        "mechanism_only": counts["mechanism"],
        "readiness_fraction": round(addressed / total, 3),
        "note": ("'addressed' counts requirements with a concrete tested "
                 "mechanism; 'mechanism_only' rows model the governance "
                 "side of a socio-technical/infra problem and are NOT a "
                 "claim of full requirement satisfaction."),
    }
