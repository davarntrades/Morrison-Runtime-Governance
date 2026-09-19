"""Provenance for finite-model verification: retained evidence and artifact identity.

Three things live here, and they are deliberately kept apart:

`VerificationEvidenceLedger`
    Retains the REAL `EvidenceRecord` objects the GovernanceKernel produced
    while the verifier explored. It never creates a record, never edits one,
    and never writes a "verification passed" record of its own. Its whole job
    is that a record outlives the throwaway kernel that made it.

`verifier_identity()`
    Who ran the enumeration: package version, repository commit, interpreter.

`artifact_digest()` / `validate_verification_artifact()`
    Integrity of the artifact itself, and the independent re-check that a
    reviewer can run without trusting the process that produced it.

None of this is attestation. An attestation is a signed statement by a
deployment about its own running engine; this is a record of what an
enumeration did. They are linkable -- both carry `ruleset_hash` -- and they
are not the same claim.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .state import canonical_json, stable_hash


VERIFIER_VERSION = "mrg.global-verification/2"
ARTIFACT_SCHEMA = "mrg.global-verification.v2"

# Fields excluded from the artifact digest because they are not properties of
# the verification: when it happened to be serialized, and the digest itself.
_DIGEST_EXCLUDED = ("timestamp", "artifact_integrity")


def _git(repo_root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    # Return the output even when EMPTY. `git status --porcelain` on a clean
    # tree prints nothing, and collapsing that into None made "clean" and
    # "could not run git" indistinguishable -- which reads as clean to every
    # caller that tests truthiness, i.e. fails open.
    return out.stdout.strip()


def verifier_identity(repo_root: str | Path | None = None) -> dict[str, Any]:
    """Identify the code that performed the enumeration.

    `repository_commit` is None when the verifier runs outside a git checkout.
    That is reported as None rather than guessed: a consumer that requires a
    commit should fail on the None, not on a fabricated value.
    """
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[2]
    commit = _git(root, "rev-parse", "HEAD") or None
    status = _git(root, "status", "--porcelain")
    return {
        "verifier_version": VERIFIER_VERSION,
        "repository_commit": commit,
        "repository_dirty": (None if status is None else bool(status)),
        "python": sys.version.split()[0],
    }


@dataclass
class RetainedEvidence:
    """One real kernel evidence record, kept with the branch that produced it."""

    record_hash: str
    record: dict[str, Any]
    branch_id: str
    sequence: int
    prev_hash: str
    # Whether prev_hash names a record this ledger also holds. Usually False:
    # the predecessor is a replayed prefix step, not a decision under test.
    prev_retained: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_hash": self.record_hash,
            "branch_id": self.branch_id,
            "sequence": self.sequence,
            "prev_hash": self.prev_hash,
            "prev_retained": self.prev_retained,
            "record": self.record,
        }


@dataclass
class VerificationEvidenceLedger:
    """Retains kernel evidence past the lifetime of the branch kernel.

    LIFECYCLE, stated explicitly because it is easy to get wrong:

    1. Every branch is evaluated on a FRESH `GovernanceKernel` with its own
       `InMemoryContinuityStore` and its own `EvidenceChain`. That isolation is
       required: branches are independent hypotheticals and must not inherit
       one another's governed history.
    2. Consequently each branch's chain begins at GENESIS. These are many short
       chains, NOT one global chain, and this ledger never splices them into
       one. `chain_segments()` returns them separately for that reason.
    3. This ledger retains the record behind each DECISION, keyed by
       `record_hash`; an identical decision re-derived on another branch
       produces an identical record and is retained once.
    4. Because a branch is evaluated by replaying its prefix, the kernel also
       files records for the replayed steps. Those are not decisions under
       test and are not retained, so a retained record's `prev_hash` often
       names a record this ledger does not hold. `prev_retained` says so per
       record. A segment is therefore NOT a verifiable hash chain, and this
       ledger never presents one as such; what IS verifiable is each record's
       own seal, which `validate_verification_artifact` recomputes.
    5. The ledger outlives the kernels. Nothing is reconstructed afterwards.
    """

    records: dict[str, RetainedEvidence] = field(default_factory=dict)
    _branch_seen: dict[str, list[str]] = field(default_factory=dict)

    def retain(self, record: Any, *, branch_id: str) -> str | None:
        """Retain a real `EvidenceRecord`. Returns its hash, or None if absent.

        A decision without evidence is not given a substitute.
        """
        if record is None:
            return None
        record_hash = getattr(record, "record_hash", "") or ""
        if not record_hash:
            return None
        if record_hash not in self.records:
            prev_hash = getattr(record, "prev_hash", "") or ""
            self.records[record_hash] = RetainedEvidence(
                record_hash=record_hash,
                record=_record_to_dict(record),
                branch_id=branch_id,
                sequence=int(getattr(record, "seq", 0) or 0),
                prev_hash=prev_hash,
                prev_retained=prev_hash in self.records,
            )
        self._branch_seen.setdefault(branch_id, [])
        if record_hash not in self._branch_seen[branch_id]:
            self._branch_seen[branch_id].append(record_hash)
        return record_hash

    def resolve(self, record_hash: str) -> RetainedEvidence | None:
        return self.records.get(record_hash)

    def chain_segments(self) -> dict[str, list[str]]:
        """Per-branch record hashes, in production order. Never concatenated."""
        return {k: list(v) for k, v in sorted(self._branch_seen.items())}

    def to_dict(self) -> dict[str, Any]:
        return {
            "retention_model": (
                "Per-branch kernels produce independent evidence chains, each "
                "starting at GENESIS. The record behind each decision is "
                "retained and de-duplicated by record_hash. These segments are "
                "NOT one chain and must not be verified as one."
            ),
            "chain_linkage": (
                "Retained records are decision records. Branch evaluation "
                "replays the prefix, and those replayed records are not "
                "retained, so prev_hash commonly names a record absent here "
                "(prev_retained=false). A segment is NOT a verifiable hash "
                "chain. What is verifiable is each record's own seal."
            ),
            "record_count": len(self.records),
            "branch_count": len(self._branch_seen),
            "records": [
                self.records[k].to_dict() for k in sorted(self.records)
            ],
            "chain_segments": self.chain_segments(),
        }


def _record_to_dict(record: Any) -> dict[str, Any]:
    """Serialize an EvidenceRecord without altering any field."""
    from dataclasses import fields as dataclass_fields

    out: dict[str, Any] = {}
    for item in dataclass_fields(record):
        value = getattr(record, item.name)
        out[item.name] = sorted(value) if isinstance(value, (set, frozenset)) else value
    return out


def artifact_digest(artifact: dict[str, Any]) -> str:
    """SHA-256 over the artifact body, excluding its own digest and timestamp."""
    body = {k: v for k, v in artifact.items() if k not in _DIGEST_EXCLUDED}
    return stable_hash(body)


def verification_identity(
    model_hash: str,
    governance_hash: str,
    algorithm: str,
    escalation_outcomes_admitted: tuple[str, ...] = (),
) -> str:
    """Identity of a verification RUN, not of the model.

    `escalation_outcomes_admitted` is observed from the traversal, not declared
    by the caller. Without it, a deny-only run and a run that also enumerates
    approvals -- which can reach opposite verdicts on the same model -- would
    share an identity.
    """
    return "gsv-" + stable_hash(
        {
            "model_hash": model_hash,
            "governance_hash": governance_hash,
            "algorithm": algorithm,
            "escalation_outcomes_admitted": sorted(escalation_outcomes_admitted),
        }
    )[:20]


@dataclass
class ValidationResult:
    """Outcome of re-checking an artifact without trusting its producer."""

    valid: bool
    checks: list[dict[str, Any]] = field(default_factory=list)

    def failures(self) -> list[dict[str, Any]]:
        return [c for c in self.checks if not c["passed"]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "passed": sum(1 for c in self.checks if c["passed"]),
            "failed": len(self.failures()),
            "checks": self.checks,
        }


def _check(checks: list, name: str, passed: bool, detail: str) -> bool:
    checks.append({"check": name, "passed": bool(passed), "detail": detail})
    return bool(passed)


def validate_verification_artifact(artifact: dict[str, Any]) -> ValidationResult:
    """Re-derive what can be re-derived, and refuse what cannot be supported.

    This is deliberately hostile to its input. It assumes the artifact may
    have been edited after the fact and checks the properties that an editor
    would have to keep consistent: the digest, the verdict/completeness
    relation, the evidence bindings, and every retained record's own seal.

    It does NOT re-run the enumeration -- it cannot, from a document -- and it
    does not verify record signatures, which needs the deployment's evidence
    key. Both are stated as `unverifiable_here` rather than passed silently.
    """
    checks: list[dict[str, Any]] = []
    ok = True

    schema = artifact.get("schema_version")
    ok &= _check(checks, "schema_version", schema == ARTIFACT_SCHEMA,
                 f"expected {ARTIFACT_SCHEMA}, found {schema!r}")

    integrity = artifact.get("artifact_integrity") or {}
    recomputed = artifact_digest(artifact)
    ok &= _check(checks, "artifact_hash", recomputed == integrity.get("artifact_hash"),
                 f"recomputed {recomputed[:16]}… vs stored "
                 f"{str(integrity.get('artifact_hash'))[:16]}…")

    fv = artifact.get("finite_verification") or {}
    verdict, complete = fv.get("verdict"), fv.get("complete_enumeration")
    ok &= _check(checks, "no_safe_from_incomplete",
                 not (verdict == "SAFE_WITHIN_MODEL" and complete is not True),
                 f"verdict={verdict} complete_enumeration={complete}")
    traversal = artifact.get("traversal") or {}
    ok &= _check(checks, "completeness_agrees",
                 traversal.get("complete_enumeration") == complete,
                 "traversal and finite_verification must report one completeness")

    comparison = artifact.get("control_comparison") or {}
    governed = comparison.get("governed") or {}
    ok &= _check(checks, "verdict_agrees_with_traversal",
                 not (verdict == "SAFE_WITHIN_MODEL"
                      and governed.get("unsafe_reachable_state_count", 0) > 0),
                 "a SAFE verdict may not accompany reachable prohibited states")

    # Escalation admissibility must match what the governed graph shows, so an
    # artifact cannot understate which resolutions were enumerated.
    edges = (governed.get("graph") or {}).get("edges") or []
    observed = sorted({e.get("escalation_outcome") for e in edges
                       if e.get("escalation_outcome")})
    declared = sorted(traversal.get("escalation_outcomes_admitted") or [])
    ok &= _check(checks, "escalation_admissibility_matches_graph", observed == declared,
                 f"graph shows {observed}, artifact declares {declared}")

    ident = verification_identity(
        (artifact.get("environment") or {}).get("model_hash", ""),
        (artifact.get("governance") or {}).get("ruleset_hash", ""),
        traversal.get("algorithm", ""),
        tuple(declared),
    )
    ok &= _check(checks, "verification_id_binds_policy",
                 ident == artifact.get("verification_id"),
                 f"recomputed {ident} vs stored {artifact.get('verification_id')}")

    # Every edge binding must resolve to a retained record, and every retained
    # record must still hash to its own record_hash.
    ledger = artifact.get("evidence_ledger") or {}
    retained = {r["record_hash"]: r for r in ledger.get("records") or []}
    bindings = (artifact.get("governance_decisions") or {}).get(
        "edge_evidence_bindings") or {}
    edge_ids = {e.get("edge_id") for e in edges}
    unresolved = [h for h in bindings.values() if h not in retained]
    ok &= _check(checks, "evidence_bindings_resolve", not unresolved,
                 f"{len(bindings)} binding(s); {len(unresolved)} unresolved")
    dangling = [k for k in bindings if k not in edge_ids]
    ok &= _check(checks, "bindings_reference_real_edges", not dangling,
                 f"{len(dangling)} binding(s) name an edge not in the graph")

    from morrison_governance.kernel.evidence import EvidenceRecord

    bad_seal = []
    for h, row in sorted(retained.items()):
        try:
            record = EvidenceRecord(**row["record"])
            record.record_hash = ""
            if record.seal().record_hash != h:
                bad_seal.append(h)
        except Exception:  # noqa: BLE001 - a record that cannot be rebuilt fails
            bad_seal.append(h)
    ok &= _check(checks, "retained_records_reseal", not bad_seal,
                 f"{len(retained)} record(s); {len(bad_seal)} failed to reseal")

    # The declared ruleset must be the one the retained records were decided
    # under. This catches a governance section swapped after the fact.
    declared_ruleset = (artifact.get("governance") or {}).get("ruleset_hash")
    declared_engine = (artifact.get("governance") or {}).get("engine_version")
    mismatched = [
        h for h, row in retained.items()
        if row["record"].get("ruleset_hash") != declared_ruleset
        or row["record"].get("engine_version") != declared_engine
    ]
    ok &= _check(checks, "governance_matches_evidence", not mismatched,
                 f"{len(mismatched)} retained record(s) were decided under a "
                 f"different ruleset or engine than the artifact declares")

    ok &= _check(checks, "verifier_identity_present",
                 bool((artifact.get("verifier") or {}).get("verifier_version")),
                 "verifier version must be recorded")

    checks.append({
        "check": "unverifiable_here", "passed": True,
        "detail": (
            "Not checked by this validator: (a) that the enumeration was "
            "actually performed -- re-run the verifier at the recorded commit; "
            "(b) evidence record SIGNATURES, which need the deployment's "
            "evidence key; (c) anything about the production environment."
        ),
    })
    return ValidationResult(valid=ok, checks=checks)
