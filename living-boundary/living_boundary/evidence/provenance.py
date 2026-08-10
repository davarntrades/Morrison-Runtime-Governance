"""Provenance, sealing, and the only filesystem write path in LB-0.

WHY THE EVIDENCE CHAIN IS MORRISON'S OWN

`EvidenceRecord` / `EvidenceChain` come from
`morrison_governance/kernel/evidence.py` — the same append-only, hash-chained
primitives the production kernel seals governance decisions with. Reusing them
means an LB-0 evidence package can be verified by the same code that verifies a
production one, and that a silently edited experimental result breaks a chain
link exactly as a silently edited decision would.

The chain LB-0 builds is entirely its own object. It is never appended to a
production chain, and nothing in this package can reach one.

WHY THE TIMESTAMPS ARE DERIVED, NOT WALL-CLOCK

A record's hash covers its timestamp, so wall-clock stamping would make the
sealed head differ on every run of an otherwise identical experiment — and
"the evidence is reproducible from the seed" would be false. Stage timestamps
are therefore a deterministic sequence derived from the seed. The real wall
clock is recorded once, in the manifest, as `generated_at`, where it documents
when the run happened without being load-bearing for verification.

THE WRITE GUARD

`write_package` is the single function in this package that touches the
filesystem, and it refuses any destination outside `living-boundary/artifacts/`.
`authority.scan_static_authority` enforces that no other module writes at all.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from living_boundary._repo_paths import ARTIFACTS_ROOT, ENGINE_ROOT
from morrison_governance.kernel.evidence import EvidenceChain, EvidenceRecord

EVIDENCE_ACTOR = "living-boundary/lb0"
EVIDENCE_TENANT = "experimental"
EVIDENCE_DECISION = "EXPERIMENTAL"


def _canonical(payload) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)


def payload_hash(payload) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def run_id_for(seed: int, dataset_hash: str) -> str:
    """A run id determined entirely by what was run, not when.

    Two runs of the same seed over the same generator produce the same id and
    therefore the same artifact directory, so "reproduce it and diff" is a
    one-line operation instead of a hunt through timestamped folders.
    """
    return f"lb0-seed{seed}-{dataset_hash[:8]}"


def code_provenance() -> dict:
    """Commit, dirtiness and interpreter, best-effort.

    A missing git binary or a tarball checkout is a MISSING INPUT, not a
    failure: the fields come back as "unavailable" and the run continues,
    because an experiment result is still meaningful without a commit id — it
    is just less traceable, and the artifact says so plainly.
    """
    def _git(*args):
        try:
            out = subprocess.run(
                ["git"] + list(args), cwd=str(ENGINE_ROOT), timeout=10,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        except (OSError, subprocess.SubprocessError):
            return ""
        return out.stdout.decode("utf-8", "replace").strip() if out.returncode == 0 else ""

    commit = _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain")
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    return {
        "commit": commit or "unavailable",
        "branch": branch or "unavailable",
        "working_tree_clean": (status == "") if commit else None,
        "engine_root": str(ENGINE_ROOT),
        "python": sys.version.split()[0],
    }


@dataclass
class ExperimentEvidence:
    """A hash-chained log of one LB-0 run, stage by stage."""

    run_id: str
    seed: int
    ruleset_hash: str = ""
    engine_version: str = ""
    chain: EvidenceChain = field(default_factory=EvidenceChain)
    stages: list = field(default_factory=list)
    _tick: int = 0

    def seal_stage(self, stage: str, summary: str, payload) -> str:
        """Append one sealed record for a pipeline stage; return its hash."""
        self._tick += 1
        digest = payload_hash(payload)
        record = self.chain.append(EvidenceRecord(
            seq=0,
            # Deterministic, seed-derived. See the module docstring.
            timestamp=float(self.seed * 1_000_000 + self._tick),
            actor=EVIDENCE_ACTOR, tenant=EVIDENCE_TENANT,
            action_hash=digest,
            proposed={"stage": stage, "run_id": self.run_id,
                      "payload_hash": digest},
            decision=EVIDENCE_DECISION, layer=stage,
            rule=None, omega_domain=None, reason=summary,
            ruleset_hash=self.ruleset_hash,
            engine_version=self.engine_version))
        self.stages.append({"stage": stage, "summary": summary,
                            "payload_hash": digest,
                            "record_hash": record.record_hash})
        return record.record_hash

    def verify(self) -> dict:
        ok, problems = self.chain.verify()
        return {"verified": ok, "problems": problems,
                "records": len(self.chain.records), "head": self.chain.head}

    def as_dict(self) -> dict:
        return {"run_id": self.run_id, "stages": list(self.stages),
                "chain": self.verify()}

    def to_jsonl(self) -> str:
        return self.chain.to_jsonl()


class ArtifactPathError(RuntimeError):
    """Raised when a write is attempted outside the LB-0 artifacts tree."""


def write_package(run_id: str, files: dict) -> Path:
    """Write the evidence package. The ONLY write path in this package.

    `files` maps relative filename -> text. Any name that would escape
    `living-boundary/artifacts/<run_id>/` is refused rather than normalised,
    because a path-traversal that is silently corrected is a write the caller
    did not know it performed.
    """
    root = Path(ARTIFACTS_ROOT).resolve()
    target = (root / run_id).resolve()
    if root not in target.parents and target != root:
        raise ArtifactPathError(
            f"refusing to write outside the LB-0 artifacts tree: {target}")

    # Every destination is validated BEFORE anything is created. Creating the
    # run directory first left an empty directory behind on a refused write —
    # a refusal that still changes the filesystem is a refusal that did not
    # fully refuse.
    resolved = []
    for name, text in sorted(files.items()):
        destination = (target / name).resolve()
        if target not in destination.parents:
            raise ArtifactPathError(
                f"refusing to write {name!r}: resolves outside {target}")
        resolved.append((destination, text))

    target.mkdir(parents=True, exist_ok=True)
    for destination, text in resolved:
        destination.write_text(text, encoding="utf-8")
    return target


def wall_clock() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
