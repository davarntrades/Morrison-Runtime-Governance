"""Independent evidence attestation.

The red-team finding this module closes:

    Evidence integrity was SELF-checked. The chain was sealed with an HMAC key
    the service itself held, so a compromised service could rewrite history and
    re-seal it, and `EvidenceChain.verify()` would still return True. "Evidence
    integrity verified" therefore meant "verified against everyone except the
    party with the strongest motive to tamper".

Independence is established in three layers, strongest first:

  1. KEYLESS RECOMPUTATION — `recompute_chain()` takes only the exported JSONL
     and rebuilds every record hash and chain link from the record CONTENT. It
     needs no key, no kernel object and no cooperation from the service. Any
     edit to any field of any record is detected by an auditor holding nothing
     but the export. This is the layer that does not depend on trusting anyone.

  2. ASYMMETRIC ATTESTATION — the chain head is signed with an Ed25519 key that
     is SEPARATE from the service's evidence/approval keys. Verification needs
     only the public key, so a verifier can confirm authorship without holding
     anything that could produce a signature. Signing is deliberately NOT
     implemented here: this package stays stdlib-only and private-key-free, the
     same supply-chain stance as `ed25519_verify.py`.

  3. EXTERNAL ANCHORING — `AnchorLog` records (seq, head) pairs monotonically.
     Anchors are meant to be shipped to storage the service cannot rewrite; a
     service that rewrites its chain must then also contradict every anchor
     already exported, which an auditor detects by comparing the two.

Layer 3 is only as independent as the storage it is pointed at. That is an
operational property this code cannot enforce, and it is stated plainly rather
than implied — see `AnchorLog.independence_note()`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

GENESIS = "0" * 64


# ─────────────────────────────────────────────────────────────
# 1. Keyless recomputation — needs nothing from the service
# ─────────────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    ok: bool
    head: str
    count: int
    problems: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def _record_digest_payload(rec: dict) -> str:
    """Reproduce EvidenceRecord._digest_payload() from raw JSON.

    Must stay byte-identical to the sealing routine in evidence.py: the whole
    point is that a third party can recompute it without importing the kernel.
    """
    body = {k: v for k, v in rec.items()
            if k not in ("record_hash", "signature")}
    return json.dumps(body, sort_keys=True, default=str, ensure_ascii=False)


def recompute_chain(jsonl: str) -> VerificationResult:
    """Verify an exported evidence chain using ONLY its own content.

    Detects: edited fields, forged verdicts, deleted records, reordered
    records, and any executed-without-PERMIT violation. Requires no key.
    """
    problems: list[str] = []
    prev = GENESIS
    head = GENESIS
    count = 0

    for lineno, line in enumerate(jsonl.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            problems.append(f"line {lineno}: malformed JSON ({e})")
            continue
        count += 1

        expect = hashlib.sha256(
            _record_digest_payload(rec).encode()).hexdigest()
        actual = rec.get("record_hash") or ""
        if expect != actual:
            problems.append(
                f"record {rec.get('seq', lineno)}: content does not match its "
                f"hash — tampered (expected {expect[:12]}…, found "
                f"{actual[:12] or '<none>'}…)")
        if rec.get("prev_hash") != prev:
            problems.append(
                f"record {rec.get('seq', lineno)}: chain break — prev_hash "
                f"{str(rec.get('prev_hash'))[:12]}… != {prev[:12]}…")
        if rec.get("seq") != count - 1:
            problems.append(
                f"record at line {lineno}: sequence discontinuity "
                f"(seq={rec.get('seq')}, expected {count - 1})")
        if rec.get("executed") and rec.get("decision") != "PERMIT":
            problems.append(
                f"record {rec.get('seq', lineno)}: violates fail-closed — "
                f"executed with decision {rec.get('decision')}")
        prev = actual
        head = actual

    return VerificationResult(ok=not problems, head=head, count=count,
                              problems=problems)


# ─────────────────────────────────────────────────────────────
# 2. Asymmetric attestation over the chain head
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ChainAttestation:
    """A signed statement that a chain head existed at a point in time.

    `signature` is Ed25519 over `payload()`, produced by a signer holding a key
    the governance service does not have.
    """

    head: str
    count: int
    issued_at: float
    signer_key_id: str
    algorithm: str = "ed25519"
    signature: str = ""          # hex

    def payload(self) -> bytes:
        """Canonical bytes that are signed. Stable across languages: an
        operator can reproduce these with any Ed25519 signer."""
        return json.dumps({
            "algorithm": self.algorithm,
            "count": self.count,
            "head": self.head,
            "issued_at": int(self.issued_at),
            "signer_key_id": self.signer_key_id,
        }, sort_keys=True, separators=(",", ":")).encode()

    def as_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "ChainAttestation":
        return ChainAttestation(
            head=d["head"], count=int(d["count"]),
            issued_at=float(d["issued_at"]),
            signer_key_id=d.get("signer_key_id", ""),
            algorithm=d.get("algorithm", "ed25519"),
            signature=d.get("signature", ""))


def verify_attestation(jsonl: str, attestation: ChainAttestation,
                       public_key: bytes,
                       verify_fn: Callable[[bytes, bytes, bytes], bool],
                       ) -> VerificationResult:
    """Full independent verification.

    `verify_fn` is injected (e.g. `ed25519_verify.verify`) so this package takes
    no crypto dependency and contains no private-key code.

    Passing requires ALL of:
      * every record hash recomputes from its own content
      * every chain link is intact and sequence is continuous
      * nothing executed without a PERMIT
      * the recomputed head equals the attested head
      * the attestation signature verifies under `public_key`
    """
    result = recompute_chain(jsonl)
    problems = list(result.problems)

    if result.head != attestation.head:
        problems.append(
            f"attested head {attestation.head[:12]}… does not match the "
            f"recomputed head {result.head[:12]}… — the chain shown is not the "
            f"chain that was attested")
    if result.count != attestation.count:
        problems.append(
            f"attested record count {attestation.count} != {result.count} "
            f"present — records added or removed after attestation")

    try:
        sig = bytes.fromhex(attestation.signature or "")
    except ValueError:
        sig = b""
    if not sig:
        problems.append("attestation carries no signature")
    elif not verify_fn(public_key, attestation.payload(), sig):
        problems.append(
            "attestation signature is invalid under the supplied public key")

    return VerificationResult(ok=not problems, head=result.head,
                              count=result.count, problems=problems)


# ─────────────────────────────────────────────────────────────
# 3. External anchoring
# ─────────────────────────────────────────────────────────────

@dataclass
class AnchorLog:
    """Monotonic (seq, head) anchors for a chain.

    A service that rewrites its evidence must also contradict every anchor it
    has already exported. That is only a real constraint once anchors live
    somewhere the service cannot rewrite — see `independence_note()`.
    """

    anchors: list = field(default_factory=list)

    def anchor(self, head: str, count: int, at: float) -> dict:
        if self.anchors and count < self.anchors[-1]["count"]:
            raise ValueError(
                f"non-monotonic anchor: count {count} < previous "
                f"{self.anchors[-1]['count']} — the chain has shrunk, which "
                f"means history was rewritten")
        rec = {"seq": len(self.anchors), "head": head, "count": count,
               "at": at}
        self.anchors.append(rec)
        return rec

    def check(self, jsonl: str) -> VerificationResult:
        """Verify a chain against previously exported anchors: every anchored
        head must still appear at its anchored position."""
        problems: list[str] = []
        prev = GENESIS
        heads: list[str] = []
        for line in jsonl.splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            heads.append(rec.get("record_hash") or "")
            prev = heads[-1]

        for a in self.anchors:
            idx = a["count"] - 1
            if idx < 0:
                continue
            if idx >= len(heads):
                problems.append(
                    f"anchor {a['seq']}: chain has {len(heads)} records but "
                    f"{a['count']} were anchored — records were removed")
                continue
            if heads[idx] != a["head"]:
                problems.append(
                    f"anchor {a['seq']}: head at record {idx} is "
                    f"{heads[idx][:12]}… but {a['head'][:12]}… was anchored — "
                    f"history was rewritten after anchoring")
        return VerificationResult(ok=not problems, head=prev,
                                  count=len(heads), problems=problems)

    def to_json(self) -> str:
        return json.dumps(self.anchors, sort_keys=True)

    @staticmethod
    def from_json(s: str) -> "AnchorLog":
        return AnchorLog(anchors=json.loads(s))

    @staticmethod
    def independence_note() -> str:
        return (
            "Anchors constrain the service only to the extent that they are "
            "stored where the service cannot rewrite them (an append-only "
            "object store with object-lock, a transparency log, or a "
            "counterparty's system). Anchors kept alongside the evidence they "
            "attest provide ordering checks but NOT independence."
        )
