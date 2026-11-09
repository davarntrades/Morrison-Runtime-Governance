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
            if k not in ("record_hash", "signature")
            # INTEGRATION: mirrors evidence.py, where the DeepSeek line binds
            # `evaluated` on new records and omits it when absent (legacy).
            and not (k == "evaluated" and v is None)}
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


# ─────────────────────────────────────────────────────────────
# 4. Decision-to-execution reconciliation (independent review, finding B)
# ─────────────────────────────────────────────────────────────

# Follow-up records that assert something happened UNDER a decision. Each must
# refer to a PERMIT decision record in the same chain.
_UNDER_PERMIT = ("dispatched", "succeeded", "unknown", "exported", "remote",
                 "reconciled_executed")


def reconcile_execution_evidence(chains, effects, *, mediated: bool = False
                                 ) -> dict:
    """Join exported evidence chains to the effects a resource recorded.

    `chains` is an iterable of JSONL exports, one per kernel chain (a chain
    file written by `JsonlEvidenceSink`, or `EvidenceChain.to_jsonl()`).
    `effects` is an iterable of mappings with a `decision_id` — what the
    RESOURCE says happened, which is the only evidence that execution actually
    occurred. Nothing here needs a key or the kernel.

    A recorded authorisation is not evidence of execution, so the two are
    counted separately:

      authorized   PERMIT decision records
      dispatched   intent records sealed before an in-process effect
      exported     leases exported for a resource to redeem (mediated)
      succeeded    in-process executor returned
      unknown      in-process executor raised after dispatch
      effects      resource effects, each bound to exactly one decision

    Problems (any one makes `ok` False): a chain that does not recompute; a
    follow-up record whose `refers_to` is not a decision record of the same
    decision id and action in that chain; a dispatch, outcome or export under a
    non-PERMIT decision; more than one dispatch, outcome or export for one
    decision; an outcome with no dispatch; an effect with no PERMIT decision;
    an in-process effect with no dispatch and outcome, or a mediated effect
    with no export; two effects for one decision (duplicate commit); a
    "succeeded" outcome the resource has no effect for. Records written before
    decision ids existed cannot be bound and are reported as such.
    """
    problems: list[str] = []
    decisions: dict[str, dict] = {}
    follow: dict[str, dict[str, list]] = {}
    unbound = 0
    parsed: list[list[dict]] = []
    for index, jsonl in enumerate(chains):
        result = recompute_chain(jsonl)
        if not result.ok:
            problems.extend(f"chain {index}: {p}" for p in result.problems)
        rows = []
        for line in jsonl.splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue                      # already reported above
        parsed.append(rows)
    # Decision records, by hash, with the chain that holds them. A REFUSAL may
    # be sealed by a different kernel than the one that issued the decision (a
    # restarted session refusing a stale PERMIT); a dispatch, outcome or
    # export may not, because only the issuing session can execute.
    home = {r.get("record_hash"): (i, r) for i, rows in enumerate(parsed) for r in rows
            if r.get("decision_id") and not r.get("refers_to")}
    for index, rows in enumerate(parsed):
        for r in rows:
            did = r.get("decision_id") or ""
            if not did:
                unbound += 1
                continue
            if not r.get("refers_to"):
                if did in decisions:
                    problems.append(f"decision {did[:12]}: two decision records")
                decisions[did] = r
                continue
            chain_of, parent = home.get(r["refers_to"], (None, None))
            if parent is None or parent.get("decision_id") != did:
                problems.append(f"chain {index} record {r.get('seq')}: refers_to does not "
                                f"resolve to decision {did[:12]}'s record")
                continue
            if r.get("outcome") in _UNDER_PERMIT and chain_of != index:
                problems.append(f"chain {index} record {r.get('seq')}: {r.get('outcome')} "
                                f"for decision {did[:12]} issued in another chain")
                continue
            if (r.get("outcome") in _UNDER_PERMIT
                    and r.get("action_hash") != parent.get("action_hash")):
                problems.append(f"decision {did[:12]}: {r.get('outcome')} record is for a "
                                f"different action than the decision")
            if r.get("outcome") in _UNDER_PERMIT and parent.get("decision") != "PERMIT":
                problems.append(f"decision {did[:12]}: {r.get('outcome')} under a "
                                f"{parent.get('decision')} decision")
            follow.setdefault(did, {}).setdefault(r.get("outcome") or "?", []).append(r)

    effect_ids: dict[str, int] = {}
    for e in effects:
        did = (e.get("decision_id") if isinstance(e, dict) else e) or ""
        effect_ids[did] = effect_ids.get(did, 0) + 1

    for did, kinds in follow.items():
        for kind in ("dispatched", "exported"):
            if len(kinds.get(kind, [])) > 1:
                problems.append(f"decision {did[:12]}: {len(kinds[kind])} {kind} records")
        outcomes = kinds.get("succeeded", []) + kinds.get("unknown", [])
        if len(outcomes) > 1:
            problems.append(f"decision {did[:12]}: {len(outcomes)} execution outcomes")
        if outcomes and not kinds.get("dispatched"):
            problems.append(f"decision {did[:12]}: execution outcome without a sealed intent")
        if kinds.get("dispatched") and kinds.get("exported"):
            problems.append(f"decision {did[:12]}: both dispatched in-process and exported")
        if kinds.get("succeeded") and effect_ids.get(did, 0) == 0:
            problems.append(f"decision {did[:12]}: outcome 'succeeded' but the resource "
                            f"recorded no effect")

    for did, count in effect_ids.items():
        if not did:
            problems.append(f"{count} resource effect(s) carry no decision id")
            continue
        if count > 1:
            problems.append(f"decision {did[:12]}: {count} resource effects (duplicate commit)")
        rec = decisions.get(did)
        if rec is None or rec.get("decision") != "PERMIT":
            problems.append(f"decision {did[:12]}: resource effect without a PERMIT "
                            f"decision record")
            continue
        kinds = follow.get(did, {})
        if mediated:
            if not kinds.get("exported"):
                problems.append(f"decision {did[:12]}: mediated effect without an "
                                f"exported-lease record")
        elif not (kinds.get("dispatched") and (kinds.get("succeeded") or kinds.get("unknown"))):
            problems.append(f"decision {did[:12]}: in-process effect without a sealed "
                            f"intent and outcome")

    def count(kind):
        return sum(len(k.get(kind, [])) for k in follow.values())
    dispatched_ids = {d for d, k in follow.items() if k.get("dispatched")}
    return {
        "ok": not problems,
        "problems": problems,
        "counts": {
            "decision_records": len(decisions),
            "authorized": sum(1 for r in decisions.values() if r.get("decision") == "PERMIT"),
            "dispatched": count("dispatched"), "exported": count("exported"),
            "succeeded": count("succeeded"), "unknown": count("unknown"),
            "refused": count("refused"),
            "dispatched_without_outcome": sum(
                1 for d in dispatched_ids
                if not (follow[d].get("succeeded") or follow[d].get("unknown"))),
            "effects": sum(effect_ids.values()),
            "effects_bound": sum(c for d, c in effect_ids.items()
                                 if d and decisions.get(d, {}).get("decision") == "PERMIT"),
            "unbound_records": unbound,
        },
    }
