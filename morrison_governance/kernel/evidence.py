"""Evidence integrity: logic-binding ruleset hashing + append-only chaining.

Two red-team findings this module closes:

  EV-01  `_ruleset_hash()` hashed only sorted "{domain}:{name}". Replacing
         `cyber_destructive_action`'s check with `lambda s: False` left the
         hash byte-identical while `wipe_disk` flipped BLOCK → PERMIT. Every
         attestation, replay verification and audit pack still validated.

  EV-02  `DecisionRecord` was a plain mutable dataclass in a plain list, with
         no prev_hash, no record_hash, no signature, no actor and no
         timestamp. A BLOCK could be mutated into an executed PERMIT and
         `fail_closed_holds()` still returned True.

Here the ruleset hash binds the executable policy LOGIC (bytecode, constants,
referenced globals and closure values of every rule's `check`), and every
decision is a hash-chained record binding the canonical action, the ruleset
version, the actor, the decision, the authorisation provenance and the
execution result.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# ─────────────────────────────────────────────────────────────
# Logic-binding ruleset hash
# ─────────────────────────────────────────────────────────────


def _fingerprint_callable(fn: Any) -> str:
    """Stable fingerprint of a callable's executable content.

    Binds bytecode, constants, names and closure cell values — so changing
    what a rule DOES changes the fingerprint even when its name is unchanged.
    """
    parts: list[str] = []
    code = getattr(fn, "__code__", None)
    if code is None:
        # builtin / C callable / functools object — fall back to its repr and
        # any wrapped function.
        wrapped = getattr(fn, "func", None) or getattr(fn, "__wrapped__", None)
        if wrapped is not None and wrapped is not fn:
            return _fingerprint_callable(wrapped)
        return hashlib.sha256(repr(fn).encode()).hexdigest()

    parts.append(code.co_name)
    parts.append(str(code.co_argcount))
    parts.append(code.co_code.hex())
    for const in code.co_consts:
        if hasattr(const, "co_code"):           # nested code object
            parts.append("code:" + const.co_code.hex())
            parts.append("consts:" + repr(const.co_consts))
        else:
            parts.append("const:" + repr(const))
    parts.append("names:" + repr(code.co_names))
    parts.append("varnames:" + repr(code.co_varnames))

    # Closure values (a rule built by a factory carries its config here).
    closure = getattr(fn, "__closure__", None)
    if closure:
        for cell in closure:
            try:
                val = cell.cell_contents
            except ValueError:
                parts.append("cell:<empty>")
                continue
            if callable(val):
                parts.append("cell:" + _fingerprint_callable(val))
            else:
                parts.append("cell:" + repr(val)[:512])

    # Module-level globals the rule actually reads (regexes, tool sets).
    g = getattr(fn, "__globals__", {}) or {}
    for name in sorted(set(code.co_names)):
        if name not in g:
            continue
        val = g[name]
        if isinstance(val, (set, frozenset)):
            parts.append(f"glob:{name}:" + repr(sorted(map(str, val))))
        elif isinstance(val, (str, int, float, bool, tuple, list)):
            parts.append(f"glob:{name}:" + repr(val)[:512])
        elif hasattr(val, "pattern"):            # compiled regex
            parts.append(f"glob:{name}:re:" + str(val.pattern))

    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def rule_fingerprint(rule: Any) -> str:
    """Fingerprint one OmegaRule: identity AND behaviour."""
    ident = f"{getattr(getattr(rule, 'domain', None), 'value', '')}:" \
            f"{getattr(rule, 'name', '')}:{getattr(rule, 'severity', '')}"
    logic = _fingerprint_callable(getattr(rule, "check", None))
    return hashlib.sha256((ident + "|" + logic).encode()).hexdigest()


def ruleset_hash(rules, extra: Optional[dict] = None) -> str:
    """Hash binding the executable policy of an entire ruleset.

    A material change to any rule's logic changes this value, even when every
    rule name is unchanged. `extra` folds in non-rule policy configuration
    (capability policy, thresholds, manifests) so the whole enforcing
    configuration is covered.
    """
    canon = "\n".join(sorted(rule_fingerprint(r) for r in rules))
    if extra:
        canon += "\n#extra:" + json.dumps(extra, sort_keys=True, default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


def ruleset_manifest(rules) -> list[dict]:
    """Per-rule fingerprints, for diffing two deployments."""
    return sorted(
        ({"domain": getattr(getattr(r, "domain", None), "value", ""),
          "name": getattr(r, "name", ""),
          "fingerprint": rule_fingerprint(r)} for r in rules),
        key=lambda d: (d["domain"], d["name"]))


# ─────────────────────────────────────────────────────────────
# Hash-chained decision evidence
# ─────────────────────────────────────────────────────────────

GENESIS = "0" * 64


@dataclass
class EvidenceRecord:
    """One governance decision, bound to everything needed to verify it."""

    seq: int
    timestamp: float
    actor: str
    tenant: str
    action_hash: str                 # canonical action the decision applies to
    proposed: dict                   # the action as proposed (post-canonical)
    decision: str                    # PERMIT | BLOCK | ESCALATE | ...
    layer: str = ""
    rule: Optional[str] = None
    omega_domain: Optional[str] = None
    reason: str = ""
    capabilities: list = field(default_factory=list)
    requirement: str = ""
    # authorisation provenance — how authority was (or was not) established
    authorization: dict = field(default_factory=dict)
    forged_authority_claims: list = field(default_factory=list)
    ruleset_hash: str = ""
    engine_version: str = ""
    executed: bool = False
    execution_result: Optional[str] = None
    trajectory_hash: str = ""
    prev_hash: str = GENESIS
    record_hash: str = ""
    signature: str = ""

    # ── integrity ────────────────────────────────────────────
    def _digest_payload(self) -> str:
        body = {k: v for k, v in asdict(self).items()
                if k not in ("record_hash", "signature")}
        return json.dumps(body, sort_keys=True, default=str, ensure_ascii=False)

    def seal(self, key: bytes = b"") -> "EvidenceRecord":
        self.record_hash = hashlib.sha256(self._digest_payload().encode()).hexdigest()
        if key:
            self.signature = hmac.new(key, self.record_hash.encode(),
                                      hashlib.sha256).hexdigest()
        return self

    def verify(self, key: bytes = b"") -> tuple[bool, str]:
        expect = hashlib.sha256(self._digest_payload().encode()).hexdigest()
        if not hmac.compare_digest(expect, self.record_hash or ""):
            return False, (f"record {self.seq} content does not match its hash "
                           f"(tampered)")
        if key:
            sig = hmac.new(key, self.record_hash.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, self.signature or ""):
                return False, f"record {self.seq} signature invalid"
        return True, "ok"

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, ensure_ascii=False, default=str)


@dataclass
class EvidenceChain:
    """Append-only, hash-chained decision log.

    Any silent edit — including flipping a BLOCK into an executed PERMIT —
    breaks either the record hash or the chain link, and `verify()` reports
    exactly which record failed.
    """

    key: bytes = b""
    records: list = field(default_factory=list)

    @property
    def head(self) -> str:
        return self.records[-1].record_hash if self.records else GENESIS

    def append(self, rec: EvidenceRecord) -> EvidenceRecord:
        rec.seq = len(self.records)
        rec.prev_hash = self.head
        rec.seal(self.key)
        self.records.append(rec)
        return rec

    def record_execution(self, rec: EvidenceRecord, executed: bool,
                         result: Optional[str] = None) -> EvidenceRecord:
        """Execution outcome is a NEW sealed record, never a mutation of the
        authorising one — so the decision and its outcome are both immutable."""
        follow = EvidenceRecord(
            seq=0, timestamp=time.time(), actor=rec.actor, tenant=rec.tenant,
            action_hash=rec.action_hash, proposed=rec.proposed,
            decision=rec.decision, layer="execution",
            reason=f"execution outcome for decision {rec.record_hash[:12]}…",
            ruleset_hash=rec.ruleset_hash, executed=executed,
            execution_result=result, capabilities=list(rec.capabilities),
            authorization=dict(rec.authorization),
        )
        return self.append(follow)

    def verify(self) -> tuple[bool, list]:
        """Full-chain verification: per-record integrity plus link continuity."""
        problems: list[str] = []
        prev = GENESIS
        for rec in self.records:
            ok, why = rec.verify(self.key)
            if not ok:
                problems.append(why)
            if rec.prev_hash != prev:
                problems.append(
                    f"record {rec.seq} chain break: prev_hash "
                    f"{rec.prev_hash[:12]}… != {prev[:12]}…")
            prev = rec.record_hash
        # Fail-closed invariant, verified against sealed evidence.
        for rec in self.records:
            if rec.executed and rec.decision not in ("PERMIT",):
                problems.append(
                    f"record {rec.seq} violates fail-closed: executed with "
                    f"decision {rec.decision}")
        return (not problems), problems

    def to_jsonl(self) -> str:
        return "\n".join(r.to_json() for r in self.records)

    def summary(self) -> dict:
        ok, problems = self.verify()
        return {
            "records": len(self.records),
            "head": self.head[:16],
            "integrity_verified": ok,
            "problems": problems,
            "executed": sum(1 for r in self.records if r.executed),
        }
