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

import copy
import hashlib
import hmac
import json
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# ─────────────────────────────────────────────────────────────
# Logic-binding ruleset hash
# ─────────────────────────────────────────────────────────────


_ADDR_RE = re.compile(r" at 0x[0-9a-fA-F]+")


def _canon_repr(value: Any, depth: int = 0) -> str:
    """Deterministic, process-independent repr.

    Two sources of cross-process instability made the ruleset hash differ on
    every restart, which silently broke attestation and replay:

      1. UNORDERED CONTAINERS. `repr(frozenset)`/`repr(set)` iterate in hash
         order, and CPython interns string hashes per-process (PYTHONHASHSEED).
         Crucially, `x in {"a", "b"}` COMPILES TO A FROZENSET CONSTANT — so
         ordinary membership tests inside rule bodies carried an unstable repr.
      2. MEMORY ADDRESSES. Default object reprs embed `at 0x7f…`, which differs
         per process and per run.

    Both are normalised here. Ordered containers keep their order because order
    is semantically meaningful in a list or tuple; only genuinely unordered
    containers are sorted.
    """
    if depth > 12:
        return "<max-depth>"
    if isinstance(value, (frozenset, set)):
        inner = sorted(_canon_repr(v, depth + 1) for v in value)
        kind = "frozenset" if isinstance(value, frozenset) else "set"
        return f"{kind}({{{', '.join(inner)}}})"
    if isinstance(value, dict):
        items = sorted((_canon_repr(k, depth + 1), _canon_repr(v, depth + 1))
                       for k, v in value.items())
        return "{" + ", ".join(f"{k}: {v}" for k, v in items) + "}"
    if isinstance(value, tuple):
        return "(" + ", ".join(_canon_repr(v, depth + 1) for v in value) + ")"
    if isinstance(value, list):
        return "[" + ", ".join(_canon_repr(v, depth + 1) for v in value) + "]"
    if hasattr(value, "co_code"):                    # nested code object
        return ("code(" + value.co_code.hex() + ","
                + _canon_repr(tuple(value.co_consts), depth + 1) + ","
                + _canon_repr(tuple(value.co_names), depth + 1) + ")")
    if hasattr(value, "pattern") and hasattr(value, "flags"):   # compiled regex
        return f"re({value.pattern!r},{int(value.flags)})"
    if isinstance(value, (str, bytes, int, float, bool)) or value is None:
        return repr(value)
    return _ADDR_RE.sub("", repr(value))


def _fingerprint_callable(fn: Any) -> str:
    """Stable fingerprint of a callable's executable content.

    Binds bytecode, constants, names and closure cell values — so changing
    what a rule DOES changes the fingerprint even when its name is unchanged.
    Every value is rendered through `_canon_repr`, so the fingerprint is
    identical across processes and machines (see `_canon_repr`).
    """
    parts: list[str] = []
    code = getattr(fn, "__code__", None)
    if code is None:
        # builtin / C callable / functools object — fall back to its repr and
        # any wrapped function.
        wrapped = getattr(fn, "func", None) or getattr(fn, "__wrapped__", None)
        if wrapped is not None and wrapped is not fn:
            return _fingerprint_callable(wrapped)
        return hashlib.sha256(_canon_repr(fn).encode()).hexdigest()

    parts.append(code.co_name)
    parts.append(str(code.co_argcount))
    parts.append(code.co_code.hex())
    for const in code.co_consts:
        parts.append("const:" + _canon_repr(const))
    parts.append("names:" + _canon_repr(tuple(code.co_names)))
    parts.append("varnames:" + _canon_repr(tuple(code.co_varnames)))

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
                parts.append("cell:" + _canon_repr(val)[:512])

    # Module-level globals the rule actually reads (regexes, tool sets).
    g = getattr(fn, "__globals__", {}) or {}
    for name in sorted(set(code.co_names)):
        if name not in g:
            continue
        val = g[name]
        if isinstance(val, (set, frozenset, dict, str, bytes, int, float,
                            bool, tuple, list)) or hasattr(val, "pattern"):
            parts.append(f"glob:{name}:" + _canon_repr(val)[:2048])

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
        # `_canon_repr`, not json.dumps(default=str): a set anywhere in `extra`
        # would otherwise be stringified in hash order and reintroduce exactly
        # the cross-process instability this function exists to avoid.
        canon += "\n#extra:" + _canon_repr(extra)
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
    # The action as the Ω engine saw it: `proposed` minus the authority
    # namespace. Recorded separately so the audit trail shows BOTH what ran and
    # what was evaluated. `proposed` used to hold `evaluated`, which made the
    # human-readable record disagree with its own action_hash.
    evaluated: Optional[dict] = None
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
    # ── decision-to-execution binding (independent review, finding B) ──
    # A decision record used to carry no decision id and no session id, and an
    # execution outcome named its decision only by a 12-character hash prefix
    # inside free-text `reason`. Resource effects are keyed by decision id, so
    # no persisted effect could be joined to the record that authorised it.
    decision_id: str = ""            # the Decision this record is about
    session_id: str = ""
    # record_hash of the DECISION record a follow-up record (intent, outcome,
    # refusal, lease export) refers to; "" on the decision record itself.
    refers_to: str = ""
    # What a follow-up record asserts, as data rather than prose:
    #   ""             the decision record itself
    #   "dispatched"   execution intent sealed BEFORE the effect
    #   "succeeded"    the executor returned
    #   "unknown"      the executor raised after dispatch; may have landed
    #   "refused"      execution was refused at the boundary
    #   "exported"     authority exported as a resource-verified lease
    #   "cancelled"    an exported lease was cancelled unredeemed
    #   "remote"       a remote runtime reported executing it
    #   "reconciled_executed" / "reconciled_not_executed"
    # `executed=True` with outcome "unknown" means "treated as having landed",
    # NOT "observed to have landed".
    outcome: str = ""
    prev_hash: str = GENESIS
    record_hash: str = ""
    signature: str = ""

    # ── integrity ────────────────────────────────────────────
    def _digest_payload(self) -> str:
        body = {k: v for k, v in asdict(self).items()
                if k not in ("record_hash", "signature")
                # `evaluated` is absent from legacy records. Omitting the
                # default keeps every previously sealed record's hash stable
                # while still binding the field on new decision records.
                and not (k == "evaluated" and v is None)}
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


_APPEND_LOCK = threading.RLock()


class JsonlEvidenceSink:
    """Durable, write-ahead persistence for ONE evidence chain.

    Each sealed record is written as one JSON line and fsynced before
    `EvidenceChain.append` returns, so a record the kernel acted on (a decision
    it returned, an intent it dispatched behind) is on disk first. A failed
    write is rolled back to the previous length and raised; the chain does not
    advance, and the kernel's existing fail-closed paths take over (a decision
    is not returned, an intent failure refuses execution, an outcome failure is
    queued and sealed late).

    One file holds one chain. Appending a second chain to a file that already
    holds one is exactly how the benchmark's persisted evidence came to fail
    recomputation, so a non-empty file is refused.
    """

    def __init__(self, path) -> None:
        import os
        self.path = str(path)
        self._fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        if os.fstat(self._fd).st_size:
            os.close(self._fd)
            raise ValueError(f"{self.path} already holds evidence; one file per chain")

    def __call__(self, rec: "EvidenceRecord") -> None:
        import os
        line = (rec.to_json() + "\n").encode("utf-8")
        start = os.fstat(self._fd).st_size
        try:
            written = os.write(self._fd, line)
            if written != len(line):
                raise OSError(f"short write ({written} of {len(line)} bytes)")
            os.fsync(self._fd)
        except BaseException:
            try:
                os.ftruncate(self._fd, start)
            finally:
                raise

    def close(self) -> None:
        import os
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1


@dataclass
class EvidenceChain:
    """Append-only, hash-chained decision log.

    Any silent edit — including flipping a BLOCK into an executed PERMIT —
    breaks either the record hash or the chain link, and `verify()` reports
    exactly which record failed.

    `sink`, when set, receives every sealed record BEFORE it joins the chain
    (see `JsonlEvidenceSink`); if it raises, the record is not appended.

    KEYLESS MODE IS NOT AUTHENTICITY. A plain SHA-256 chain detects accidental
    corruption and edits made by someone who does not recompute the chain; a
    writer that can rewrite the whole chain and recompute its hashes passes
    `verify()`. Configure `key`/`GovernanceKernel(evidence_key=...)` (or
    `require_evidence_key=True`) when the chain must be tamper-EVIDENT against
    an offline or persisted rewrite.
    """

    key: bytes = b""
    records: list = field(default_factory=list)
    sink: Optional[Any] = None

    @property
    def head(self) -> str:
        return self.records[-1].record_hash if self.records else GENESIS

    def append(self, rec: EvidenceRecord) -> EvidenceRecord:
        # Read-head, link, seal and append must be one step. Two threads
        # appending at once (an execution outcome recorded outside the kernel
        # lock while another execution's intent is sealed inside it) took the
        # same head and seq and broke the chain (R2). A module lock rather than
        # a field keeps the chain copyable and picklable.
        with _APPEND_LOCK:
            rec.seq = len(self.records)
            rec.prev_hash = self.head
            rec.seal(self.key)
            if self.sink is not None:
                self.sink(rec)
            self.records.append(rec)
            return rec

    def record_execution(self, rec: EvidenceRecord, executed: bool,
                         result: Optional[str] = None,
                         outcome: str = "") -> EvidenceRecord:
        """Execution outcome is a NEW sealed record, never a mutation of the
        authorising one — so the decision and its outcome are both immutable.
        It names its decision by id and by the decision record's full hash."""
        follow = EvidenceRecord(
            seq=0, timestamp=time.time(), actor=rec.actor, tenant=rec.tenant,
            action_hash=rec.action_hash, proposed=copy.deepcopy(rec.proposed),
            evaluated=copy.deepcopy(rec.evaluated),
            decision=rec.decision, layer="execution",
            reason=f"execution outcome for decision {rec.record_hash[:12]}…",
            ruleset_hash=rec.ruleset_hash, executed=executed,
            execution_result=result, capabilities=list(rec.capabilities),
            authorization=dict(rec.authorization),
            decision_id=rec.decision_id, session_id=rec.session_id,
            refers_to=rec.record_hash,
            outcome=outcome or ("succeeded" if executed else "refused"),
        )
        return self.append(follow)

    def anchor(self) -> dict:
        """The (head, count) a verifier needs to detect truncation later.

        A chain can only prove it is internally consistent. Deleting records
        from its END leaves a shorter chain that is still consistent, so
        detecting truncation needs the head and count recorded somewhere the
        writer of the chain cannot rewrite. Export this value there.
        """
        return {"head": self.head, "count": len(self.records),
                "keyed": bool(self.key)}

    def verify(self, expected_head: str = "",
               expected_count: Optional[int] = None,
               require_key: bool = False) -> tuple[bool, list]:
        """Full-chain verification: per-record integrity plus link continuity.

        `expected_head` / `expected_count` come from a previously exported
        anchor (`anchor()`). With them, a chain whose tail was removed fails;
        without them, truncation is undetectable and only consistency is
        checked. `require_key` fails a keyless chain, whose hashes anyone
        holding the records can recompute.
        """
        problems: list[str] = []
        if require_key and not self.key:
            problems.append("evidence chain is keyless: integrity only, not "
                            "authenticity (no evidence key configured)")
        if expected_count is not None and len(self.records) < expected_count:
            problems.append(
                f"evidence truncated: {expected_count - len(self.records)} "
                f"record(s) missing against the anchored count "
                f"{expected_count}")
        if expected_head:
            idx = (expected_count - 1) if expected_count else None
            heads = [r.record_hash for r in self.records]
            if idx is not None and 0 <= idx < len(heads):
                if heads[idx] != expected_head:
                    problems.append(
                        f"anchored head mismatch at record {idx}: the chain "
                        f"was rewritten or substituted")
            elif expected_head not in heads:
                problems.append("anchored head is not in this chain: "
                                "truncated, rewritten or substituted")
        prev = GENESIS
        from morrison_governance.kernel.canonical import (
            action_hash as _action_hash,
        )
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
            # `action_hash` must bind the record's own `proposed` action. The
            # decision record used to store the evaluated residue there while
            # hashing the full proposal, so the audit field named an action
            # that did not run. Checked only for records that carry an
            # `evaluated` field, which identifies records written under this
            # schema; legacy/synthetic records are still integrity-checked.
            if rec.evaluated is not None:
                try:
                    bound = _action_hash(rec.proposed)
                except Exception:                    # noqa: BLE001 — fail closed
                    bound = ""
                if bound != rec.action_hash:
                    problems.append(
                        f"record {rec.seq} action_hash does not bind its "
                        f"proposed action (audit record names an action that "
                        f"did not run)")
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
