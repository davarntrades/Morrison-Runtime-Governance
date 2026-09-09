"""Authority continuity — governed history that outlives the session.

The red-team finding this module closes:

    Governed history, spent approvals and denied attempts were scoped to a
    KERNEL INSTANCE, and the kernel treated one instance as one session. That is
    sound only if an actor cannot choose how many sessions it gets. It can: a
    new kernel — from a session rotation, a process restart, a worker
    migration, a retry, or a plain constructor call — started with an empty
    trajectory, an unspent approval, and no record of what it had just been
    refused.

    So a prohibited two-step trajectory executed one step per session, an
    action BLOCKed in one session succeeded on retry in the next, and one
    single-use $4.5M approval moved $13.5M across three sessions.

The fix is to key governed history to a PERSISTENT EXECUTION IDENTITY rather
than to the session that happens to be running:

    session id   →  which conversation this is.       Rotates freely.
    continuity key → whose authority this is.         Does not.

    ContinuityKey = (tenant, principal, workload)

all three from the server-side `SecurityContext`, never from a call. An actor
cannot rotate its own key, because it cannot write any of the three.

ISOLATION IS PART OF THE PROPERTY, NOT A CONCESSION TO IT. The key is the
isolation boundary: two principals, two tenants, or two genuinely independent
workloads have different keys and share nothing. Solving session splitting by
merging unrelated histories would make agent-b in tenant beta inherit taint from
agent-a in tenant acme — a worse system, not a safer one. `workload` exists so a
deployment can separate one principal's genuinely independent jobs; because it
is trusted configuration, separating them is an administrative act, not
something the agent can do to itself mid-attack.

WHERE CONTINUITY CANNOT BE ESTABLISHED, NOTHING IS ASSUMED CLEAN. An
unidentifiable principal or an unreachable store is not a fresh start; it is an
unknown history, and the kernel escalates or blocks rather than treating the
execution as clean.

Stores
------
`InMemoryContinuityStore`   process-wide. Closes fragmentation across sessions,
                            threads and workers inside one process.
`FileContinuityStore`       append-only JSONL under an advisory lock. Adds
                            durability across process restart and sharing
                            between processes on one host.

Neither is a distributed store. `ContinuityStore` is the interface a deployment
implements against Redis, a database, or its own ledger service; a multi-host
deployment that leaves the default in place has continuity per host and no
further, and should say so. See LIMITATIONS.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Iterable, Optional, Protocol

DENIED = "denied"
RESERVED = "reserved"
EXECUTED = "executed"
# A reservation whose lease lapsed without ever being released or confirmed.
# It is NOT an abandoned plan: the caller held a PERMIT and may have run it —
# a decision-plane runtime that crashes after acting looks exactly like this.
# Treated as history, because "we do not know" must not read as "it did not
# happen".
UNCONFIRMED = "unconfirmed"

# How the kernel behaves when continuity cannot be established.
ESCALATE_POLICY = "escalate"
BLOCK_POLICY = "block"
PERMIT_POLICY = "permit"          # explicit, auditable opt-out


# ─────────────────────────────────────────────────────────────
# Identity
# ─────────────────────────────────────────────────────────────

_SAFE = re.compile(r"[^a-z0-9._:-]+")


def _slug(value: str) -> str:
    """A READABLE label. Lossy by design; never used alone as an identity."""
    return _SAFE.sub("_", str(value or "").strip().lower())


@dataclass(frozen=True)
class ContinuityKey:
    """The persistent execution identity governed history is filed under."""

    tenant: str
    principal: str
    workload: str = ""

    def fingerprint(self) -> str:
        """A collision-free digest of the exact identity triple.

        The readable slug is NOT an identity. It replaces every character
        outside `[a-z0-9._:-]` with `_` and joins the three fields with `/`,
        and since `/` is itself replaceable the mapping is many-to-one:
        `("acme", "agent-x/y")` and `("acme", "agent-x_y")` produced the same
        string, so two distinct principals shared one governed history. That
        defeats the isolation property (CONT-05) which is what makes continuity
        safe rather than blunt, and it needs no forgery — identity providers
        emit names containing `/` routinely.

        The digest is taken over a length-prefixed encoding, so no arrangement
        of separators inside a field can imitate a field boundary.
        """
        parts = [self.tenant, self.principal, self.workload]
        encoded = "\x1f".join(f"{len(p)}:{p}" for p in parts)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:32]

    def as_str(self) -> str:
        """The storage key: a readable prefix plus the collision-free digest.

        The prefix is for operators reading a store by eye; the digest is what
        makes the key an identity.
        """
        return (f"{_slug(self.tenant)}/{_slug(self.principal)}/"
                f"{_slug(self.workload)}#{self.fingerprint()}")

    def __str__(self) -> str:            # pragma: no cover - convenience
        return self.as_str()


@dataclass(frozen=True)
class ContinuityStatus:
    """Whether a persistent identity could be established, and why not."""

    key: Optional[ContinuityKey]
    established: bool
    reason: str = ""

    @property
    def name(self) -> str:
        return self.key.as_str() if self.key else "(unestablished)"


_ANONYMOUS_IDS = frozenset({"", "anonymous", "unknown", "none", "null", "-"})


def resolve_continuity(principal: Any, workload: str = "") -> ContinuityStatus:
    """Derive the continuity key from an authenticated principal.

    Fails when the identity is not specific enough to file history under.
    A principal we cannot name is a principal whose past we cannot look up, and
    the honest answer is "unknown history", never "no history".
    """
    principal_id = str(getattr(principal, "id", "") or "").strip()
    tenant = str(getattr(principal, "tenant", "") or "").strip()

    if principal_id.lower() in _ANONYMOUS_IDS:
        return ContinuityStatus(
            None, False,
            "the principal is anonymous, so no governed history can be "
            "attributed to it and none can be ruled out")
    if not tenant:
        return ContinuityStatus(
            None, False,
            f"principal {principal_id!r} has no tenant, so its governed "
            f"history cannot be isolated from another tenant's")
    return ContinuityStatus(
        ContinuityKey(tenant=tenant, principal=principal_id, workload=workload),
        True, "continuity established")


# ─────────────────────────────────────────────────────────────
# Entries
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LedgerEntry:
    """One governed attempt, as it is filed against a continuity key."""

    decision_id: str
    action: dict
    verdict: str
    state: str
    reason: str = ""
    actor: str = ""
    session_id: str = ""
    semantic_hash: str = ""
    capabilities: tuple = ()
    timestamp: float = 0.0
    # The wall-clock instant this entry was filed, independent of the `now` the
    # caller passed. `timestamp` may be an evaluation clock — a finite-model
    # verifier legitimately drives the kernel from t=0 — and the retention
    # window used to filter on it, so an action executed with `now=0.0` was
    # filed outside every realistic window and vanished from the very next
    # decision. Retention filters on THIS field.
    wall_timestamp: float = 0.0
    expires_at: float = 0.0
    # Wall-clock deadline for a reservation, for the same reason.
    wall_expires_at: float = 0.0
    seq: int = 0

    def to_json(self) -> str:
        return json.dumps({**asdict(self), "capabilities": list(self.capabilities)},
                          sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def from_json(line: str) -> "LedgerEntry":
        raw = json.loads(line)
        raw["capabilities"] = tuple(raw.get("capabilities") or ())
        return LedgerEntry(**raw)


class ContinuityStore(Protocol):
    """The contract a deployment implements to share governed history.

    Every method is keyed, so one store serves every principal without any of
    them seeing another's history.

    `consume` MUST be atomic: it is the single-use primitive behind both
    approval nonces and decision leases, and a store that lets two callers both
    receive True re-opens the double-spend.

    `transaction(key)` MUST serialise the whole authorize read-modify-write for
    one continuity key across every concurrent writer the deployment has. An
    in-process lock is not enough: two PROCESSES authorising for the same
    principal at the same moment each read the history before either wrote it,
    and both were permitted — the concurrent form of trajectory fragmentation.
    """

    def transaction(self, key: str): ...
    def append(self, key: str, entry: LedgerEntry) -> LedgerEntry: ...
    def entries(self, key: str) -> list: ...
    def set_state(self, key: str, decision_id: str, state: str,
                  timestamp: float, action: Optional[dict] = None) -> bool: ...
    def drop(self, key: str, decision_id: str) -> bool: ...
    def consume(self, key: str, token: str) -> bool: ...
    def consumed(self, key: str, token: str) -> bool: ...
    def revoke(self, key: str, semantic_hash: str, reason: str) -> None: ...
    def revocation(self, key: str, semantic_hash: str): ...
    def health(self) -> None: ...

    def scope(self) -> str:
        """How far this store's continuity reaches.

        One of "process", "host", "deployment". Surfaced on every decision so a
        deployment can ASSERT the scope of the guarantee it is relying on
        instead of believing it. A store shared across a fleet returns
        "deployment"; the built-in stores do not, and say so.
        """


class InMemoryContinuityStore:
    """Process-wide governed history. Thread-safe, not durable.

    Closes fragmentation across sessions, threads and workers within one
    process. A restart is still a clean slate — use `FileContinuityStore` or a
    deployment store for durability.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, list[LedgerEntry]] = {}
        self._tokens: dict[str, set[str]] = {}
        self._revoked: dict[str, dict[str, str]] = {}

    @contextmanager
    def transaction(self, key: str):
        """Serialise one key's read-modify-write. Reentrant within a thread."""
        with self._lock:
            yield

    def append(self, key: str, entry: LedgerEntry) -> LedgerEntry:
        with self._lock:
            bucket = self._entries.setdefault(key, [])
            stamped = replace(entry, seq=len(bucket))
            bucket.append(stamped)
            return stamped

    def entries(self, key: str) -> list:
        with self._lock:
            return list(self._entries.get(key, ()))

    def set_state(self, key: str, decision_id: str, state: str,
                  timestamp: float, action: Optional[dict] = None) -> bool:
        with self._lock:
            bucket = self._entries.get(key, [])
            for index, entry in enumerate(bucket):
                if entry.decision_id == decision_id:
                    bucket[index] = replace(
                        entry, state=state, timestamp=timestamp,
                        action=action if action is not None else entry.action)
                    return True
            return False

    def drop(self, key: str, decision_id: str) -> bool:
        with self._lock:
            bucket = self._entries.get(key, [])
            for index, entry in enumerate(bucket):
                if entry.decision_id == decision_id and entry.state == RESERVED:
                    bucket.pop(index)
                    return True
            return False

    def consume(self, key: str, token: str) -> bool:
        with self._lock:
            spent = self._tokens.setdefault(key, set())
            if token in spent:
                return False
            spent.add(token)
            return True

    def consumed(self, key: str, token: str) -> bool:
        with self._lock:
            return token in self._tokens.get(key, ())

    def revoke(self, key: str, semantic_hash: str, reason: str) -> None:
        with self._lock:
            self._revoked.setdefault(key, {}).setdefault(
                semantic_hash, (reason, time.time()))

    def revocation(self, key: str, semantic_hash: str):
        """Returns `(reason, revoked_at)` or None. The caller applies the TTL."""
        with self._lock:
            return self._revoked.get(key, {}).get(semantic_hash)

    def health(self) -> None:
        return None

    def scope(self) -> str:
        return "process"

    def reset(self) -> None:
        """Drop all history. For tests and for an operator wiping a deployment."""
        with self._lock:
            self._entries.clear()
            self._tokens.clear()
            self._revoked.clear()


class FileContinuityStore:
    """Append-only JSONL governed history under an advisory file lock.

    Durable across process restart and shared between processes on one host,
    which is what closes trajectory fragmentation by restart or worker
    migration. Every mutation is an appended record, so a crash mid-write
    truncates at a record boundary and the surviving prefix still reads back —
    a torn final line is discarded rather than failing the whole store.

    Not a distributed store: two hosts writing to two paths have two histories.
    """

    def __init__(self, path: str, fsync: bool = True) -> None:
        self.path = str(path)
        self.fsync = fsync
        self._lock = threading.RLock()
        self._depth = 0
        self._held = None
        self._lock_path = self.path + ".lock"
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    @contextmanager
    def transaction(self, key: str):
        """Hold an EXCLUSIVE cross-process lock for the whole critical section.

        Reentrant: `flock` is held per file descriptor, so a nested acquire on a
        second descriptor in the same process would deadlock against itself.
        One descriptor is held for the outermost transaction and inner
        operations ride on it.

        The lock covers the whole file rather than one key. Coarser than it
        needs to be, and correct; a deployment that needs per-key concurrency
        should implement `ContinuityStore` against a database.
        """
        with self._lock:
            outermost = self._depth == 0
            if outermost:
                handle = open(self._lock_path, "a+", encoding="utf-8")
                _flock(handle)
                self._held = handle
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
                if outermost:
                    try:
                        _funlock(self._held)
                    finally:
                        self._held.close()
                        self._held = None

    # ── file plumbing ────────────────────────────────────────
    def _write(self, record: dict) -> None:
        line = json.dumps(record, sort_keys=True, separators=(",", ":"),
                          default=str)
        with self.transaction(""):
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                if self.fsync:
                    os.fsync(handle.fileno())

    def _read(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        with self.transaction(""):
            with open(self.path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        out: list[dict] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                # A torn final record from a crash. Discard the fragment; the
                # committed prefix is still authoritative.
                continue
        return out

    # ── ContinuityStore ──────────────────────────────────────
    def append(self, key: str, entry: LedgerEntry) -> LedgerEntry:
        with self.transaction(key):
            stamped = replace(entry, seq=len(self.entries(key)))
            self._write({"op": "append", "key": key,
                         "entry": json.loads(stamped.to_json())})
            return stamped

    def entries(self, key: str) -> list:
        state: dict[str, LedgerEntry] = {}
        order: list[str] = []
        for record in self._read():
            if record.get("key") != key:
                continue
            op = record.get("op")
            if op == "append":
                entry = LedgerEntry(**{**record["entry"],
                                       "capabilities": tuple(record["entry"].get("capabilities") or ())})
                if entry.decision_id not in state:
                    order.append(entry.decision_id)
                state[entry.decision_id] = entry
            elif op == "state" and record.get("decision_id") in state:
                entry = state[record["decision_id"]]
                state[record["decision_id"]] = replace(
                    entry, state=record["state"],
                    timestamp=record.get("timestamp", entry.timestamp),
                    action=record.get("action") or entry.action)
            elif op == "drop" and record.get("decision_id") in state:
                state.pop(record["decision_id"], None)
                order = [d for d in order if d != record["decision_id"]]
        return [state[d] for d in order if d in state]

    def set_state(self, key: str, decision_id: str, state: str,
                  timestamp: float, action: Optional[dict] = None) -> bool:
        self._write({"op": "state", "key": key, "decision_id": decision_id,
                     "state": state, "timestamp": timestamp, "action": action})
        return True

    def drop(self, key: str, decision_id: str) -> bool:
        self._write({"op": "drop", "key": key, "decision_id": decision_id})
        return True

    def consume(self, key: str, token: str) -> bool:
        """Atomic across processes: read-then-write inside the file lock."""
        with self.transaction(key):
            if self.consumed(key, token):
                return False
            self._write({"op": "consume", "key": key, "token": token,
                         "timestamp": time.time()})
            return True

    def consumed(self, key: str, token: str) -> bool:
        return any(r.get("op") == "consume" and r.get("key") == key
                   and r.get("token") == token for r in self._read())

    def revoke(self, key: str, semantic_hash: str, reason: str) -> None:
        self._write({"op": "revoke", "key": key,
                     "semantic_hash": semantic_hash, "reason": reason,
                     "timestamp": time.time()})

    def revocation(self, key: str, semantic_hash: str):
        """Returns `(reason, revoked_at)` or None. The caller applies the TTL."""
        for record in self._read():
            if (record.get("op") == "revoke" and record.get("key") == key
                    and record.get("semantic_hash") == semantic_hash):
                return (str(record.get("reason") or "revoked"),
                        float(record.get("timestamp") or 0.0))
        return None

    def scope(self) -> str:
        return "host"

    def health(self) -> None:
        """Raise if the store cannot be written. The kernel fails closed on it."""
        with self.transaction(""):
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write("")
                handle.flush()


def _flock(handle, shared: bool = False) -> None:
    """Advisory lock where the platform has one; a no-op where it does not."""
    try:
        import fcntl
    except ImportError:                      # pragma: no cover - non-POSIX
        return
    fcntl.flock(handle.fileno(),
                fcntl.LOCK_SH if shared else fcntl.LOCK_EX)


def _funlock(handle) -> None:
    try:
        import fcntl
    except ImportError:                      # pragma: no cover - non-POSIX
        return
    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


# ─────────────────────────────────────────────────────────────
# The process-wide default
# ─────────────────────────────────────────────────────────────
# A deployment that configures nothing still gets continuity across the
# sessions, threads and workers inside its process. That is the safe default:
# the alternative is the finding this module exists to close.

_DEFAULT_STORE = InMemoryContinuityStore()


def default_store() -> InMemoryContinuityStore:
    return _DEFAULT_STORE


def reset_default_store() -> None:
    """Wipe the process-wide store. Used by test isolation and by operators."""
    _DEFAULT_STORE.reset()
