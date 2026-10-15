"""Execution leases — turning part of complete mediation into enforcement.

THE ASSUMPTION THIS MODULE ATTACKS
----------------------------------
Every claim Morrison makes rests on T1: *every consequential executor is
reachable only through `GovernanceKernel.execute`.* Four rounds of adversarial
evaluation left T1 the largest residual, and it is the one thing the library has
never been able to check. Morrison governs what calls it. A second SDK, raw
HTTP, a credential the agent holds directly, a compromised connector — all
execute unseen, and no amount of hardening inside the kernel changes that.

The gap is structural: the kernel is a LIBRARY the caller invokes, so its
authority is exactly as complete as the caller's discipline. Asking nicely does
not scale, and neither does auditing every code path.

WHAT THIS MODULE CHANGES
------------------------
It moves the check from the CALLER to the RESOURCE. The kernel mints a short,
single-use, action-bound token when it permits an action; a resource-side
enforcement point — an API gateway, a database proxy, a sidecar, a tool server —
refuses any request that does not carry a valid one:

    agent ──proposal──▶ kernel ──lease──▶ agent ──request+lease──▶ gateway
                                                                     │
                                                          verify_lease(...)
                                                                     │
                                                              resource

Under that arrangement a bypass stops being invisible. An agent that skips the
kernel arrives at the resource with no lease and is refused THERE, by something
that is not the agent and does not depend on the agent's cooperation.

WHAT IT DOES NOT CHANGE
-----------------------
This does not prove complete mediation, and nothing in a Python library can.

  * It only covers resources that actually verify leases. An unenforced path is
    exactly as open as before.
  * It requires an external issuer, public resource keys and a shared atomic registry.
  * A resource with its own long-lived credential that the agent also holds is
    reachable without any request the gateway sees.
  * It is an authorisation check, not a transport: a gateway that verifies the
    lease and then forwards a DIFFERENT request has re-created ATK-02 at its own
    boundary, which is why the lease binds the canonical action hash and the
    verifier is given the request to re-derive it from.

So T1 does not become true. It becomes *checkable at each boundary a deployment
chooses to enforce*, and the set of unenforced boundaries becomes an explicit,
enumerable list rather than a blanket assumption. That is a smaller claim than
"complete mediation" and it is one a deployment can actually audit.

Exported authority uses external Ed25519 signing and a shared atomic registry.
The configured registry performs durable I/O.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import sqlite3
import time
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Optional, Protocol

from morrison_governance.kernel.ed25519 import verify as verify_ed25519

LEASE_VERSION = "mrl2"
_SIGNING_DOMAIN = b"MorrisonExecutionLease:mrl2\0"
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class LeaseStore(Protocol):
    """Shared registry: durable atomic issuance, consumption and cancellation.

    All replicas must use one backend. Issuers register; resources consume.
    SQLite below implements this on one local host, not across arbitrary hosts.
    """
    def register(self, lease_id: str, token_hash: str) -> bool: ...
    def consume(self, lease_id: str, token_hash: str) -> bool: ...
    def cancel(self, lease_id: str) -> bool: ...


class SQLiteLeaseStore:
    """At-most-once dispatch through a trusted shared local SQLite file.

    Resource effects are not a crash-atomic transaction with redemption.
    Missing configuration never creates an implicit process-local store.
    """
    def __init__(self, path: str | Path, timeout_s: float = 10.0):
        if not str(path) or str(path) == ":memory:":
            raise ValueError("a persistent shared lease-store path is required")
        self.path = str(Path(path).resolve())
        self.timeout_s = timeout_s
        with self._connect() as con:
            con.execute("CREATE TABLE IF NOT EXISTS execution_leases "
                        "(lease_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, "
                        "state TEXT NOT NULL CHECK(state IN ('issued','spent','cancelled')))")

    def _connect(self):
        return sqlite3.connect(self.path, timeout=self.timeout_s)

    def register(self, lease_id: str, token_hash: str) -> bool:
        with self._connect() as con:
            try:
                con.execute("INSERT INTO execution_leases VALUES (?, ?, 'issued')",
                            (lease_id, token_hash))
            except sqlite3.IntegrityError:
                return False
        return True

    def consume(self, lease_id: str, token_hash: str) -> bool:
        with self._connect() as con:
            changed = con.execute("UPDATE execution_leases SET state='spent' "
                                  "WHERE lease_id=? AND token_hash=? AND state='issued'",
                                  (lease_id, token_hash)).rowcount
        return changed == 1

    def cancel(self, lease_id: str) -> bool:
        with self._connect() as con:
            changed = con.execute("UPDATE execution_leases SET state='cancelled' "
                                  "WHERE lease_id=? AND state='issued'", (lease_id,)).rowcount
        return changed == 1


def lease_id_for(decision: Any) -> str:
    return hashlib.sha256(f"{decision.decision_id}:{decision.action_hash}".encode()).hexdigest()[:32]


def lease_token_hash(lease: "ExecutionLease") -> str:
    return hashlib.sha256(lease.encode().encode()).hexdigest()


@dataclass(frozen=True)
class ExecutionLease:
    """Ed25519-signed, action-bound portable authorization (mrl2)."""
    lease_id: str
    action_hash: str
    semantic_hash: str
    principal: str
    tenant: str
    session_id: str
    decision_id: str
    tool_family: str
    issued_at: float
    expires_at: float
    signature: str = ""

    def _payload(self) -> str:
        return json.dumps({
            "v": LEASE_VERSION, "lease_id": self.lease_id,
            "action_hash": self.action_hash, "semantic_hash": self.semantic_hash,
            "principal": self.principal, "tenant": self.tenant,
            "session_id": self.session_id, "decision_id": self.decision_id,
            "tool_family": self.tool_family,
            "issued_at": round(self.issued_at, 3), "expires_at": round(self.expires_at, 3),
        }, sort_keys=True, separators=(",", ":"), allow_nan=False)

    def signing_payload(self) -> bytes:
        return _SIGNING_DOMAIN + self._payload().encode()

    def sign(self, signer: Callable[[bytes], bytes]) -> "ExecutionLease":
        if not callable(signer):
            raise ValueError("an external Ed25519 signer is required; symmetric lease keys are unsupported")
        signature = signer(self.signing_payload())
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError("external Ed25519 signer must return a 64-byte signature")
        return replace(self, signature=signature.hex())

    def encode(self) -> str:
        blob = json.dumps({"p": self._payload(), "s": self.signature}, separators=(",", ":"))
        return base64.urlsafe_b64encode(blob.encode()).decode().rstrip("=")

    @staticmethod
    def decode(token: str) -> "ExecutionLease":
        if not isinstance(token, str) or len(token) > 16384:
            raise ValueError("invalid execution lease size/type")
        outer = json.loads(base64.b64decode(
            (token + "=" * (-len(token) % 4)).encode(), altchars=b"-_", validate=True))
        if not isinstance(outer, dict) or set(outer) != {"p", "s"}:
            raise ValueError("invalid execution lease envelope")
        raw = json.loads(outer["p"])
        fields = {"v", "lease_id", "action_hash", "semantic_hash", "principal", "tenant",
                  "session_id", "decision_id", "tool_family", "issued_at", "expires_at"}
        if not isinstance(raw, dict) or set(raw) != fields or raw["v"] != LEASE_VERSION:
            raise ValueError("unsupported or malformed execution lease schema")
        for field in fields - {"v", "issued_at", "expires_at"}:
            if not isinstance(raw[field], str) or not raw[field].strip():
                raise ValueError(f"missing or invalid lease {field}")
        for field in ("action_hash", "semantic_hash"):
            if not _HASH.fullmatch(raw[field]):
                raise ValueError(f"invalid lease {field}")
        for field in ("issued_at", "expires_at"):
            if type(raw[field]) not in (int, float) or not math.isfinite(raw[field]):
                raise ValueError(f"invalid lease {field}")
        if raw["expires_at"] <= raw["issued_at"]:
            raise ValueError("lease lifetime must be positive")
        if not isinstance(outer["s"], str) or len(outer["s"]) != 128:
            raise ValueError("invalid Ed25519 signature encoding")
        bytes.fromhex(outer["s"])
        return ExecutionLease(**{k: v for k, v in raw.items() if k != "v"}, signature=outer["s"])


@dataclass
class LeaseVerifier:
    """Public-key resource verifier with mandatory binding and shared registry.

    execute() hashes and forwards the same private snapshot. A lower-level
    verify() caller must enforce that correspondence. Legacy mrl1 is refused.
    """
    public_key: bytes
    store: Optional[LeaseStore] = None
    max_skew_s: float = 5.0

    def verify(self, token: str, request: Optional[dict] = None,
               now: Optional[float] = None) -> tuple[bool, str]:
        try:
            if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
                return False, "lease verification is DISABLED: no valid Ed25519 public key"
            if not token:
                return False, "no execution lease presented; this request did not come through the governance kernel"
            lease = ExecutionLease.decode(token)
            if not verify_ed25519(self.public_key, lease.signing_payload(), bytes.fromhex(lease.signature)):
                return False, "execution lease signature invalid"
            stamp = time.time() if now is None else now
            if type(stamp) not in (int, float) or not math.isfinite(stamp):
                return False, "invalid verification time"
            if type(self.max_skew_s) not in (int, float) or not math.isfinite(self.max_skew_s) or self.max_skew_s < 0:
                return False, "invalid clock skew configuration"
            skew = min(self.max_skew_s, lease.expires_at - lease.issued_at)
            if stamp > lease.expires_at + skew:
                return False, "execution lease expired"
            if lease.issued_at - self.max_skew_s > stamp:
                return False, "execution lease is issued in the future"
            if not isinstance(request, dict) or not isinstance(request.get("tool"), str) or not request["tool"].strip():
                return False, "the actual request is required for action binding"
            from morrison_governance.kernel.canonical import action_hash
            if action_hash(request) != lease.action_hash:
                return False, "the request does not match the action this lease authorises"
            if self.store is None:
                return False, "a shared atomic lease store is required"
            if self.store.consume(lease.lease_id, lease_token_hash(lease)) is not True:
                return False, "execution lease is unissued, cancelled, or has already been redeemed"
            return True, f"lease {lease.lease_id[:12]}… verified"
        except Exception as exc:  # noqa: BLE001 — all boundary errors refuse
            return False, f"malformed execution lease or unavailable dependency: {type(exc).__name__}"

    def execute(self, token: str, request: dict, executor: Callable[[dict], Any],
                now: Optional[float] = None) -> tuple[bool, Any]:
        try:
            snapshot = deepcopy(request)
        except Exception as exc:  # noqa: BLE001
            return False, f"invalid request snapshot: {type(exc).__name__}"
        ok, reason = self.verify(token, snapshot, now=now)
        if not ok:
            return False, reason
        try:
            return True, executor(snapshot)
        except Exception as exc:  # noqa: BLE001
            return False, f"executor failed after redemption; outcome unknown: {type(exc).__name__}"


def mint_lease(decision: Any, signer: Callable[[bytes], bytes], ttl_s: float = 60.0,
               now: Optional[float] = None) -> ExecutionLease:
    """Sign a reserved PERMIT snapshot; kernel registration is required separately."""
    if getattr(decision, "verdict", None) != "PERMIT":
        raise ValueError("only a PERMIT decision can mint an execution lease")
    if not getattr(decision, "reserved", False):
        raise ValueError("this decision holds no trajectory reservation")
    if type(ttl_s) not in (int, float) or not math.isfinite(ttl_s) or ttl_s <= 0:
        raise ValueError("lease TTL must be finite and positive")
    stamp = time.time() if now is None else now
    return ExecutionLease(
        lease_id=lease_id_for(decision), action_hash=decision.action_hash,
        semantic_hash=decision.semantic_hash, principal=decision.principal_id,
        tenant=getattr(decision, "authorization", {}).get("tenant", ""),
        session_id=decision.session_id, decision_id=decision.decision_id,
        tool_family=decision.action["tool"], issued_at=stamp, expires_at=stamp + ttl_s,
    ).sign(signer)


# ─────────────────────────────────────────────────────────────
# Mediation coverage
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MediationSurface:
    """One route by which this deployment can cause an effect."""

    name: str
    enforced: bool
    mechanism: str = ""
    note: str = ""


@dataclass
class MediationReport:
    """What a deployment can actually say about complete mediation.

    Deliberately blunt: it reports the ENUMERATED surfaces and says outright
    that it cannot enumerate them itself. The value is not the number, it is
    that the unenforced set becomes an explicit list somebody signed rather
    than a blanket assumption nobody wrote down.
    """

    surfaces: tuple = ()

    @property
    def enforced(self) -> tuple:
        return tuple(s for s in self.surfaces if s.enforced)

    @property
    def unenforced(self) -> tuple:
        return tuple(s for s in self.surfaces if not s.enforced)

    @property
    def complete(self) -> bool:
        """True only if every DECLARED surface is enforced.

        This is never evidence that the declaration is complete. Morrison
        cannot discover a route nobody told it about, and a deployment that
        forgets one gets a clean report and an open path.
        """
        return bool(self.surfaces) and not self.unenforced

    def as_dict(self) -> dict:
        return {
            "declared_surfaces": len(self.surfaces),
            "enforced": [s.name for s in self.enforced],
            "unenforced": [s.name for s in self.unenforced],
            "all_declared_surfaces_enforced": self.complete,
            "caveat": (
                "Enumeration is supplied by the deployment. Morrison cannot "
                "discover an execution route it was not told about, so this "
                "reports the completeness of the DECLARATION, never of the "
                "deployment."),
        }

    def summary(self) -> str:
        if not self.surfaces:
            return ("no execution surfaces declared; complete mediation is "
                    "entirely unevidenced")
        if self.complete:
            return (f"all {len(self.surfaces)} DECLARED execution surfaces "
                    f"enforce leases; undeclared routes remain unevidenced")
        names = ", ".join(s.name for s in self.unenforced)
        return (f"{len(self.unenforced)} of {len(self.surfaces)} declared "
                f"execution surfaces do not enforce leases: {names}")
