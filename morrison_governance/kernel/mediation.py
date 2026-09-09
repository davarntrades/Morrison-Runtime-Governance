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
  * It relies on a shared secret between the kernel and the enforcement point.
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

Deterministic: no clock beyond the deadline it is given, no RNG beyond the nonce
the kernel supplies, no I/O.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

LEASE_VERSION = "mrl1"


@dataclass(frozen=True)
class ExecutionLease:
    """A single-use, action-bound capability to perform ONE transition.

    Everything a resource-side enforcement point needs to decide without
    talking to Morrison: which action, on whose authority, in which session,
    until when, and once.
    """

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

    # ── wire format ──────────────────────────────────────────
    def _payload(self) -> str:
        return json.dumps({
            "v": LEASE_VERSION, "lease_id": self.lease_id,
            "action_hash": self.action_hash,
            "semantic_hash": self.semantic_hash,
            "principal": self.principal, "tenant": self.tenant,
            "session_id": self.session_id, "decision_id": self.decision_id,
            "tool_family": self.tool_family,
            "issued_at": round(self.issued_at, 3),
            "expires_at": round(self.expires_at, 3),
        }, sort_keys=True, separators=(",", ":"))

    def sign(self, key: bytes) -> "ExecutionLease":
        if not key:
            raise ValueError(
                "refusing to sign an execution lease with an empty key: an "
                "unsigned lease is a token anyone can mint, which is worse "
                "than no token at all because it looks like enforcement")
        from dataclasses import replace
        return replace(self, signature=hmac.new(
            key, self._payload().encode(), hashlib.sha256).hexdigest())

    def encode(self) -> str:
        """The header value an agent carries to the resource."""
        blob = json.dumps({"p": self._payload(), "s": self.signature},
                          separators=(",", ":"))
        return base64.urlsafe_b64encode(blob.encode()).decode().rstrip("=")

    @staticmethod
    def decode(token: str) -> "ExecutionLease":
        padded = token + "=" * (-len(token) % 4)
        outer = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        raw = json.loads(outer["p"])
        if raw.get("v") != LEASE_VERSION:
            raise ValueError(f"unsupported lease version {raw.get('v')!r}")
        return ExecutionLease(
            lease_id=raw["lease_id"], action_hash=raw["action_hash"],
            semantic_hash=raw["semantic_hash"], principal=raw["principal"],
            tenant=raw["tenant"], session_id=raw["session_id"],
            decision_id=raw["decision_id"], tool_family=raw["tool_family"],
            issued_at=raw["issued_at"], expires_at=raw["expires_at"],
            signature=outer["s"])


@dataclass
class LeaseVerifier:
    """The resource-side enforcement point.

    Deployed in the gateway, sidecar or tool server that fronts a resource —
    NOT in the agent, and not in the kernel. Its whole value is that it is a
    different process from the one being governed, so an agent that skips
    Morrison cannot also skip this.

    `seen` is the single-use store. In one process a set is enough; across a
    fleet it must be shared and atomic, exactly as `ContinuityStore.consume`
    must be, and for the same reason: a verifier that lets two callers redeem
    one lease has re-created the double-spend at the resource boundary.
    """

    key: bytes
    max_skew_s: float = 5.0
    seen: set = field(default_factory=set)
    _consume: Optional[Any] = None

    def verify(self, token: str, request: Optional[dict] = None,
               now: Optional[float] = None) -> tuple[bool, str]:
        """Decide whether this request may proceed. Returns `(ok, reason)`.

        Fails closed on every error, including a malformed token: a resource
        that cannot understand a lease has not been shown one.
        """
        now = time.time() if now is None else now
        if not self.key:
            return False, ("lease verification is DISABLED: no signing key is "
                           "configured. Failing closed — an unverified lease "
                           "is not a lease.")
        if not token:
            return False, ("no execution lease presented; this request did not "
                           "come through the governance kernel")
        try:
            lease = ExecutionLease.decode(token)
        except Exception as exc:                     # noqa: BLE001
            return False, f"malformed execution lease: {type(exc).__name__}"

        expected = hmac.new(self.key, lease._payload().encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, lease.signature or ""):
            return False, "execution lease signature invalid"
        # The skew allowance must never exceed the lease's own lifetime. A
        # deployment that mints one-second leases was getting a five-second
        # grace period it did not ask for, so the short TTL it chose bought it
        # nothing: an expired lease verified.
        skew = min(self.max_skew_s, max(0.0, lease.expires_at - lease.issued_at))
        if now > lease.expires_at + skew:
            return False, (f"execution lease expired "
                           f"{now - lease.expires_at:.3f}s ago")
        if lease.issued_at - self.max_skew_s > now:
            return False, "execution lease is issued in the future"

        # ATK-02 at the resource boundary: a verifier that checks the lease and
        # then forwards a DIFFERENT request has verified nothing. The lease
        # binds the canonical action hash, so the verifier re-derives it from
        # the request it is actually about to forward.
        if request is not None:
            from morrison_governance.kernel.canonical import action_hash
            if action_hash(request) != lease.action_hash:
                return False, ("the request does not match the action this "
                               "lease authorises")

        if self._consume is not None:
            if not self._consume(lease.lease_id):
                return False, "execution lease has already been redeemed"
        else:
            if lease.lease_id in self.seen:
                return False, "execution lease has already been redeemed"
            self.seen.add(lease.lease_id)
        return True, f"lease {lease.lease_id[:12]}… verified"


def mint_lease(decision: Any, key: bytes, ttl_s: float = 60.0,
               now: Optional[float] = None) -> ExecutionLease:
    """Mint the lease for a PERMIT decision.

    Refuses anything that is not a permitted, reserved decision: a lease is the
    portable form of an authorisation, so it must not be mintable from
    something that was not one.
    """
    if getattr(decision, "verdict", None) != "PERMIT":
        raise ValueError(
            f"only a PERMIT decision can mint an execution lease; this one is "
            f"{getattr(decision, 'verdict', None)!r}")
    if not getattr(decision, "reserved", False):
        raise ValueError(
            "this decision holds no trajectory reservation, so it was issued "
            "for analysis and cannot authorise a real request")
    stamp = time.time() if now is None else now
    return ExecutionLease(
        lease_id=hashlib.sha256(
            f"{decision.decision_id}:{decision.action_hash}".encode()
        ).hexdigest()[:32],
        action_hash=decision.action_hash,
        semantic_hash=decision.semantic_hash,
        principal=decision.principal_id,
        tenant=getattr(decision, "authorization", {}).get("tenant", ""),
        session_id=decision.session_id,
        decision_id=decision.decision_id,
        tool_family=getattr(decision, "tool_family", ""),
        issued_at=stamp,
        # Never outlive the decision it represents.
        expires_at=min(stamp + ttl_s, decision.issued_wall + ttl_s)
        if decision.issued_wall else stamp + ttl_s,
    ).sign(key)


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
