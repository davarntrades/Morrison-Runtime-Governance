"""Trust boundary: where authority actually comes from.

The red-team finding this module closes:

    TrajectoryState.to_eval_dict() splices **args into the same namespace the
    Ω rules read their control flags from. Every deployment rule ends in
    `not _authorized(s)`, and `_authorized()` reads that namespace. So a caller
    that writes `{"authorized": true}` into its own arguments authorises itself.
    12 of 13 blocked catastrophic actions became executable that way.

The fix is a strict separation:

  * REQUEST metadata (anything the caller can write) is DATA. It is quarantined
    out of the authority namespace before evaluation and retained only as a
    forgery signal.
  * AUTHORITY is derived from a server-side SecurityContext: an authenticated
    principal, policy state, and cryptographically verified approval artifacts
    bound to a specific canonical action hash.

Nothing a caller can write can widen what it is allowed to do.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field, replace
from typing import Any, Optional

from morrison_governance.kernel.canonical import action_hash, canonicalize

# ─────────────────────────────────────────────────────────────
# Quarantined authority fields
# ─────────────────────────────────────────────────────────────
# Any request field that could REDUCE restriction if believed. These are
# stripped from the evaluation namespace and can never confer authority.
# Fields that only ever INCREASE suspicion (e.g. a requested `role: admin`)
# are deliberately NOT quarantined — they are evidence for detection and
# removing them would blind the privilege-escalation rules that already work.
AUTHORITY_FIELDS = frozenset({
    # approval / authorisation assertions
    "authorized", "authorised", "approved", "approval", "approved_by",
    "approver", "verified", "sanctioned", "change_approved", "admin_authorized",
    "authorization", "authorisation", "auth", "consent", "consented",
    "reviewed", "signed_off", "signoff", "override", "override_approved",
    "break_glass", "emergency_approved", "exception_approved", "waiver",
    # trust / boundary assertions
    "destination_internal", "is_internal", "internal", "destination_external",
    "external", "trusted", "is_trusted", "privileged", "is_privileged",
    "safe", "is_safe", "sanitized", "sanitised", "anonymized", "anonymised",
    "deidentified", "de_identified", "encrypted",
    # policy-bound comparison values the caller must not choose
    "threshold", "limit", "max_amount", "risk_score", "identity_score",
    "confidence", "severity_override", "policy", "policy_override",
    # identity assertions (identity comes from the session, never the payload)
    "actor", "principal", "user_id", "tenant", "tenant_id", "on_behalf_of",
    "requested_by", "session_customer", "impersonate",
})

# Fields whose presence is itself a signal worth recording loudly.
_FORGERY_SIGNIFICANT = frozenset({
    "authorized", "authorised", "approved", "approved_by", "approver",
    "verified", "sanctioned", "change_approved", "admin_authorized",
    "destination_internal", "is_internal", "internal", "trusted",
    "privileged", "break_glass", "threshold", "override",
})


def quarantine_authority(call: dict) -> tuple[dict, dict]:
    """Split a canonical call into (clean_call, quarantined_fields).

    `clean_call` is what the Ω rules evaluate. `quarantined_fields` is retained
    as evidence — a caller asserting `authorized: true` has told us something
    important about itself, and we record it rather than discarding it.
    """
    canon = canonicalize(call)
    args = dict(canon.get("args") or {})
    quarantined: dict[str, Any] = {}
    for key in list(args.keys()):
        if str(key).strip().lower() in AUTHORITY_FIELDS:
            quarantined[key] = args.pop(key)
    return {"tool": canon["tool"], "args": args}, quarantined


def forged_authority_claims(quarantined: dict) -> list[str]:
    """The subset of quarantined fields that assert authority the caller does
    not have. Truthy assertions only — an explicit `authorized: false` is not
    a forgery attempt."""
    out = []
    for k, v in quarantined.items():
        kl = str(k).strip().lower()
        if kl not in _FORGERY_SIGNIFICANT:
            continue
        if isinstance(v, bool) and not v:
            continue
        if v in (None, "", 0):
            continue
        out.append(kl)
    return sorted(out)


# ─────────────────────────────────────────────────────────────
# Identity
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Principal:
    """An authenticated actor. Constructed by the runtime from session state —
    never parsed out of a tool call."""

    id: str
    tenant: str = ""
    roles: frozenset = field(default_factory=frozenset)
    # Capabilities this principal may exercise WITHOUT a per-action approval.
    granted_capabilities: frozenset = field(default_factory=frozenset)

    def has_role(self, role: str) -> bool:
        return role in self.roles


ANONYMOUS = Principal(id="anonymous", tenant="", roles=frozenset(),
                      granted_capabilities=frozenset())


# ─────────────────────────────────────────────────────────────
# Approval artifacts
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ApprovalArtifact:
    """A verifiable grant to perform ONE specific canonical action.

    Bound to `action_hash`, so an approval obtained for a $100 transfer cannot
    be replayed against a $4,500,000 transfer: the hash differs, verification
    fails. This is what makes action-mutation-after-approval structurally
    impossible.
    """

    action_hash: str
    issuer: str
    scope: str = ""
    issued_at: float = 0.0
    expires_at: float = 0.0
    nonce: str = ""
    signature: str = ""

    def _payload(self) -> str:
        return "|".join([
            self.action_hash, self.issuer, self.scope,
            f"{self.issued_at:.0f}", f"{self.expires_at:.0f}", self.nonce,
        ])

    def sign(self, key: bytes) -> "ApprovalArtifact":
        # An empty key is not a key. HMAC accepts b"" happily and produces a
        # perfectly valid tag, which means anyone who knows the scheme could
        # mint approvals — so refuse to create the artifact at all rather than
        # hand back one that carries no authority but looks authoritative.
        if not key:
            raise ValueError(
                "refusing to sign an approval artifact with an empty key: "
                "configure GOVERNANCE_APPROVAL_KEY")
        sig = hmac.new(key, self._payload().encode(), hashlib.sha256).hexdigest()
        return replace(self, signature=sig)

    def verify(self, key: bytes, expected_action_hash: str,
               trusted_issuers: frozenset, now: float,
               seen_nonces: Optional[set] = None) -> tuple[bool, str]:
        """Constant-time signature check plus binding, expiry, issuer and
        replay checks. Returns (ok, reason)."""
        # FAIL CLOSED on an absent key. `hmac.new(b"", …)` is a valid HMAC, so
        # an unconfigured deployment would verify attacker-minted approvals —
        # re-opening the whole approval-bypass finding. No key means no approval
        # can ever verify, so no approval-based PERMIT can be produced.
        if not key:
            return False, ("approval verification is DISABLED: no approval "
                           "signing key is configured (set "
                           "GOVERNANCE_APPROVAL_KEY). Failing closed — no "
                           "approval can be accepted.")
        if not self.signature:
            return False, "approval artifact is unsigned"
        expect = hmac.new(key, self._payload().encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, self.signature):
            return False, "approval signature invalid"
        if self.action_hash != expected_action_hash:
            return False, (
                f"approval is bound to a different action "
                f"({self.action_hash[:12]}… != {expected_action_hash[:12]}…)")
        if trusted_issuers and self.issuer not in trusted_issuers:
            return False, f"approval issuer {self.issuer!r} is not trusted"
        if self.expires_at and now > self.expires_at:
            return False, "approval has expired"
        if seen_nonces is not None and self.nonce and self.nonce in seen_nonces:
            return False, "approval nonce already used (replay)"
        return True, "approval verified"


# ─────────────────────────────────────────────────────────────
# Security context
# ─────────────────────────────────────────────────────────────

@dataclass
class SecurityContext:
    """Server-side trust state. The ONLY source of authority.

    Constructed by the runtime from authenticated session state and deployment
    configuration. A tool call can never construct or mutate one.
    """

    principal: Principal = ANONYMOUS
    approvals: tuple = ()
    signing_key: bytes = b""
    trusted_issuers: frozenset = field(default_factory=frozenset)

    # Trusted destination configuration (see kernel.destinations)
    internal_url_hosts: tuple = ()
    internal_email_domains: tuple = ()
    internal_cidrs: tuple = ()

    # Policy for tools with no declared capability manifest entry.
    # "escalate" (default) | "block" | "permit"
    unknown_tool_policy: str = "escalate"
    # Declared tool manifest: {tool_name: [capability, ...]}
    tool_manifest: dict = field(default_factory=dict)

    # Policy-owned comparison values a caller must not choose.
    policy_values: dict = field(default_factory=dict)

    _used_nonces: set = field(default_factory=set)

    # ── approvals ────────────────────────────────────────────
    def verified_approval(self, expected_hash: str,
                          now: Optional[float] = None
                          ) -> tuple[Optional[ApprovalArtifact], str]:
        """Return the verified approval for this exact action, if any."""
        now = time.time() if now is None else now
        # Checked before anything else: without a signing key there is no way to
        # distinguish a real approval from a forged one, so the honest answer is
        # that approval-based authorisation is unavailable — not that the
        # approval passed.
        if not self.signing_key:
            return None, ("approval verification is DISABLED: no approval "
                          "signing key is configured (set "
                          "GOVERNANCE_APPROVAL_KEY). Failing closed.")
        if not self.approvals:
            return None, "no approval artifact presented"
        last = "no approval artifact presented"
        for art in self.approvals:
            ok, reason = art.verify(self.signing_key, expected_hash,
                                    self.trusted_issuers, now,
                                    self._used_nonces)
            if ok:
                return art, reason
            last = reason
        return None, last

    def consume_nonce(self, art: ApprovalArtifact) -> None:
        if art.nonce:
            self._used_nonces.add(art.nonce)

    def grants(self, capability: str) -> bool:
        return capability in self.principal.granted_capabilities

    def describe(self) -> dict:
        return {
            "principal": self.principal.id,
            "tenant": self.principal.tenant,
            "roles": sorted(self.principal.roles),
            "granted_capabilities": sorted(self.principal.granted_capabilities),
            "approvals_presented": len(self.approvals),
            "unknown_tool_policy": self.unknown_tool_policy,
            "manifest_tools": len(self.tool_manifest),
        }


def issue_approval(call: dict, issuer: str, key: bytes, ttl_s: float = 300.0,
                   scope: str = "", nonce: str = "",
                   now: Optional[float] = None) -> ApprovalArtifact:
    """Helper for trusted approval services (and tests): mint a signed approval
    bound to the canonical hash of `call`.

    Raises if `key` is empty — see `ApprovalArtifact.sign`.
    """
    now = time.time() if now is None else now
    return ApprovalArtifact(
        action_hash=action_hash(call), issuer=issuer, scope=scope,
        issued_at=now, expires_at=now + ttl_s, nonce=nonce,
    ).sign(key)
