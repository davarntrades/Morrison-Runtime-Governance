"""Capability → authority policy.

Declares, per canonical capability, what authority an actor must hold before
the action may execute. Three requirement levels:

    DENY      never executable by an agent (no approval can unlock it)
    APPROVAL  executable only with a verified ApprovalArtifact bound to the
              exact canonical action hash  → otherwise ESCALATE
    GRANT     executable if the principal holds the capability grant
              → otherwise ESCALATE
    ALLOW     no additional authority required

Unknown / unmodelled tools follow SecurityContext.unknown_tool_policy and
default to ESCALATE — never silent PERMIT.

Thresholds and limits live HERE, on the server side, because the red team
defeated `excessive_amount` simply by supplying its own `threshold` in the
call arguments.
"""

from __future__ import annotations

from morrison_governance.kernel import capabilities as C

DENY = "deny"
APPROVAL = "approval"
GRANT = "grant"
ALLOW = "allow"

# Default enterprise posture. A deployment may override via
# SecurityContext.policy_values["capability_policy"].
CAPABILITY_POLICY: dict[str, str] = {
    # Destroying audit evidence is never delegable to an autonomous agent.
    C.CAP_LOG_TAMPER: DENY,

    C.CAP_DATA_DESTRUCTIVE: APPROVAL,
    C.CAP_INFRA_DESTRUCTIVE: APPROVAL,
    C.CAP_BACKUP_DESTRUCTIVE: APPROVAL,
    C.CAP_SECURITY_CONTROL: APPROVAL,
    C.CAP_CREDENTIAL_READ: APPROVAL,
    C.CAP_CREDENTIAL_CHANGE: APPROVAL,
    C.CAP_IAM_PRIVILEGED: APPROVAL,
    C.CAP_PAYMENT: APPROVAL,
    C.CAP_PERSISTENCE: APPROVAL,
    C.CAP_CODE_EXEC: APPROVAL,
    C.CAP_DELEGATION: APPROVAL,
    C.CAP_WILDCARD_SCOPE: APPROVAL,

    # Egress is conditional: governed only when the destination resolves
    # external (see kernel.gate). Reads are ordinary work.
    C.CAP_EXTERNAL_DATA_MOVE: ALLOW,
    C.CAP_DATA_READ: ALLOW,
}

# Server-owned comparison values. A caller cannot choose these.
DEFAULT_POLICY_VALUES = {
    # Payments at or below this value, to a non-external destination, do not
    # require a per-action approval. 0 disables auto-approval entirely.
    "payment_auto_approve_max": 0,
    # External egress requires approval once the trajectory has read data.
    "egress_requires_approval_after_read": True,
}

_ORDER = {ALLOW: 0, GRANT: 1, APPROVAL: 2, DENY: 3}


def requirement_for(caps: frozenset, policy: dict | None = None) -> tuple[str, str]:
    """Strictest requirement across the capability set → (level, capability)."""
    table = dict(CAPABILITY_POLICY)
    if policy:
        table.update(policy)
    best, who = ALLOW, ""
    for cap in sorted(caps):
        level = table.get(cap, ALLOW)
        if _ORDER[level] > _ORDER[best]:
            best, who = level, cap
    return best, who
