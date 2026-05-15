"""
Ω domain definitions.

Ω = ∪ Ωₐ — the forbidden state region is domain-decomposed.
Each domain defines what must not occur.
The framework guarantees it cannot occur.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class OmegaDomain(Enum):
    """
    Pre-defined Ω domains. Each represents a class of forbidden states.
    """

    FINANCE = "finance"
    FINTECH = "fintech"
    CYBERSECURITY = "cybersecurity"
    HEALTHCARE = "healthcare"
    DATA_PRIVACY = "data_privacy"
    ENTERPRISE = "enterprise"
    BANKING = "banking"
    COMPLIANCE = "compliance"
    FRAUD = "fraud"
    CUSTOM = "custom"


@dataclass
class OmegaRule:
    """
    A single rule within an Ω domain.

    Attributes:
        domain: which Ω domain this rule belongs to
        name: human-readable rule identifier
        description: what this rule prevents
        check: callable that takes a trajectory state dict and returns
               True if the state violates Ω (i.e. is forbidden)
        severity: classification of violation severity
    """

    domain: OmegaDomain
    name: str
    description: str
    check: Callable[[dict], bool]
    severity: str = "critical"

    def evaluate(self, state: dict) -> bool:
        """Returns True if the state violates this rule (enters Ω)."""
        return self.check(state)


# ═══════════════════════════════════════════════════════════════
# DEFAULT Ω RULE SETS
# ═══════════════════════════════════════════════════════════════
# These are starter rules. Enterprise deployments define their
# own Ω based on regulatory and operational requirements.
# ═══════════════════════════════════════════════════════════════


def _default_finance_rules() -> list[OmegaRule]:
    """Finance domain: unauthorized transactions, guaranteed returns, fabricated filings."""
    return [
        OmegaRule(
            domain=OmegaDomain.FINANCE,
            name="unauthorized_transfer",
            description="Transfer execution without explicit authorisation",
            check=lambda s: (
                s.get("tool") in ("transfer", "send_payment", "execute_trade")
                and not s.get("authorized", False)
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.FINANCE,
            name="guaranteed_profit",
            description="Claims of guaranteed profit or fabricated audited filings",
            check=lambda s: any(
                kw in str(s.get("content", "")).lower()
                for kw in ("guaranteed return", "guaranteed profit", "risk-free")
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.FINANCE,
            name="excessive_amount",
            description="Transaction exceeding governance threshold without approval",
            check=lambda s: (
                s.get("amount", 0) > s.get("threshold", float("inf"))
                and not s.get("approved", False)
            ),
        ),
    ]


def _default_cybersecurity_rules() -> list[OmegaRule]:
    """Cybersecurity domain: credential exfiltration, shell injection, privilege escalation."""
    return [
        OmegaRule(
            domain=OmegaDomain.CYBERSECURITY,
            name="credential_exfiltration",
            description="Attempt to read, copy, or transmit credentials",
            check=lambda s: (
                any(
                    kw in str(s.get("args", "")).lower()
                    for kw in (
                        "password", "secret", "api_key", "token",
                        "/etc/shadow", ".env", "credentials",
                    )
                )
                and s.get("tool") in ("read_file", "exec", "http_request", "shell")
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.CYBERSECURITY,
            name="shell_injection",
            description="Arbitrary shell command execution",
            check=lambda s: (
                s.get("tool") in ("shell", "exec", "subprocess")
                and any(
                    op in str(s.get("args", ""))
                    for op in (";", "&&", "|", "`", "$(", "rm -rf", "curl", "wget")
                )
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.CYBERSECURITY,
            name="privilege_escalation",
            description="Attempt to escalate privileges",
            check=lambda s: any(
                kw in str(s.get("args", "")).lower()
                for kw in ("sudo", "chmod 777", "chown root", "setuid")
            ),
        ),
    ]


def _default_healthcare_rules() -> list[OmegaRule]:
    """Healthcare domain: diagnosis guarantees, fabricated evidence, PHI exposure."""
    return [
        OmegaRule(
            domain=OmegaDomain.HEALTHCARE,
            name="guaranteed_diagnosis",
            description="Guaranteed diagnosis or fabricated clinical evidence",
            check=lambda s: any(
                kw in str(s.get("content", "")).lower()
                for kw in (
                    "definitive diagnosis", "guaranteed cure",
                    "clinical trial shows 100%", "fabricated",
                )
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.HEALTHCARE,
            name="phi_exposure",
            description="Patient health information transmitted to unauthorized endpoint",
            check=lambda s: (
                s.get("contains_phi", False)
                and s.get("tool") in ("http_request", "send_email", "api_call")
                and not s.get("hipaa_authorized", False)
            ),
        ),
    ]


def _default_data_privacy_rules() -> list[OmegaRule]:
    """Data privacy domain: PII exfiltration, unauthorized data sharing."""
    return [
        OmegaRule(
            domain=OmegaDomain.DATA_PRIVACY,
            name="pii_exfiltration",
            description="Personal identifiable information sent to external endpoint",
            check=lambda s: (
                s.get("contains_pii", False)
                and s.get("destination_external", False)
                and not s.get("consent_verified", False)
            ),
        ),
    ]


def _default_enterprise_rules() -> list[OmegaRule]:
    """Enterprise domain: customer data leakage, classified artifact exposure, role escalation."""
    return [
        OmegaRule(
            domain=OmegaDomain.ENTERPRISE,
            name="customer_pii_external",
            description="Customer PII transmitted externally without sanitization",
            check=lambda s: (
                s.get("contains_customer_data", False)
                and s.get("destination_external", False)
                and not s.get("sanitized", False)
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.ENTERPRISE,
            name="internal_artifact_leak",
            description="Internal/restricted/confidential artifact sent externally",
            check=lambda s: (
                str(s.get("data_classification", "")).lower()
                in ("internal", "restricted", "confidential")
                and s.get("destination_external", False)
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.ENTERPRISE,
            name="unauthorized_role_change",
            description="Role/permission change without admin authorization",
            check=lambda s: (
                s.get("tool") in ("update_role", "grant_permission", "modify_acl")
                and not s.get("admin_approved", False)
            ),
        ),
    ]


def _default_compliance_rules() -> list[OmegaRule]:
    """Compliance domain: PCI card data exposure, GDPR purpose limitation, encryption gaps."""
    return [
        OmegaRule(
            domain=OmegaDomain.COMPLIANCE,
            name="pci_card_exposure",
            description="Card data (PAN/CVV) sent to non-PCI endpoint",
            check=lambda s: (
                any(
                    kw in str(s.get("args", "")).lower()
                    for kw in ("card_number", "pan", "cvv", "cvc", "track_data")
                )
                and not s.get("pci_compliant_endpoint", False)
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.COMPLIANCE,
            name="gdpr_purpose_mismatch",
            description="EU personal data accessed for non-consented purpose",
            check=lambda s: (
                s.get("contains_pii", False)
                and s.get("data_subject_eu", False)
                and str(s.get("purpose", "")) != ""
                and s.get("purpose") not in [
                    p.strip() for p in str(s.get("consented_purposes", "")).split(",")
                ]
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.COMPLIANCE,
            name="encryption_missing",
            description="Sensitive data transmitted with TLS disabled",
            check=lambda s: (
                s.get("contains_sensitive", False)
                and s.get("tool") in ("http_request", "api_call", "send_email")
                and s.get("tls", True) is False
            ),
        ),
    ]


def _default_fraud_rules() -> list[OmegaRule]:
    """Fraud domain: structuring, velocity anomalies, synthetic identity."""
    return [
        OmegaRule(
            domain=OmegaDomain.FRAUD,
            name="structuring_pattern",
            description="Amount just below reporting threshold (structuring)",
            check=lambda s: (
                s.get("tool") in ("transfer", "send_payment", "withdraw")
                and 9000 <= s.get("amount", 0) <= 9999
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.FRAUD,
            name="velocity_anomaly",
            description="Transaction velocity exceeds short-window threshold",
            check=lambda s: (
                s.get("tool") in ("transfer", "send_payment", "withdraw")
                and s.get("transactions_last_hour", 0) > 10
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.FRAUD,
            name="synthetic_identity",
            description="Identity score below confidence floor on account creation",
            check=lambda s: (
                s.get("tool") in ("create_account", "open_account", "kyc")
                and s.get("identity_score", 1.0) < 0.5
            ),
        ),
    ]


# Registry of default rules by domain
DEFAULT_RULES: dict[OmegaDomain, Callable[[], list[OmegaRule]]] = {
    OmegaDomain.FINANCE: _default_finance_rules,
    OmegaDomain.FINTECH: _default_finance_rules,
    OmegaDomain.BANKING: _default_finance_rules,
    OmegaDomain.CYBERSECURITY: _default_cybersecurity_rules,
    OmegaDomain.HEALTHCARE: _default_healthcare_rules,
    OmegaDomain.DATA_PRIVACY: _default_data_privacy_rules,
    OmegaDomain.ENTERPRISE: _default_enterprise_rules,
    OmegaDomain.COMPLIANCE: _default_compliance_rules,
    OmegaDomain.FRAUD: _default_fraud_rules,
}


def get_default_rules(domain: OmegaDomain) -> list[OmegaRule]:
    """Load default Ω rules for a domain."""
    factory = DEFAULT_RULES.get(domain)
    if factory is None:
        return []
    return factory()
