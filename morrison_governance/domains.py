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
    MENTAL_HEALTH_SAFETY = "mental_health_safety"
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


# ═══════════════════════════════════════════════════════════════
# MENTAL HEALTH SAFETY — runtime governance for mental-health-
# adjacent autonomous systems.
#
# IMPORTANT: this is a runtime *safety governance* component, not
# a clinical tool. Rules detect categorical risk markers a parent
# system attaches to a planned response (e.g. category, user_state,
# safety_disabled) and block trajectories that would worsen
# self-harm risk. They do NOT contain any operational self-harm
# content and do not require any. Safe supportive trajectories
# (validate distress, route to crisis support, ground the user)
# remain PERMITted.
# ═══════════════════════════════════════════════════════════════

_RESPONSE_TOOLS = (
    "respond", "chat_reply", "assistant_response", "generate_response",
    "send_message", "reply", "answer",
)
_CRISIS_USER_STATES = (
    "active_crisis", "suicidal_ideation", "self_harm_disclosure",
    "acute_distress", "imminent_risk",
)
_ROLEPLAY_TOOLS = ("roleplay", "persona", "character", "act_as", "simulate")
_BYPASS_PERSONAS = (
    "no_safety", "unfiltered", "jailbreak", "dan", "no_restrictions",
)
_CRISIS_TOPIC_CLASSES = ("self_harm", "suicide", "crisis", "mental_health")
_MEDICATION_ADVICE_TOOLS = (
    "prescribe", "prescribe_medication_advice", "medication_advice",
    "drug_advice", "dosage_advice", "overdose_calculator",
)
_HARM_PURPOSES = (
    "self_harm", "intentional_overdose", "overdose", "intentional_harm",
)
_THERAPEUTIC_ROLES = (
    "therapist", "counsellor", "counselor", "psychiatrist", "psychologist",
    "doctor", "clinician", "psychotherapist", "licensed_clinician",
)
_FALSE_REASSURANCE_TONES = (
    "reassure", "false_reassure", "minimise", "minimize", "dismiss",
)


def _mh_marker(state: dict, *names: str) -> Optional[str]:
    """Return the first matching abstract marker found in the state, or None.
    Looks at common arg keys (category / topic_class / intent / purpose)."""
    for k in ("category", "topic_class", "intent", "purpose", "risk_class"):
        v = str(state.get(k, "")).lower()
        if v in names:
            return v
    return None


def _default_mental_health_safety_rules() -> list[OmegaRule]:
    """Mental-health-adjacent runtime safety rules.

    Each rule matches a structural *category* of risk an upstream system
    attaches to a planned response. The rules are deny-by-default for
    operational self-harm assistance and permit safe supportive /
    crisis-routing trajectories. Attribution is per-category so the
    audit log shows exactly which Ω rule fired."""

    def _cat(name):
        return lambda s, n=name: _mh_marker(s, n) is not None

    return [
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="self_harm_instruction",
            description="Providing instructions or stepwise assistance for self-harm",
            check=_cat("self_harm_instruction"),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="suicide_method_query",
            description="Answering or assisting a query about suicide methods",
            check=_cat("suicide_method_query"),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="suicide_planning_assistance",
            description="Assisting in planning or operationalising suicide",
            check=_cat("suicide_planning_assistance"),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="concealment_advice",
            description="Advice on concealing self-harm from caregivers/clinicians",
            check=_cat("concealment_advice"),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="hopelessness_reinforcement",
            description="Reinforcing hopelessness / 'no way out' framing",
            check=_cat("hopelessness_reinforcement"),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="discourage_help_seeking",
            description="Discouraging the user from seeking professional or crisis support",
            check=_cat("discourage_help_seeking"),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="unsafe_pseudo_therapy_escalation",
            description="Unsafe pseudo-therapy intensifying negative affect or distress",
            check=lambda s: _mh_marker(
                s, "unsafe_pseudo_therapy",
                "unsafe_pseudo_therapy_escalation") is not None,
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="unsafe_medication_self_harm_advice",
            description="Medication / dosage advice tied to a self-harm purpose",
            check=lambda s: (
                str(s.get("tool", "")).lower() in _MEDICATION_ADVICE_TOOLS
                and (str(s.get("purpose", "")).lower() in _HARM_PURPOSES
                     or str(s.get("category", "")).lower() in _HARM_PURPOSES)
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="roleplay_safety_bypass",
            description="Roleplay / persona frame requesting safety bypass on a crisis topic",
            check=lambda s: (
                str(s.get("tool", "")).lower() in _ROLEPLAY_TOOLS
                and (str(s.get("persona", "")).lower() in _BYPASS_PERSONAS
                     or s.get("safety_disabled") is True)
                and str(s.get("topic_class", "")).lower() in _CRISIS_TOPIC_CLASSES
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="failure_to_route_crisis_disclosure",
            description=(
                "A response to a user in active crisis that does not route to "
                "crisis support / emergency services and carries no referral"
            ),
            check=lambda s: (
                str(s.get("tool", "")).lower() in _RESPONSE_TOOLS
                and str(s.get("user_state", "")).lower() in _CRISIS_USER_STATES
                and s.get("route_to_support") is not True
                and not s.get("crisis_referral")
                and not s.get("emergency_referral")
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="false_reassurance_under_crisis",
            description="Reassuring / minimising tone toward a user in active crisis without routing to support",
            check=lambda s: (
                str(s.get("tool", "")).lower() in _RESPONSE_TOOLS
                and str(s.get("user_state", "")).lower() in _CRISIS_USER_STATES
                and (str(s.get("tone", "")).lower() in _FALSE_REASSURANCE_TONES
                     or _mh_marker(s, "false_reassurance",
                                   "minimise_crisis", "minimize_crisis") is not None)
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="therapeutic_impersonation",
            description="Claiming a regulated therapeutic role without verification",
            check=lambda s: (
                str(s.get("claimed_role", "")).lower() in _THERAPEUTIC_ROLES
                and s.get("verified") is not True
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="authority_exploitation",
            description="Asserting authority on a crisis topic without verification",
            check=lambda s: (
                bool(s.get("claimed_authority"))
                and str(s.get("topic_class", "")).lower() in _CRISIS_TOPIC_CLASSES
                and s.get("verified") is not True
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="dependency_formation",
            description="Fostering exclusive reliance on the assistant; displacing external support",
            check=lambda s: _mh_marker(
                s, "dependency_formation", "foster_exclusive_reliance",
                "replace_external_support") is not None,
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="emotional_isolation",
            description="Encouraging severance from external relationships / support networks",
            check=lambda s: _mh_marker(
                s, "emotional_isolation", "sever_external_relationships",
                "discourage_external_contacts") is not None,
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="recursive_emotional_pressure",
            description="Repeated pressure pushing the user toward an unsafe choice",
            check=lambda s: _mh_marker(
                s, "recursive_emotional_pressure",
                "pressure_toward_unsafe") is not None,
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="emotional_contradiction_gaslighting",
            description="Gaslighting / denying user distress / emotional contradiction chains",
            check=lambda s: _mh_marker(
                s, "gaslighting", "emotional_contradiction",
                "deny_user_distress") is not None,
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="bait_and_switch",
            description="A response framed as safe but operationally unsafe",
            check=lambda s: _mh_marker(
                s, "bait_and_switch", "safe_then_unsafe") is not None,
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="latent_escalation",
            description="A response whose effect is latent escalation of self-harm risk",
            check=lambda s: _mh_marker(s, "latent_escalation") is not None,
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="contextual_drift_unsafe",
            description="Drift across turns that lands on an unsafe categorical marker",
            check=lambda s: _mh_marker(s, "contextual_drift_unsafe") is not None,
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="memory_contamination",
            description="Memory-injected content reframing safety into unsafe action",
            check=lambda s: _mh_marker(s, "memory_contamination") is not None,
        ),
        OmegaRule(
            domain=OmegaDomain.MENTAL_HEALTH_SAFETY,
            name="indirect_coercion",
            description="Indirect coercion toward unsafe action",
            check=lambda s: _mh_marker(s, "indirect_coercion") is not None,
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
    OmegaDomain.MENTAL_HEALTH_SAFETY: _default_mental_health_safety_rules,
}


def get_default_rules(domain: OmegaDomain) -> list[OmegaRule]:
    """Load default Ω rules for a domain."""
    factory = DEFAULT_RULES.get(domain)
    if factory is None:
        return []
    return factory()
