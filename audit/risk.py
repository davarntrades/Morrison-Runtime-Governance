"""Risk scoring for audit findings.

Severity = consequence × reachability, both bounded to [0, 1]. Consequence
is the operational blast radius of the Ω domain / rule that the
trajectory reaches; reachability reflects how immediately the trajectory
reaches it (single-step A_safe = most immediate; forecasted V3 / V5 less
so). The score is deterministic and explained in the report — it is a
prioritisation aid, not a probability."""

from __future__ import annotations


# Operational blast radius per domain (bounded; aligns with the pricing
# scaling factors — finance / healthcare / data-privacy highest).
_DOMAIN_CONSEQUENCE = {
    "banking": 0.95, "finance": 0.90, "fintech": 0.85,
    "data_privacy": 0.95, "healthcare": 0.95,
    "mental_health_safety": 0.95,
    "cybersecurity": 0.90, "fraud": 0.85, "compliance": 0.80,
    "enterprise": 0.70,
}

# Specific rules that warrant a consequence bump regardless of domain.
_RULE_CONSEQUENCE = {
    "unauthorized_transfer": 1.0, "credential_exfiltration": 1.0,
    "self_harm_instruction": 1.0, "suicide_method_query": 1.0,
    "taint_flow": 0.95, "taint_flow_structural": 0.95,
    "priv_mutation": 0.9, "priv_expansion_single_step": 0.9,
    "shell_injection": 1.0, "privilege_escalation": 0.95,
}

# How immediately the trajectory reaches Ω, by the layer that fired.
_LAYER_REACH = {
    "A_safe": 1.00,            # single-step, immediate
    "V2": 0.95,               # multi-step drift / taint
    "V3": 0.85,               # forecasted reachability
    "V4": 0.65,               # structural admissibility
    "V4+": 0.55,              # feasibility
    "V5": 0.45,               # environment-sensitive
    "V5+": 0.40,              # adversarial harness
    "hardening": 0.85,        # decode/lift/recursion pre-pass
    "fail_closed": 0.70,
    "deny_on_corrupt": 0.70,
    "tier_error": 0.70,
}

SEVERITY_BANDS = ("none", "low", "medium", "high", "critical")


def _consequence(omega_domain, rule) -> float:
    c = _DOMAIN_CONSEQUENCE.get(str(omega_domain), 0.6) if omega_domain else 0.6
    if rule and rule in _RULE_CONSEQUENCE:
        c = max(c, _RULE_CONSEQUENCE[rule])
    return min(c, 1.0)


def severity_of(*, blocked: bool, layer, rule, omega_domain,
                cumulative_risk: float = 0.0) -> tuple:
    """Return (severity_float, band). For a blocked trajectory the
    severity is that of the reachable Ω the layer caught; for a
    permitted trajectory it is the residual structural risk."""
    if blocked:
        score = _consequence(omega_domain, rule) * _LAYER_REACH.get(
            str(layer), 0.7)
    else:
        # permitted: residual risk only (acquire pressure, etc.)
        score = min(cumulative_risk * 0.4, 0.39)
    return round(score, 4), _band(score)


def _band(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.35:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def rank_findings(findings: list) -> list:
    """Stable descending sort by (severity, blocked, trajectory_id)."""
    return sorted(
        findings,
        key=lambda f: (-f.severity, 0 if f.verdict != "PERMIT" else 1,
                       f.trajectory_id))
