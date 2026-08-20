"""Illustrative enterprise-impact projection over governed session evidence.

This module is deliberately downstream of governance.  It receives recorded
steps, never invokes policy or execution, and cannot affect a Morrison verdict.
Direct exposure is extracted only from explicit monetary action arguments.
Everything under ``estimated_enterprise_impact`` is an illustrative demo
assumption rather than an observed saving.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Iterable, Optional


VALUE_IMPACT_DISCLAIMER = "Illustrative estimate — not guaranteed savings."

ILLUSTRATIVE_IMPACT_PROFILES = {
    "unauthorized_financial_transfer": {
        "label": "Unauthorized financial transaction",
        "multiplier_range": {"min": Decimal("2.5"), "max": Decimal("10")},
        "possible_costs": [
            "Unauthorized transfer value", "FCA / AML review",
            "Compliance audit", "Customer reimbursement", "Legal review",
            "Incident response", "Operational disruption",
            "Reputational impact",
        ],
    },
    "credential_compromise": {
        "label": "Credential / infrastructure compromise",
        "illustrative_range": {"min": 150000, "max": 1500000},
        "possible_costs": [
            "Credential / secret compromise", "Breach response",
            "Forensic investigation", "Privilege escalation remediation",
            "Operational downtime", "Customer trust impact",
        ],
    },
    "cross_tenant_access": {
        "label": "Cross-tenant data exposure",
        "illustrative_range": {"min": 100000, "max": 1000000},
        "possible_costs": [
            "Investigation", "Tenant remediation", "Legal response",
            "Regulatory review", "Customer notification",
            "Reputational impact",
        ],
    },
}

_MONETARY_TOOLS = frozenset({"transfer", "transfer_funds"})
_CREDENTIAL_TOOLS = frozenset({"read_secret"})


def _number(value) -> Optional[Decimal]:
    """Return a defensible positive numeric amount, never parse prose."""
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return None
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return amount if amount.is_finite() and amount > 0 else None


def _json_number(value: Optional[Decimal]):
    if value is None:
        return None
    return int(value) if value == value.to_integral_value() else float(value)


def _incident_classes(step: dict) -> set[str]:
    call = step.get("normalized_call") or {}
    tool = str(call.get("tool", "")).lower()
    decision = step.get("morrison_decision") or {}
    rule = str(decision.get("rule", "")).lower()
    layer = str(decision.get("layer", "")).lower()
    metadata = decision.get("metadata") or {}
    capabilities = {str(item).lower() for item in metadata.get("capabilities", [])}
    classes: set[str] = set()
    if tool in _MONETARY_TOOLS or "payment.move_funds" in capabilities:
        classes.add("unauthorized_financial_transfer")
    if tool in _CREDENTIAL_TOOLS or any(
            marker in capability for capability in capabilities
            for marker in ("secret", "credential", "privilege")):
        classes.add("credential_compromise")
    if rule == "cross_tenant" or layer == "tenancy":
        classes.add("cross_tenant_access")
    return classes


def _unsafe(step: dict) -> bool:
    verdict = str((step.get("morrison_decision") or {}).get("verdict", ""))
    return verdict in {"BLOCK", "ESCALATE"}


def _monetary_amount(step: dict) -> Optional[Decimal]:
    call = step.get("normalized_call") or {}
    if str(call.get("tool", "")).lower() not in _MONETARY_TOOLS:
        metadata = (step.get("morrison_decision") or {}).get("metadata") or {}
        if "payment.move_funds" not in metadata.get("capabilities", []):
            return None
    return _number((call.get("args") or {}).get("amount"))


def _impact_envelope(classes: Iterable[str], direct: Optional[Decimal]) -> dict | None:
    ranges = []
    profiles = []
    for profile_id in sorted(set(classes)):
        profile = ILLUSTRATIVE_IMPACT_PROFILES.get(profile_id)
        if not profile:
            continue
        profiles.append(profile_id)
        if profile_id == "unauthorized_financial_transfer" and direct is not None:
            multiplier = profile["multiplier_range"]
            ranges.append((direct * multiplier["min"],
                           direct * multiplier["max"]))
        elif profile.get("illustrative_range"):
            fixed = profile["illustrative_range"]
            ranges.append((Decimal(fixed["min"]), Decimal(fixed["max"])))
    if not ranges:
        return None
    # A non-additive envelope avoids implying that overlapping incident costs
    # can be summed.  It communicates the highest illustrative exposure band.
    return {
        "min": _json_number(max(item[0] for item in ranges)),
        "max": _json_number(max(item[1] for item in ranges)),
        "basis": "illustrative_impact_profile",
        "aggregation": "non_additive_risk_envelope",
        "profiles": profiles,
    }


def calculate_session_value_impact(steps: Iterable[dict], mode: str,
                                   unauthorized_executions: int = 0) -> dict:
    """Derive a read-only value explanation from authoritative session steps."""
    rows = list(steps)
    unsafe = [step for step in rows if _unsafe(step)]
    permitted = [step for step in rows
                 if (step.get("morrison_decision") or {}).get("verdict") == "PERMIT"]
    direct_amounts = [amount for step in unsafe
                      if (amount := _monetary_amount(step)) is not None]
    direct_identified = sum(direct_amounts, Decimal("0")) if direct_amounts else None
    enforced = mode != "shadow"
    prevented_steps = [
        step for step in unsafe
        if not step.get("execution_occurred") and (
            (step.get("morrison_decision") or {}).get("verdict") == "BLOCK"
            or (step.get("morrison_decision") or {}).get("verdict") == "ESCALATE"
            and bool(step.get("operator_decision"))
        )
    ]
    prevented_amounts = [amount for step in prevented_steps
                         if (amount := _monetary_amount(step)) is not None]
    direct_prevented = (
        sum(prevented_amounts, Decimal("0"))
        if enforced and prevented_amounts else None
    )
    incident_classes = set()
    impact_steps = unsafe if not enforced else prevented_steps
    for step in impact_steps:
        incident_classes.update(_incident_classes(step))
    # Enforcement-mode avoided-impact wording is supportable only for exposure
    # that did not execute. Shadow describes observed risk, so it uses the
    # identified amount instead.
    impact_basis = direct_identified if not enforced else direct_prevented
    envelope = _impact_envelope(incident_classes, impact_basis)
    possible_costs = []
    for profile_id in sorted(incident_classes):
        for label in ILLUSTRATIVE_IMPACT_PROFILES[profile_id]["possible_costs"]:
            if label not in possible_costs:
                possible_costs.append(label)
    intercepted = sum(
        not step.get("execution_occurred") for step in unsafe
    ) if enforced else 0
    legitimate_preserved = sum(
        bool(step.get("execution_occurred")) for step in permitted
    )
    first_intervention = min(
        (int(step.get("step", 0)) for step in unsafe), default=None)
    continued_after = bool(first_intervention is not None and any(
        int(step.get("step", 0)) > first_intervention for step in rows))

    return {
        "mode": mode,
        "measurement_type": "illustrative",
        "currency": "GBP",
        "measured_facts": {
            "total_proposed_actions": len(rows),
            "permitted_actions": len(permitted),
            "blocked_actions": sum(
                (step.get("morrison_decision") or {}).get("verdict") == "BLOCK"
                for step in rows),
            "escalated_actions": sum(
                (step.get("morrison_decision") or {}).get("verdict") == "ESCALATE"
                for step in rows),
            "unauthorized_executions": int(unauthorized_executions),
        },
        "direct_simulated_exposure_identified": _json_number(direct_identified),
        "direct_simulated_exposure_prevented": _json_number(direct_prevented),
        "estimated_enterprise_impact": envelope,
        "incident_classes": [
            {"id": profile_id,
             "label": ILLUSTRATIVE_IMPACT_PROFILES[profile_id]["label"]}
            for profile_id in sorted(incident_classes)
        ],
        "possible_costs": possible_costs,
        "workflow_continuity": {
            "preserved": bool(unsafe and legitimate_preserved),
            "permitted_actions": legitimate_preserved,
            "intercepted_actions": intercepted,
            "continued_after_intervention": continued_after,
        },
        "would_guarded_pilot_intervene": bool(unsafe) if mode == "shadow" else None,
        "disclaimer": VALUE_IMPACT_DISCLAIMER,
    }
