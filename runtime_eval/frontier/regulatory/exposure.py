"""Read-only multi-regime exposure context over sealed runtime facts."""

from __future__ import annotations

from decimal import Decimal

from runtime_eval.frontier.regulatory.applicability import (
    applicability, trajectory_capabilities,
)
from runtime_eval.frontier.regulatory.registry import REGULATORY_PROFILES
from runtime_eval.frontier.regulatory.schema import (
    normalize_organization_profile, organization_profile_hash,
)


REGULATORY_DISCLAIMER = (
    "Statutory maximum context only; not a predicted fine or guaranteed saving. "
    "Requires factual and legal applicability determination."
)
CONTROL_FRAMEWORK_DISCLAIMER = (
    "Control / assurance context only; no statutory fine is calculated. "
    "This is not a predicted contractual loss or guaranteed saving."
)


def _calculation(framework_id: str, regulatory_profile: dict,
                 organization: dict, status: str) -> dict:
    def unavailable(reason: str) -> dict:
        return {"available": False, "reason": reason}
    if status != "CONFIRMED_BY_CONFIGURATION":
        return unavailable("Applicability is not confirmed by organization configuration.")
    tiers = regulatory_profile.get("penalty_tiers") or {}
    if not tiers:
        return unavailable("No deterministic statutory monetary formula is provided for this profile.")
    turnover = organization.get("annual_global_turnover")
    if not turnover:
        return unavailable("INSUFFICIENT INFORMATION TO CALCULATE TURNOVER-BASED EXPOSURE")
    currency = regulatory_profile.get("currency")
    if turnover.get("currency") != currency:
        return unavailable(f"Configured turnover must be in {currency}; no exchange-rate inference is performed.")

    entity = organization.get("entity_classifications", {})
    if framework_id in {"eu_gdpr", "uk_gdpr"}:
        tier = entity.get(f"{framework_id}_penalty_tier", "unknown")
    elif framework_id == "eu_ai_act":
        tier = organization.get("ai_system_classification", {}).get(
            "eu_ai_act_penalty_tier", "unknown")
        sme = entity.get("eu_ai_act_sme", "unknown")
        if sme == "unknown":
            return unavailable("SME classification is required because Article 99 applies lower rather than higher ceilings to SMEs.")
    elif framework_id == "nis2":
        tier = entity.get("nis2", "unknown")
    else:
        tier = "unknown"
    if tier not in tiers:
        return unavailable("An explicit supported penalty tier/classification is required; no infringement tier is inferred.")

    rule = tiers[tier]
    turnover_amount = Decimal(str(turnover["amount"]))
    percentage_amount = turnover_amount * Decimal(str(rule["turnover_percent"])) / 100
    fixed = Decimal(str(rule["fixed"]))
    if framework_id == "eu_ai_act" and entity.get("eu_ai_act_sme") == "true":
        maximum = min(fixed, percentage_amount)
        operator = "lower_of_fixed_or_turnover_for_sme"
    else:
        maximum = max(fixed, percentage_amount)
        operator = regulatory_profile["calculation_method"]
    amount = int(maximum) if maximum == maximum.to_integral_value() else float(maximum)
    return {
        "available": True,
        "basis": operator,
        "tier": tier,
        "organization_turnover": turnover,
        "fixed_ceiling": {"amount": rule["fixed"], "currency": currency},
        "turnover_percentage": rule["turnover_percent"],
        "turnover_based_amount": {
            "amount": int(percentage_amount) if percentage_amount == percentage_amount.to_integral_value() else float(percentage_amount),
            "currency": currency,
        },
        "maximum_context": {"amount": amount, "currency": currency},
        "aggregation": "shown_per_framework_not_summed",
        "note": ("NIS2 value is the Directive's required minimum national upper-limit context; national implementation may differ."
                 if framework_id == "nis2" else
                 "Statutory ceiling context, not an expected or imposed penalty."),
    }


def calculate_regulatory_exposure(steps: list[dict], mode: str,
                                  organization_profile: dict | None) -> dict:
    """Project legal/control context without touching governance or execution."""
    organization = normalize_organization_profile(organization_profile)
    capability_steps = trajectory_capabilities(steps, organization)
    observed = set(capability_steps)
    frameworks = []
    for framework_id, regulatory_profile in REGULATORY_PROFILES.items():
        profile_triggers = set(regulatory_profile["trigger_capabilities"])
        matched = observed & profile_triggers
        # Enabling a framework only supplies organization context.  It never
        # manufactures a trajectory trigger, including for the EU AI Act.
        if not matched:
            continue
        status, reason = applicability(framework_id, observed, organization)
        triggering_steps = sorted({step for cap in matched
                                   for step in capability_steps.get(cap, [])})
        calculation = _calculation(framework_id, regulatory_profile,
                                   organization, status)
        has_statutory_model = (
            "STATUTORY_PENALTY" in regulatory_profile["exposure_types"])
        frameworks.append({
            "framework_id": framework_id,
            "framework_name": regulatory_profile["framework_name"],
            "jurisdiction": regulatory_profile["jurisdiction"],
            "applicability": status,
            "applicability_reason": reason,
            "triggering_capabilities": sorted(matched),
            "triggering_steps": triggering_steps,
            "exposure_types": regulatory_profile["exposure_types"],
            "obligation_categories": regulatory_profile["obligations"],
            "calculation": calculation,
            "source": regulatory_profile["source"],
            "profile_version": regulatory_profile["profile_version"],
            "effective_from": regulatory_profile["effective_from"],
            "effective_to": regulatory_profile["effective_to"],
            "source_last_verified": regulatory_profile["source_last_verified"],
            "disclaimer": (REGULATORY_DISCLAIMER if has_statutory_model
                           else CONTROL_FRAMEWORK_DISCLAIMER),
        })

    available = [row for row in frameworks if row["calculation"]["available"]]
    mitigation_recorded = mode != "shadow" and any(
        (row.get("morrison_decision") or {}).get("verdict") in
        {"BLOCK", "ESCALATE"} and not row.get("execution_occurred")
        for row in steps)
    by_currency = {}
    for row in available:
        maximum = row["calculation"]["maximum_context"]
        currency = maximum["currency"]
        current = by_currency.get(currency)
        if not current or maximum["amount"] > current["amount"]:
            by_currency[currency] = {
                "amount": maximum["amount"], "currency": currency,
                "framework_id": row["framework_id"],
            }
    return {
        "measurement_type": "contextual",
        "mode": mode,
        "organization_profile": organization,
        "organization_profile_hash": organization_profile_hash(organization),
        "frameworks": frameworks,
        "distinct_obligation_areas": len({obligation for row in frameworks
                                          for obligation in row["obligation_categories"]}),
        "highest_statutory_context_by_currency": list(by_currency.values()),
        "statutory_maxima_aggregation": "NOT_SUMMED_ACROSS_FRAMEWORKS",
        "runtime_mitigation_recorded": mitigation_recorded,
        "runtime_mitigation_language": (
            "REGULATORY EXPOSURE OBSERVED — no enforcement occurred in Shadow Mode."
            if mode == "shadow" else
            ("RUNTIME MITIGATION RECORDED — potential regulatory exposure was not realized through prevented simulated execution paths."
             if mitigation_recorded else
             "REGULATORY CONTEXT SURFACED — no prevented protected execution was recorded in this session.")
        ),
        "disclaimer": REGULATORY_DISCLAIMER,
    }
