"""Map structured runtime metadata to cautious framework applicability."""

from __future__ import annotations


def trajectory_capabilities(steps: list[dict], profile: dict) -> dict[str, list[int]]:
    """Derive regulatory triggers from calls and Morrison metadata, never prose."""
    found: dict[str, list[int]] = {}
    data_categories = set(profile.get("data_categories", []))
    for row in steps:
        step = int(row.get("step", 0))
        call = row.get("normalized_call") or {}
        tool = str(call.get("tool", "")).lower()
        decision = row.get("morrison_decision") or {}
        metadata = decision.get("metadata") or {}
        caps = {str(item).lower() for item in metadata.get("capabilities", [])}
        triggers = set()
        # Preserve only known structured runtime capability labels.  This is
        # intentionally metadata-driven; prompt text and scenario names are
        # never used to manufacture legal relevance.
        triggers.update(caps & {
            "personal_data.read", "external_data_egress",
            "cross_tenant_access", "payment.move_funds",
            "credential_access", "privilege_escalation",
            "critical_service_disruption", "high_risk_ai_action",
            "payment_card_data", "health_data",
        })
        if tool in {"transfer", "transfer_funds"} or "payment.move_funds" in caps:
            triggers.add("payment.move_funds")
        if tool == "read_account":
            triggers.add("financial_data.read")
        if tool == "read_customer_record":
            triggers.add("personal_data.read")
        if tool in {"send_email", "http_request"} or "data.external_move" in caps:
            triggers.add("external_data_egress")
        if tool == "read_secret" or any("credential" in item or "secret" in item
                                         for item in caps):
            triggers.add("credential_access")
        if (str(decision.get("rule", "")).lower() == "cross_tenant" or
                str(decision.get("layer", "")).lower() == "tenancy"):
            triggers.add("cross_tenant_access")
        if "payment_card_data" in data_categories and (
                "payment.move_funds" in triggers or
                "financial_data.read" in triggers):
            triggers.add("payment_card_data")
        if "health_data" in data_categories and (
                "personal_data.read" in triggers or
                "external_data_egress" in triggers):
            triggers.add("health_data")
        for trigger in triggers:
            found.setdefault(trigger, []).append(step)
    return found


def applicability(framework_id: str, triggers: set[str], profile: dict) -> tuple[str, str]:
    """Return status and reason without asserting that a violation occurred."""
    enabled = set(profile.get("frameworks_enabled", []))
    jurisdictions = set(profile.get("jurisdictions", []))
    data = set(profile.get("data_categories", []))
    entities = set(profile.get("regulated_entities", []))
    contracts = set(profile.get("contractual_frameworks", []))
    classifications = profile.get("entity_classifications", {})
    ai = profile.get("ai_system_classification", {})

    if framework_id not in enabled:
        return "POTENTIALLY_RELEVANT", "Framework relevance detected; applicability is not enabled by organization configuration."
    if framework_id == "eu_ai_act":
        classification = ai.get("eu_ai_act", "unknown")
        if classification in {"", "unknown"}:
            return "INSUFFICIENT_INFORMATION", "AI-system classification is required; AI use alone does not establish applicability."
        if classification == "not_applicable":
            return "NOT_APPLICABLE", "Organization configuration marks this AI system out of scope."
        return "CONFIRMED_BY_CONFIGURATION", f"Organization configuration classifies the AI system as {classification}."
    if framework_id in {"eu_gdpr", "uk_gdpr"}:
        needed = "eu" if framework_id == "eu_gdpr" else "uk"
        if needed not in jurisdictions:
            return "INSUFFICIENT_INFORMATION", f"Configured {needed.upper()} jurisdiction is required."
        runtime_personal_data = {"personal_data.read", "cross_tenant_access"} & triggers
        if "personal_data" not in data and not runtime_personal_data:
            return "NOT_APPLICABLE", "No structured personal-data trigger is present."
        if "personal_data" not in data:
            return "POTENTIALLY_RELEVANT", (
                "Structured customer-data relevance is present, but explicit "
                "organization personal-data scope is required to confirm applicability.")
        return "CONFIRMED_BY_CONFIGURATION", (
            "Jurisdiction and personal-data scope are explicitly configured, "
            "and the structured runtime trajectory is relevant.")
    if framework_id == "nis2":
        classification = classifications.get("nis2", "unknown")
        if "eu" not in jurisdictions or classification in {"", "unknown"}:
            return "INSUFFICIENT_INFORMATION", "EU jurisdiction and essential/important entity classification are required."
        if classification == "not_applicable":
            return "NOT_APPLICABLE", "Organization configuration marks the entity out of NIS2 scope."
        return "CONFIRMED_BY_CONFIGURATION", f"Entity is configured as a NIS2 {classification} entity."
    if framework_id == "dora":
        if "eu" in jurisdictions and "financial_services" in entities:
            return "CONFIRMED_BY_CONFIGURATION", "EU jurisdiction and financial-services regulated-entity status are configured."
        return "INSUFFICIENT_INFORMATION", "EU financial-entity classification is required."
    if framework_id == "pci_dss":
        if "pci_dss" in contracts or "payment_card_data" in data:
            return "CONFIRMED_BY_CONFIGURATION", "PCI DSS contractual scope or payment-card data is explicitly configured."
        return "INSUFFICIENT_INFORMATION", "Cardholder-data or contractual PCI scope is required."
    if framework_id == "hipaa_hitech":
        classification = classifications.get("hipaa_hitech", "unknown")
        if classification == "not_applicable":
            return "NOT_APPLICABLE", "Organization configuration marks HIPAA/HITECH out of scope."
        if ("us" in jurisdictions and "health_data" in data and
                classification in {"covered_entity", "business_associate"}):
            return "CONFIRMED_BY_CONFIGURATION", "US jurisdiction, health data and HIPAA entity status are configured."
        return "INSUFFICIENT_INFORMATION", "US jurisdiction, health-data scope and covered-entity/business-associate status are required."
    if framework_id == "uk_financial_services":
        if "uk" in jurisdictions and "financial_services" in entities:
            return "CONFIRMED_BY_CONFIGURATION", "UK financial-services regulated-entity status is configured."
        return "INSUFFICIENT_INFORMATION", "UK jurisdiction and regulated financial-services entity status are required."
    return "INSUFFICIENT_INFORMATION", "No deterministic applicability rule is configured."
