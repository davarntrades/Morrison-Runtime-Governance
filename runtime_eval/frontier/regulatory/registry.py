"""Versioned regulatory/control profiles backed by official sources.

Penalty values here are deterministic source data, never model-generated.
Profiles without a simple reliable monetary rule deliberately declare no
monetary calculation.
"""

from __future__ import annotations


REGULATORY_PROFILES = {
    "eu_gdpr": {
        "framework_name": "EU GDPR", "jurisdiction": "EU",
        "profile_version": "1.0", "effective_from": "2018-05-25",
        "effective_to": None, "source_last_verified": "2026-08-13",
        "source": {
            "authority": "European Union / EUR-Lex",
            "name": "Regulation (EU) 2016/679, Article 83",
            "reference": "Article 83(4)-(6)",
            "url": "https://eur-lex.europa.eu/eli/reg/2016/679/art_83/oj/eng",
        },
        "exposure_types": ["DATA_PROTECTION", "STATUTORY_PENALTY"],
        "trigger_capabilities": ["personal_data.read", "external_data_egress",
                                 "cross_tenant_access"],
        "obligations": ["Lawful and secure processing", "Access control",
                        "Personal-data breach governance"],
        "penalty_tiers": {
            "standard": {"fixed": 10000000, "turnover_percent": 2},
            "higher": {"fixed": 20000000, "turnover_percent": 4},
        },
        "currency": "EUR", "calculation_method": "higher_of_fixed_or_turnover",
    },
    "uk_gdpr": {
        "framework_name": "UK GDPR / Data Protection Act 2018",
        "jurisdiction": "UK", "profile_version": "1.0",
        "effective_from": "2021-01-01", "effective_to": None,
        "source_last_verified": "2026-08-13",
        "source": {
            "authority": "Information Commissioner's Office",
            "name": "The maximum amount of a fine under UK GDPR and DPA 2018",
            "reference": "UK GDPR Articles 83(4)-(6); DPA 2018",
            "url": "https://ico.org.uk/about-the-ico/our-information/policies-and-procedures/data-protection-fining-guidance/statutory-background/the-maximum-amount-of-a-fine-under-uk-gdpr-and-dpa-2018/",
        },
        "exposure_types": ["DATA_PROTECTION", "STATUTORY_PENALTY"],
        "trigger_capabilities": ["personal_data.read", "external_data_egress",
                                 "cross_tenant_access"],
        "obligations": ["Lawful and secure processing", "Access control",
                        "Personal-data breach governance"],
        "penalty_tiers": {
            "standard": {"fixed": 8700000, "turnover_percent": 2},
            "higher": {"fixed": 17500000, "turnover_percent": 4},
        },
        "currency": "GBP", "calculation_method": "higher_of_fixed_or_turnover",
    },
    "eu_ai_act": {
        "framework_name": "EU AI Act", "jurisdiction": "EU",
        "profile_version": "1.0", "effective_from": "2024-08-01",
        "effective_to": None, "source_last_verified": "2026-08-13",
        "source": {
            "authority": "European Union / EUR-Lex",
            "name": "Regulation (EU) 2024/1689, Article 99",
            "reference": "Article 99(3)-(7)",
            "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj?locale=en",
        },
        "exposure_types": ["REGULATORY_ENFORCEMENT", "STATUTORY_PENALTY"],
        "trigger_capabilities": ["high_risk_ai_action"],
        "obligations": ["Configured AI-system obligation context",
                        "Human oversight and runtime control evidence"],
        "penalty_tiers": {
            "prohibited_practice": {"fixed": 35000000, "turnover_percent": 7},
            "other_obligation": {"fixed": 15000000, "turnover_percent": 3},
            "incorrect_information": {"fixed": 7500000, "turnover_percent": 1},
        },
        "currency": "EUR", "calculation_method": "ai_act_article_99",
    },
    "nis2": {
        "framework_name": "NIS2 Directive", "jurisdiction": "EU",
        "profile_version": "1.0", "effective_from": "2023-01-16",
        "effective_to": None, "source_last_verified": "2026-08-13",
        "source": {
            "authority": "European Union / EUR-Lex",
            "name": "Directive (EU) 2022/2555, Article 34",
            "reference": "Article 34(4)-(5), as corrected",
            "url": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj?locale=en",
        },
        "exposure_types": ["OPERATIONAL_RESILIENCE", "REGULATORY_ENFORCEMENT",
                           "STATUTORY_PENALTY"],
        "trigger_capabilities": ["credential_access", "external_data_egress",
                                 "critical_service_disruption"],
        "obligations": ["Cybersecurity risk management", "Incident handling",
                        "Reporting and access-control evidence"],
        "penalty_tiers": {
            "essential": {"fixed": 10000000, "turnover_percent": 2},
            "important": {"fixed": 7000000, "turnover_percent": 1.4},
        },
        "currency": "EUR",
        "calculation_method": "directive_minimum_national_ceiling",
    },
    "dora": {
        "framework_name": "Digital Operational Resilience Act (DORA)",
        "jurisdiction": "EU", "profile_version": "1.0",
        "effective_from": "2025-01-17", "effective_to": None,
        "source_last_verified": "2026-08-13",
        "source": {
            "authority": "European Union / EUR-Lex",
            "name": "Regulation (EU) 2022/2554",
            "reference": "ICT risk management and incident governance",
            "url": "https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX:32022R2554",
        },
        "exposure_types": ["OPERATIONAL_RESILIENCE", "REGULATORY_ENFORCEMENT"],
        "trigger_capabilities": ["credential_access", "external_data_egress",
                                 "payment.move_funds", "critical_service_disruption"],
        "obligations": ["ICT risk management", "Incident reporting",
                        "Third-party ICT risk and operational resilience"],
        "penalty_tiers": {}, "currency": None, "calculation_method": None,
    },
    "pci_dss": {
        "framework_name": "PCI DSS", "jurisdiction": "CONTRACTUAL",
        "profile_version": "1.0", "effective_from": "2024-06-11",
        "effective_to": None, "source_last_verified": "2026-08-13",
        "source": {
            "authority": "PCI Security Standards Council",
            "name": "PCI DSS v4.0.1",
            "reference": "PCI DSS v4.0.1",
            "url": "https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1",
        },
        "exposure_types": ["CONTRACTUAL", "ASSURANCE_FRAMEWORK"],
        "trigger_capabilities": ["payment_card_data", "payment.move_funds",
                                 "external_data_egress"],
        "obligations": ["Cardholder-data access control", "Secure processing",
                        "Audit and monitoring evidence"],
        "penalty_tiers": {}, "currency": None, "calculation_method": None,
    },
    "hipaa_hitech": {
        "framework_name": "HIPAA / HITECH", "jurisdiction": "US",
        "profile_version": "1.0", "effective_from": "2013-03-26",
        "effective_to": None, "source_last_verified": "2026-08-13",
        "source": {
            "authority": "U.S. Department of Health and Human Services",
            "name": "HIPAA Enforcement Rule",
            "reference": "45 CFR Parts 160 and 164",
            "url": "https://www.hhs.gov/hipaa/for-professionals/special-topics/enforcement-rule/index.html",
        },
        "exposure_types": ["DATA_PROTECTION", "REGULATORY_ENFORCEMENT"],
        "trigger_capabilities": ["health_data", "external_data_egress",
                                 "cross_tenant_access"],
        "obligations": ["Protected health information safeguards",
                        "Breach and enforcement evidence"],
        "penalty_tiers": {}, "currency": None, "calculation_method": None,
    },
    "uk_financial_services": {
        "framework_name": "UK Financial Services Governance Context",
        "jurisdiction": "UK", "profile_version": "1.0",
        "effective_from": "2026-08-13", "effective_to": None,
        "source_last_verified": "2026-08-13",
        "source": {
            "authority": "Financial Conduct Authority",
            "name": "FCA Handbook — Senior Management Arrangements, Systems and Controls",
            "reference": "SYSC",
            "url": "https://www.handbook.fca.org.uk/handbook/SYSC/",
        },
        "exposure_types": ["FINANCIAL_CONTROL", "REGULATORY_ENFORCEMENT"],
        "trigger_capabilities": ["payment.move_funds", "financial_data.read",
                                 "credential_access"],
        "obligations": ["Systems and controls", "Authorization governance",
                        "Operational risk evidence"],
        "penalty_tiers": {}, "currency": None, "calculation_method": None,
    },
}


def public_profile_registry() -> list[dict]:
    """Return safe profile metadata for authenticated operator configuration."""
    return [{
        "framework_id": framework_id,
        "framework_name": profile["framework_name"],
        "jurisdiction": profile["jurisdiction"],
        "profile_version": profile["profile_version"],
        "source": profile["source"],
        "source_last_verified": profile["source_last_verified"],
    } for framework_id, profile in REGULATORY_PROFILES.items()]
