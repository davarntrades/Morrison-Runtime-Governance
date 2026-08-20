"""Schema helpers for explicitly configured regulatory applicability inputs.

The profile is intentionally small and conservative. Missing values remain
missing; sector, turnover, regulated status and legal classifications are
never inferred from model text or a scenario title.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation


APPLICABILITY_STATUSES = frozenset({
    "CONFIRMED_BY_CONFIGURATION", "POTENTIALLY_RELEVANT",
    "NOT_APPLICABLE", "INSUFFICIENT_INFORMATION",
})

EXPOSURE_TYPES = frozenset({
    "STATUTORY_PENALTY", "REGULATORY_ENFORCEMENT", "CONTRACTUAL",
    "CERTIFICATION", "OPERATIONAL_RESILIENCE", "DATA_PROTECTION",
    "FINANCIAL_CONTROL", "ASSURANCE_FRAMEWORK",
})

_LIST_FIELDS = (
    "jurisdictions", "data_categories", "regulated_entities",
    "frameworks_enabled", "contractual_frameworks",
)


def _strings(value) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return sorted({str(item).strip().lower() for item in value
                   if str(item).strip()})


def _turnover(value) -> dict | None:
    if not isinstance(value, dict):
        return None
    amount = value.get("amount")
    if isinstance(amount, bool) or not isinstance(amount, (int, float, Decimal)):
        return None
    try:
        parsed = Decimal(str(amount))
    except (InvalidOperation, ValueError):
        return None
    currency = str(value.get("currency", "")).strip().upper()
    year = value.get("year")
    if not parsed.is_finite() or parsed <= 0 or currency not in {"EUR", "GBP", "USD"}:
        return None
    return {
        "amount": int(parsed) if parsed == parsed.to_integral_value() else float(parsed),
        "currency": currency,
        "year": int(year) if isinstance(year, int) and 2000 <= year <= 2100 else None,
    }


def normalize_organization_profile(raw: dict | None) -> dict:
    """Return a bounded, serializable profile without making legal inferences."""
    source = raw if isinstance(raw, dict) else {}
    profile = {
        "profile_version": "1.0",
        "organization_id": str(source.get("organization_id", "")).strip()[:120] or None,
        "sector": str(source.get("sector", "")).strip().lower()[:80] or None,
        "annual_global_turnover": _turnover(source.get("annual_global_turnover")),
        "ai_system_classification": {},
        "entity_classifications": {},
    }
    for field in _LIST_FIELDS:
        profile[field] = _strings(source.get(field))
    for field in ("ai_system_classification", "entity_classifications"):
        value = source.get(field)
        if isinstance(value, dict):
            profile[field] = {
                str(key).strip().lower()[:80]: str(item).strip().lower()[:120]
                for key, item in value.items()
                if str(key).strip() and str(item).strip()
            }
    return profile


def organization_profile_hash(profile: dict) -> str:
    payload = json.dumps(profile, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False)
    return hashlib.sha256(payload.encode()).hexdigest()
