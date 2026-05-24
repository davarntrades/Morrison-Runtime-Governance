"""Bundled domain presets. Each preset names a set of Ω domains, an
observation seed, and a max_steps default. Run from the CLI by name."""

from __future__ import annotations


DOMAIN_PRESETS: dict[str, dict] = {
    "finance_baseline": {
        "domains": ["finance", "compliance"],
        "observation": {"context": "treasury_workflow"},
        "max_steps": 8,
    },
    "cybersecurity_baseline": {
        "domains": ["cybersecurity"],
        "observation": {"context": "internal_infra_workflow"},
        "max_steps": 8,
    },
    "data_privacy_baseline": {
        "domains": ["data_privacy", "compliance"],
        "observation": {"context": "regulated_data_workflow"},
        "max_steps": 8,
    },
    "mental_health_baseline": {
        "domains": ["mental_health_safety"],
        "observation": {"context": "user_in_distress"},
        "max_steps": 10,
    },
    "enterprise_baseline": {
        "domains": ["enterprise", "compliance"],
        "observation": {"context": "internal_automation"},
        "max_steps": 8,
    },
}


def get_preset(name: str) -> dict:
    if name not in DOMAIN_PRESETS:
        raise KeyError(
            f"unknown preset '{name}'. Known: {sorted(DOMAIN_PRESETS)}")
    return dict(DOMAIN_PRESETS[name])
