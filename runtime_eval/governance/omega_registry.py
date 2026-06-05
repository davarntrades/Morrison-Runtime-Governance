"""Domain-preset registry — compose a GovernanceLayer over a set of
domains by name. Wraps morrison_governance.OmegaDomain so the CLI /
Colab can pick domains with a string label."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from morrison_governance import GovernanceLayer, OmegaDomain


_DOMAIN_LABELS: dict[str, OmegaDomain] = {
    "finance":              OmegaDomain.FINANCE,
    "fintech":              OmegaDomain.FINTECH,
    "banking":              OmegaDomain.BANKING,
    "cybersecurity":        OmegaDomain.CYBERSECURITY,
    "healthcare":           OmegaDomain.HEALTHCARE,
    "data_privacy":         OmegaDomain.DATA_PRIVACY,
    "enterprise":           OmegaDomain.ENTERPRISE,
    "compliance":           OmegaDomain.COMPLIANCE,
    "fraud":                OmegaDomain.FRAUD,
    "mental_health_safety": OmegaDomain.MENTAL_HEALTH_SAFETY,
    # ── Omega-Sector expansion ──
    "insurance":            OmegaDomain.INSURANCE,
    "government":           OmegaDomain.GOVERNMENT,
    "supply_chain":         OmegaDomain.SUPPLY_CHAIN,
    "energy":               OmegaDomain.ENERGY,
    "telecommunications":   OmegaDomain.TELECOMMUNICATIONS,
    "manufacturing":        OmegaDomain.MANUFACTURING,
    "aerospace":            OmegaDomain.AEROSPACE,
    "defence":              OmegaDomain.DEFENCE,
}


@dataclass
class OmegaRegistry:
    """Build a GovernanceLayer with deterministic configuration."""

    domains: list = field(default_factory=lambda: ["finance", "cybersecurity"])
    horizon: int = 3
    forecast_horizon: int = 4
    enable_taint: bool = True
    enable_forecast: bool = True
    internal_email_domains: tuple = ()
    internal_url_hosts: tuple = ()
    log_all: bool = False

    def labels_to_domains(self) -> list[OmegaDomain]:
        out = []
        for lab in self.domains:
            if lab not in _DOMAIN_LABELS:
                raise KeyError(
                    f"unknown domain '{lab}'. Known: "
                    f"{sorted(_DOMAIN_LABELS)}")
            out.append(_DOMAIN_LABELS[lab])
        return out

    def build(self) -> GovernanceLayer:
        return GovernanceLayer(
            domains=self.labels_to_domains(),
            horizon=self.horizon,
            forecast_horizon=self.forecast_horizon,
            enable_taint=self.enable_taint,
            enable_forecast=self.enable_forecast,
            internal_email_domains=self.internal_email_domains,
            internal_url_hosts=self.internal_url_hosts,
            log_all=self.log_all,
        )

    @staticmethod
    def known() -> list[str]:
        return sorted(_DOMAIN_LABELS)
