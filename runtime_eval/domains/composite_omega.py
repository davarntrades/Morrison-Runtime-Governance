"""Composite Ω domains.

Compose multiple OmegaDomain sets and add cross-domain rules that fire
when a trajectory touches more than one domain's risk geometry — e.g.,
financial-execution AND egress in the same trajectory is a stronger
signal than either alone. This is structural composition, not
content-based intersection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.domains import OmegaRule


def _has_capability(state: dict, cap: str) -> bool:
    """Capability tags exposed by semantic_lifting + structural inference."""
    caps = state.get("_lifted_capabilities") or []
    if cap in caps:
        return True
    try:
        from morrison_governance.forecasting import infer_capabilities
        if cap in infer_capabilities({"tool": state.get("tool"),
                                       "args": state.get("args", {})}):
            return True
    except Exception:                                  # noqa: BLE001
        pass
    return False


# ─────────────────────────────────────────────────────────────
# Cross-domain composite Ω rules
# ─────────────────────────────────────────────────────────────

def _cross_rules() -> list[OmegaRule]:
    return [
        OmegaRule(
            domain=OmegaDomain.COMPLIANCE,
            name="financial_execution_with_egress",
            description=("A financial-execution step (transfer / payment) "
                          "carrying an explicit external URL / endpoint / "
                          "host in the same call — composite Ω across "
                          "finance + cybersecurity. The recipient `to` "
                          "field alone does NOT count; only an explicit "
                          "external-network endpoint."),
            check=lambda s: (
                "financial_execution" in (s.get("_lifted_capabilities") or [])
                and any(s.get(k) for k in ("url", "endpoint", "host"))
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.COMPLIANCE,
            name="acquire_plus_priv_in_one_call",
            description=("Acquire + privilege widening in a single call — "
                          "a composite that the per-domain rules don't "
                          "individually flag."),
            check=lambda s: (
                _has_capability(s, "acquire") and _has_capability(s, "priv")
            ),
        ),
        OmegaRule(
            domain=OmegaDomain.COMPLIANCE,
            name="exec_plus_external_url",
            description=("Code-exec capability combined with an external "
                          "url/endpoint in the same call — composite "
                          "compromise indicator."),
            check=lambda s: (
                _has_capability(s, "exec")
                and any(s.get(k) for k in ("url", "endpoint", "host"))
            ),
        ),
    ]


@dataclass
class CompositeOmega:
    """Compose multiple OmegaDomain sets + cross-domain rules into a
    single GovernanceLayer. Replay-deterministic by construction
    (no RNG, no clock)."""

    domains: list = field(default_factory=lambda: [OmegaDomain.FINANCE,
                                                    OmegaDomain.CYBERSECURITY])
    horizon: int = 3
    forecast_horizon: int = 4
    enable_taint: bool = True
    enable_forecast: bool = True
    log_all: bool = False

    def build(self) -> GovernanceLayer:
        return GovernanceLayer(
            domains=list(self.domains),
            custom_rules=_cross_rules(),
            horizon=self.horizon,
            forecast_horizon=self.forecast_horizon,
            enable_taint=self.enable_taint,
            enable_forecast=self.enable_forecast,
            log_all=self.log_all,
        )

    @staticmethod
    def cross_rules() -> list[OmegaRule]:
        return _cross_rules()
