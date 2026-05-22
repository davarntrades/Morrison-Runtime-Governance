"""Adaptive Ω evolution.

New failure modes emerge over time. Ω must grow — but deterministically,
versioned, and with provenance, so any decision is auditable and
replayable at the Ω-version it was made under. This registry ingests
new Ω rules (e.g. surfaced from an incident or an adversarial finding)
and can materialise a GovernanceLayer at any version."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule


@dataclass
class OmegaVersion:
    version: int
    rule_name: str
    provenance: str
    digest: str

    def as_dict(self) -> dict:
        return {"version": self.version, "rule_name": self.rule_name,
                "provenance": self.provenance, "digest": self.digest}


def _digest(prev: str, rule_name: str, provenance: str) -> str:
    return hashlib.sha256(
        json.dumps({"prev": prev, "rule": rule_name, "prov": provenance},
                   sort_keys=True).encode()).hexdigest()[:16]


class AdaptiveOmega:
    """Versioned Ω registry. Base domains are fixed; ingested rules form
    an append-only, hash-chained version history."""

    def __init__(self, base_domains: list,
                 horizon: int = 3, forecast_horizon: int = 4):
        self.base_domains = list(base_domains)
        self.horizon = horizon
        self.forecast_horizon = forecast_horizon
        self._ingested: list = []           # list[(OmegaRule, OmegaVersion)]
        self._chain = "GENESIS"

    def ingest_incident(self, rule: OmegaRule, provenance: str) -> OmegaVersion:
        version = len(self._ingested) + 1
        self._chain = _digest(self._chain, rule.name, provenance)
        ov = OmegaVersion(version=version, rule_name=rule.name,
                          provenance=provenance, digest=self._chain)
        self._ingested.append((rule, ov))
        return ov

    @property
    def current_version(self) -> int:
        return len(self._ingested)

    def history(self) -> list:
        return [ov for _r, ov in self._ingested]

    def layer_at_version(self, version: Optional[int] = None,
                         **kwargs) -> GovernanceLayer:
        """Build a GovernanceLayer with base domains + ingested rules up
        to `version` (default: all). Deterministic for a fixed version."""
        v = self.current_version if version is None else version
        custom = [r for r, ov in self._ingested if ov.version <= v]
        return GovernanceLayer(
            domains=self.base_domains, custom_rules=custom,
            horizon=self.horizon, forecast_horizon=self.forecast_horizon,
            log_all=False, **kwargs)

    def current_layer(self, **kwargs) -> GovernanceLayer:
        return self.layer_at_version(None, **kwargs)
