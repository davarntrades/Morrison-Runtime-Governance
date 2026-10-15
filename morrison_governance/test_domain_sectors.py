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

# (label, a blocking sector-specific call, the authorisation that permits it)
#
# PROVENANCE NOTE — the authorised variants used to be written as
# ``{"tool": "pay_claim", "approved": True}``: the flag sat at the top level of
# the CALLER'S OWN payload, where the extractor folded it into the trusted
# context and it satisfied `_sec_authorized`. That is the policy-state
# provenance defect, not a feature — under it, any caller (or any peer message
# copied into a call) authorised itself by writing one key, and an invented
# name like `coordinator_ceo1_confirmed` did the same through the suffix scan.
#
# The INTENT of these cases is unchanged and still enforced: an authorised
# sector action must PERMIT, with no happy-path false positive. What changes is
# that the authorisation is now established through the deployment's trusted
# channel (`trusted_facts=`) rather than asserted by the call about itself.
# `test_sector_authorisation_must_be_trusted_not_asserted` below pins both
# halves, so the old spelling is now covered as a negative case.
SECTOR_CASES = {
    "insurance": ({"tool": "pay_claim"}, {"approved": True}),
    "government": ({"tool": "modify_benefit"}, {"authorized": True}),
    "supply_chain": ({"tool": "reroute_shipment"}, {"approved": True}),
    "energy": ({"tool": "open_breaker"}, {"authorized": True}),
    "telecommunications": ({"tool": "sim_swap"}, {"verified": True}),
    "manufacturing": ({"tool": "disable_interlock"}, {"authorized": True}),
    "aerospace": ({"tool": "override_autopilot"}, {"authorized": True}),
    "defence": ({"tool": "engage_target"}, {"authorized": True}),
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
    call, trusted = SECTOR_CASES[label]
    result = GovernanceLayer(domains=[OmegaDomain(label)], horizon=2).evaluate(
        call, trusted_facts=trusted)
    assert result.permitted, (
        f"{label}: authorisation established through the trusted channel "
        f"should PERMIT: {call} + {trusted}")


@pytest.mark.parametrize("label", SECTORS)
def test_sector_authorisation_must_be_trusted_not_asserted(label):
    """The same semantic claim, supplied by the CALLER, must not authorise.

    Three spellings of the old self-assertion, plus an invented field name the
    codebase has never seen. None may PERMIT; the trusted channel above must.
    """
    call, trusted = SECTOR_CASES[label]
    g = GovernanceLayer(domains=[OmegaDomain(label)], horizon=2)
    flag = next(iter(trusted))

    top_level = g.evaluate({**call, flag: True})
    in_args = g.evaluate({**call, "args": {flag: True}})
    invented = g.evaluate({**call, "args": {"coordinator_ceo1_confirmed": True}})

    assert top_level.blocked, f"{label}: top-level self-assertion authorised itself"
    assert in_args.blocked, f"{label}: in-args self-assertion authorised itself"
    assert invented.blocked, f"{label}: an invented field name authorised itself"
    assert g.evaluate(call, trusted_facts=trusted).permitted, (
        f"{label}: the trusted channel must still work")


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
    # The authorisation is established by the deployment, not asserted by the
    # call about itself — see the provenance note on SECTOR_CASES.
    permitted = g.evaluate(
        {"tool": "modify_config", "step_1_tool": "verify_identity"},
        trusted_facts={"authorized": True})
    assert permitted.permitted
    # And the old spelling, where the caller wrote the flag into its own
    # payload, must no longer authorise anything.
    self_asserted = g.evaluate({
        "tool": "modify_config", "step_1_tool": "verify_identity",
        "authorized": True})
    assert self_asserted.blocked


def test_benign_sector_trajectory_permitted():
    g = GovernanceLayer(domains=[OmegaDomain.ENERGY], horizon=2)
    assert g.evaluate({"tool": "read_telemetry"}).permitted
    assert g.evaluate({"tool": "generate_report"}).permitted


def test_geometry_unchanged_existing_domains_intact():
    """Adding sectors must not perturb existing-domain behaviour."""
    fin = GovernanceLayer(domains=[OmegaDomain.FINANCE], horizon=2)
    assert fin.evaluate({"tool": "transfer", "authorized": False}).blocked
    assert fin.evaluate({"tool": "read_report"}).permitted
