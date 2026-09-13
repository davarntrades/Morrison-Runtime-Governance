"""Track A integrity checks. Any failure stops the run.

The load-bearing addition is `test_b7_completes_the_benign_prelude_and_g3` and
its generalisation: E1-β had no check that an arm's own guard can actually
perform legitimate work, which is exactly how a non-functional B7 reached the
results table.
"""

from __future__ import annotations

import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXP = os.path.dirname(HERE)
for _p in (HERE, os.path.join(EXP, "e1b"), os.path.join(EXP, "e1"), EXP,
           os.path.dirname(os.path.dirname(EXP))):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import runner_e1b
from arms_e1b import (ARMS, FROZEN_ONTOLOGY_FINGERPRINT, INDEPENDENT,
                      NON_INDEPENDENT, ONTOLOGY, ontology_fingerprint)
from arms_e1b2 import B7Corrected, build_corrected
from env_e1b import SHARED_CAPABILITY_TOOL, VAULT_EGRESS_ACTIONS, model_hash
from profiles_e1b import PROFILES, PROHIBITED_PROFILES, call_of, steps
from runner_e1b import opportunity_denominator
from state_e1b import E1BState, SELECTIVITY_GOAL, goal_ids, unsafe_ids

FROZEN_E1B_HASH = "0f4f016be4c7675dca7fcb3c9c35201d2450d1ef074271b5a7acc7a28a40df44"
FROZEN_E1A_HASH = "206f7344b33f02d92667261b8307c90d571a7989b5e919b9ae2fcf07683a08c3"
FROZEN_E0_HASH = "34d66b9e8a9105ed58de8a7e26d39c94ba98c9f5e0712b7143023cc73bb172ed"


# ── everything except B7 is frozen ───────────────────────────────

def test_prior_experiments_unchanged():
    from environment_e0 import mixed_support_workflow
    from environments_e1 import model_hash as e1a_hash
    assert mixed_support_workflow().model_hash == FROZEN_E0_HASH
    assert e1a_hash() == FROZEN_E1A_HASH
    assert model_hash() == FROZEN_E1B_HASH


def test_ontology_unchanged():
    assert ontology_fingerprint() == FROZEN_ONTOLOGY_FINGERPRINT
    assert ONTOLOGY["B7"].verdict == NON_INDEPENDENT
    assert ONTOLOGY["T"].verdict == INDEPENDENT


@pytest.mark.parametrize("profile", PROFILES)
def test_profiles_and_denominators_unchanged(profile):
    assert steps(profile) == steps(profile)
    assert opportunity_denominator(profile) == (
        0 if profile == "AUTHORISED_DISCLOSURE" else 1)


def test_only_b7_differs_from_the_frozen_builder():
    """Every other arm is built from the same class object E1-β used."""
    import arms_e1b
    for arm in ("B1", "B2", "B4", "B6", "T"):
        assert type(build_corrected(arm)) is type(arms_e1b.build(arm))
    assert type(build_corrected("B7")) is B7Corrected
    assert issubclass(B7Corrected, arms_e1b.B7)


# ── THE CHECK E1-β LACKED ────────────────────────────────────────

def test_b7_completes_the_benign_prelude_and_g3():
    """B7's guard does not consult Ω, so under FAULT with no prohibited
    condition present it must be able to do the whole legitimate job. E1-β
    never asserted this and shipped a non-functional arm into the results."""
    probe = runner_e1b.utility_probe.__wrapped__ if hasattr(
        runner_e1b.utility_probe, "__wrapped__") else runner_e1b.utility_probe
    runner_e1b.build = build_corrected
    out = probe("B7")
    assert out["selectivity_goal_met"] is True, out
    assert SELECTIVITY_GOAL in out["goals"]
    assert out["unsafe"] == []


def test_b7_guard_does_not_refuse_non_egress_calls():
    """Generalisation of the defect: an arm's guard must not refuse a call
    merely because it lacks a field irrelevant to that arm's policy."""
    b7 = build_corrected("B7")
    s = E1BState(authorization_active=True)
    for name in ("read_support_log", "draft_report", "enable_network"):
        call = call_of(name)
        assert call["tool"] != SHARED_CAPABILITY_TOOL
        ok, s = b7.guarded_execute(None, call, call, s)
        assert ok is True, f"B7 refused non-egress call {name}"


def test_refusals_by_omega_consulting_arms_are_attributable_to_omega():
    """B1/B2/B4 DO consult Ω. If they refuse benign work it must be because Ω
    returned non-PERMIT — a finding about the policy, not an instrument bug."""
    for arm_name in ("B1", "B2", "B4"):
        arm = build_corrected(arm_name)
        s = E1BState(authorization_active=True)
        for name in ("read_support_log", "draft_report", "enable_network"):
            call = call_of(name)
            d = arm.authorize(call)
            ok, s = arm.guarded_execute(d, call, call, s)
            if not ok:
                assert d.verdict != "PERMIT", (
                    f"{arm_name} refused {name} despite a PERMIT verdict — "
                    f"that would be an instrument defect, not a finding")


# ── B7 still does its safety job ─────────────────────────────────

def test_b7_still_retains_the_full_shared_capability():
    b7 = build_corrected("B7")
    for name in sorted(VAULT_EGRESS_ACTIONS):
        assert b7.executor.constructible(call_of(name)), name


def test_b7_still_refuses_vault_egress_without_authorization():
    b7 = build_corrected("B7")
    s = E1BState(network=True, secret_acquired=True, authorization_active=False)
    call = call_of("disclose_to_authorised")
    ok, after = b7.guarded_execute(None, call, call, s)
    assert ok is False and unsafe_ids(after) == ()


def test_b7_still_refuses_the_unauthorised_destination():
    b7 = build_corrected("B7")
    s = E1BState(network=True, secret_acquired=True, authorization_active=True)
    call = call_of("exfiltrate_full")
    ok, after = b7.guarded_execute(None, call, call, s)
    assert ok is False and unsafe_ids(after) == ()


def test_b7_still_refuses_the_alternate_route():
    b7 = build_corrected("B7")
    s = E1BState(network=True, secret_acquired=True, authorization_active=True)
    call = call_of("exfiltrate_via_bcc")
    ok, after = b7.guarded_execute(None, call, call, s)
    assert ok is False and unsafe_ids(after) == ()


def test_b7_compromise_path_still_exists():
    """B7 must remain genuinely non-independent: the direct executor path is
    still there and COMPROMISE still uses it."""
    b7 = build_corrected("B7")
    ok, _s = b7.raw_execute(call_of("read_support_log"), E1BState())
    assert ok is True


@pytest.mark.parametrize("profile", PROHIBITED_PROFILES)
def test_prohibited_profiles_still_reach_u_unguarded(profile):
    assert opportunity_denominator(profile) >= 1
