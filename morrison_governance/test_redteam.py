"""
Assumption-driven red-team suite (#7).

This suite does not assert "no attack ever succeeds". It asserts the
harness's *detection contract*: each probe targets an implicit assumption
with a structurally-distinct family carrying one intent, the result is
deterministic, the assumptions that DO hold are confirmed held, and the
known residual gaps are reproducibly flagged (not silently green).

Run:  python3 morrison_governance/test_redteam.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import (
    GovernanceLayer, OmegaDomain, RedTeamSession,
)

DOM = [OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE]


def gf():
    return GovernanceLayer(domains=DOM, log_all=False)


def _report():
    return RedTeamSession(gf).run()


def test_report_is_deterministic():
    a = _report()
    b = _report()
    assert a.summary() == b.summary()
    assert ([(p.assumption, p.held, p.blocked) for p in a.probes]
            == [(p.assumption, p.held, p.blocked) for p in b.probes])


def test_held_assumptions_are_confirmed():
    held = set(_report().assumptions_held)
    for must_hold in (
        "verdict_independent_of_planner_identity",
        "sink_dangerous_only_after_textual_source",
        "single_agent_boundary_contains_trajectory",
        "structural_reachability_is_name_independent",
    ):
        assert must_hold in held, (must_hold, held)


def test_known_gaps_are_reproducibly_flagged():
    """The harness must SURFACE real gaps, not paper over them. These two
    assumptions do not hold against the current hierarchy; if either
    starts holding (a genuine fix), update this pin and LIMITATIONS.md."""
    violated = set(_report().assumptions_violated)
    assert "acquire_egress_caught_for_open_world_names" in violated, violated
    assert "privilege_requires_admin_keyword" in violated, violated


def test_planner_identity_probe_blocks_every_rendering():
    rep = _report()
    probe = next(p for p in rep.probes
                 if p.assumption == "verdict_independent_of_planner_identity")
    assert probe.blocked == probe.family_size == 5
    assert all(v == "BLOCK" for _, v, _ in probe.detail)
    assert {l for _, _, l in probe.detail} == {"V2"}


def test_multi_agent_probe_uses_joint_trajectory():
    rep = _report()
    probe = next(p for p in rep.probes
                 if p.assumption
                 == "single_agent_boundary_contains_trajectory")
    assert probe.held and probe.detail[0][1] == "BLOCK"


def test_summary_counts_consistent():
    rep = _report()
    s = rep.summary()
    assert s["probes"] == len(rep.probes) == 6
    assert s["held"] + s["violated"] == s["probes"]
    assert s["held"] == 4 and s["violated"] == 2


if __name__ == "__main__":
    T = [test_report_is_deterministic,
         test_held_assumptions_are_confirmed,
         test_known_gaps_are_reproducibly_flagged,
         test_planner_identity_probe_blocks_every_rendering,
         test_multi_agent_probe_uses_joint_trajectory,
         test_summary_counts_consistent]
    print("\n" + "═" * 60 + "\n  Assumption-Driven Red-Team Harness\n"
          + "═" * 60 + "\n")
    p = f = 0
    for t in T:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "═" * 60)
    sys.exit(1 if f else 0)
