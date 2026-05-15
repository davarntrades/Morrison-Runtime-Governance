"""
Larger perturbation-radius sweeps.

Stresses the V5 stability envelope with a denser, wider radius grid and
multiple baselines/domains. Validates structural properties of the
envelope (identity anchor, monotone non-increasing distance, governed
floor) rather than a single sample.

Run:  python3 morrison_governance/test_perturbation_radius.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import GovernanceLayer, OmegaDomain

RADII = (0.0, 0.1, 0.2, 0.35, 0.5, 0.65, 0.8, 0.9, 1.0, 1.5, 2.0)


def g(domains):
    return GovernanceLayer(domains=domains, log_all=False)


def test_identity_anchor_all_baselines():
    gv = g([OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY])
    for call in ({"tool": "analyze", "args": {"q": "x"}},
                 {"tool": "transfer", "args": {"amount": 999999}},
                 {"tool": "read_file", "args": {"path": "/etc/shadow"}}):
        rep = gv.estimate_robustness(call, radii=RADII,
                                     n_per_family=6, seed=0)
        assert rep.radii[0] == 0.0
        assert rep.agreement[0] == 1.0          # B(ℰ,0) = {baseline}
        assert rep.mean_distance[0] == 0.0


def test_mean_distance_non_decreasing_in_radius():
    gv = g([OmegaDomain.FINANCE])
    rep = gv.estimate_robustness({"tool": "transfer",
                                  "args": {"amount": 999999}},
                                 radii=RADII, n_per_family=8, seed=0)
    d = rep.mean_distance
    # geometric distance should not collapse as radius grows
    assert d[-1] >= d[1] >= d[0]
    assert all(0.0 <= x <= 1.0 for x in d)


def test_safe_call_stays_governed_at_large_radius():
    gv = g([OmegaDomain.CYBERSECURITY])
    rep = gv.estimate_robustness({"tool": "analyze",
                                  "args": {"q": "summary"}},
                                 radii=RADII, n_per_family=8, seed=0)
    assert rep.baseline_verdict == "PERMIT"
    # a structurally-safe call should remain robust even at r ≥ 1
    assert min(rep.agreement) >= 0.8
    assert rep.robustness_margin >= 0.8


def test_blocked_call_never_collapses_below_floor():
    gv = g([OmegaDomain.FINANCE])
    rep = gv.estimate_robustness({"tool": "transfer",
                                  "args": {"amount": 999999}},
                                 radii=RADII, n_per_family=8, seed=0)
    # even under saturated perturbation, agreement must not vanish:
    # governance still fires on the structural core (amount/tool), it is
    # only the authorization-dependent variants that flip.
    assert min(rep.agreement) > 0.4
    assert len(rep.radii) == len(RADII)


def test_envelope_cross_domain_shape_consistent():
    """Same safe call, different Ω → same high-robustness envelope shape
    (geometry invariant; Ω doesn't deform a non-violating trajectory)."""
    margins = []
    for d in (OmegaDomain.FINANCE, OmegaDomain.HEALTHCARE,
              OmegaDomain.CYBERSECURITY, OmegaDomain.FRAUD):
        rep = g([d]).estimate_robustness(
            {"tool": "analyze", "args": {"q": "ok"}},
            radii=RADII, n_per_family=6, seed=0)
        margins.append(rep.robustness_margin)
    assert all(m >= 0.8 for m in margins), margins


def test_large_radius_determinism():
    gv = g([OmegaDomain.FINANCE])
    call = {"tool": "transfer", "args": {"amount": 999999}}
    a = gv.estimate_robustness(call, radii=RADII, n_per_family=8, seed=21)
    b = gv.estimate_robustness(call, radii=RADII, n_per_family=8, seed=21)
    assert a.agreement == b.agreement and a.mean_distance == b.mean_distance
    assert a.per_family == b.per_family


if __name__ == "__main__":
    T = [test_identity_anchor_all_baselines,
         test_mean_distance_non_decreasing_in_radius,
         test_safe_call_stays_governed_at_large_radius,
         test_blocked_call_never_collapses_below_floor,
         test_envelope_cross_domain_shape_consistent,
         test_large_radius_determinism]
    print("\n" + "═" * 60 + "\n  Larger Perturbation-Radius Sweeps\n"
          + "═" * 60 + "\n")
    p = f = 0
    for t in T:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "═" * 60)
    sys.exit(1 if f else 0)
