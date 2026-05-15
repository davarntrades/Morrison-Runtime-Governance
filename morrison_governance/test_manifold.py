"""
V5 perturbation-manifold robustness — test suite.

Run:
    python3 morrison_governance/test_manifold.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import (
    GovernanceLayer, OmegaDomain, structural_distance, cross_domain_transfer,
    DEFAULT_MANIFOLDS,
)


def _g():
    return GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY,
                                    OmegaDomain.FINANCE], log_all=False)


# ---- geometric distance metric ----------------------------------------

def test_distance_identity_and_symmetry():
    a = {"tool": "read_file", "args": {"path": "/x"}}
    b = {"tool": "http_request", "args": {"url": "u"}}
    assert structural_distance(a, a) == 0.0
    assert structural_distance(a, b) == structural_distance(b, a)
    assert 0.0 < structural_distance(a, b) <= 1.0


def test_distance_monotone_with_change():
    base = {"tool": "read_file", "args": {"path": "/x"}}
    near = {"tool": "read_file", "args": {"path": "/y"}}      # arg value only
    far = {"tool": "http_request", "args": {"url": "u", "to": "z"}}
    assert structural_distance(base, near) < structural_distance(base, far)


# ---- stability envelope -----------------------------------------------

def test_envelope_radius0_is_identity_anchor():
    g = _g()
    rep = g.estimate_robustness({"tool": "transfer",
                                 "args": {"amount": 999999}}, seed=0)
    assert rep.radii[0] == 0.0
    assert rep.agreement[0] == 1.0  # B(ℰ,0) = {baseline}


def test_safe_call_high_robustness_margin():
    g = _g()
    rep = g.estimate_robustness({"tool": "analyze",
                                 "args": {"q": "summary"}}, seed=0)
    assert rep.baseline_verdict == "PERMIT"
    assert rep.robustness_margin >= 0.8  # robust across the ball


def test_envelope_fields_well_formed():
    g = _g()
    rep = g.estimate_robustness({"tool": "transfer",
                                 "args": {"amount": 999999}}, seed=0)
    assert len(rep.radii) == len(rep.agreement) == len(rep.mean_distance)
    assert all(0.0 <= a <= 1.0 for a in rep.agreement)
    assert rep.mean_distance[0] == 0.0  # no deformation at r=0
    assert all(m in rep.per_family for m in
               (mf.name for mf in DEFAULT_MANIFOLDS))
    assert rep.collapse_threshold is None or 0.0 <= rep.collapse_threshold


def test_envelope_determinism():
    g = _g()
    call = {"tool": "transfer", "args": {"amount": 999999}}
    a = g.estimate_robustness(call, seed=11)
    b = g.estimate_robustness(call, seed=11)
    assert a.agreement == b.agreement
    assert a.mean_distance == b.mean_distance
    assert a.per_family == b.per_family


# ---- cross-domain transfer (geometry invariant, only Ω changes) -------

def test_cross_domain_geometry_invariant():
    tr = cross_domain_transfer(
        lambda ds: GovernanceLayer(domains=ds, log_all=False),
        {"tool": "transfer", "args": {"amount": 50000}},
        [[OmegaDomain.FINANCE], [OmegaDomain.HEALTHCARE],
         [OmegaDomain.CYBERSECURITY], [OmegaDomain.COMPLIANCE]])
    assert tr.geometry_invariant is True   # same middleware everywhere
    assert tr.omega_dependent is True      # verdict changes only via Ω
    assert tr.verdict_by_domain["FINANCE"] == "BLOCK"


def test_cross_domain_invariant_call_stable_everywhere():
    """A structurally-safe call is PERMIT under every Ω."""
    tr = cross_domain_transfer(
        lambda ds: GovernanceLayer(domains=ds, log_all=False),
        {"tool": "analyze", "args": {"q": "summary"}},
        [[OmegaDomain.FINANCE], [OmegaDomain.HEALTHCARE],
         [OmegaDomain.FRAUD], [OmegaDomain.DATA_PRIVACY]])
    assert set(tr.verdict_by_domain.values()) == {"PERMIT"}
    assert tr.geometry_invariant is True


if __name__ == "__main__":
    tests = [
        test_distance_identity_and_symmetry,
        test_distance_monotone_with_change,
        test_envelope_radius0_is_identity_anchor,
        test_safe_call_high_robustness_margin,
        test_envelope_fields_well_formed,
        test_envelope_determinism,
        test_cross_domain_geometry_invariant,
        test_cross_domain_invariant_call_stable_everywhere,
    ]
    print("\n" + "═" * 64)
    print("  V5 — Perturbation-Manifold Robustness")
    print("═" * 64 + "\n")
    p = f = 0
    for t in tests:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "═" * 64)
    sys.exit(1 if f else 0)
