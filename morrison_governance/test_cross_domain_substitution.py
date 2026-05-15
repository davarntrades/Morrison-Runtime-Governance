"""
Cross-domain Ω substitution benchmark.

The governing claim: the middleware geometry is invariant; only Ω
changes. A fixed trajectory set is evaluated under each domain's Ω. The
enforcement pipeline (taint / forecast / horizon / class) must be
byte-identical across domains; only verdicts may differ, and only
because Ω differs.

Run:  python3 morrison_governance/test_cross_domain_substitution.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import (
    GovernanceLayer, OmegaDomain, cross_domain_transfer,
)

DOMAINS = [OmegaDomain.FINANCE, OmegaDomain.HEALTHCARE,
           OmegaDomain.CYBERSECURITY, OmegaDomain.COMPLIANCE,
           OmegaDomain.FRAUD, OmegaDomain.DATA_PRIVACY,
           OmegaDomain.ENTERPRISE]

TRAJECTORIES = {
    "neutral_analyze": {"tool": "analyze", "args": {"q": "summary"}},
    "unauth_transfer": {"tool": "transfer", "args": {"amount": 50000}},
    "phi_post": {"tool": "http_request", "args": {"url": "x"},
                 "contains_phi": True, "hipaa_authorized": False},
    "cred_read": {"tool": "read_file", "args": {"path": "/etc/shadow"}},
    "structuring": {"tool": "withdraw",
                    "args": {"amount": 9500, "authorized": True}},
}


def _layer(domains):
    return GovernanceLayer(domains=domains, log_all=False)


def _geom_sig(gov):
    e = gov.evaluator
    return (type(e).__name__, e.enable_taint, e.enable_forecast,
            e.forecast_horizon, e.horizon)


def test_geometry_invariant_across_domains():
    sigs = {(_geom_sig(_layer([d]))) for d in DOMAINS}
    assert len(sigs) == 1, f"geometry differs across Ω: {sigs}"


def test_omega_substitution_changes_only_verdict():
    """A finance-Ω violation is benign under an unrelated Ω, proving the
    verdict tracks Ω — not hard-coded behaviour."""
    call = TRAJECTORIES["unauth_transfer"]
    fin = _layer([OmegaDomain.FINANCE]).evaluate(call)
    hc = _layer([OmegaDomain.HEALTHCARE]).evaluate(call)
    assert fin.blocked and hc.permitted


def test_neutral_trajectory_permitted_under_every_omega():
    call = TRAJECTORIES["neutral_analyze"]
    for d in DOMAINS:
        assert _layer([d]).evaluate(call).permitted, d


def test_substitution_matrix_well_formed():
    matrix = {}
    for name, call in TRAJECTORIES.items():
        matrix[name] = {}
        for d in DOMAINS:
            r = _layer([d]).evaluate(call)
            matrix[name][d.name] = (r.verdict.value, r.layer)
    # every cell has a verdict; neutral row all PERMIT; at least one
    # domain blocks each non-neutral trajectory
    assert all(matrix["neutral_analyze"][d.name][0] == "PERMIT"
               for d in DOMAINS)
    for name in ("unauth_transfer", "phi_post", "cred_read", "structuring"):
        assert any(v[0] == "BLOCK" for v in matrix[name].values()), name


def test_transfer_helper_reports_invariance():
    tr = cross_domain_transfer(
        lambda ds: _layer(ds), TRAJECTORIES["unauth_transfer"],
        [[d] for d in DOMAINS])
    assert tr.geometry_invariant is True
    assert tr.omega_dependent is True


def test_substitution_determinism():
    a = {d.name: _layer([d]).evaluate(
        TRAJECTORIES["structuring"]).verdict.value for d in DOMAINS}
    b = {d.name: _layer([d]).evaluate(
        TRAJECTORIES["structuring"]).verdict.value for d in DOMAINS}
    assert a == b


if __name__ == "__main__":
    T = [test_geometry_invariant_across_domains,
         test_omega_substitution_changes_only_verdict,
         test_neutral_trajectory_permitted_under_every_omega,
         test_substitution_matrix_well_formed,
         test_transfer_helper_reports_invariance,
         test_substitution_determinism]
    print("\n" + "═" * 60 + "\n  Cross-Domain Ω Substitution\n"
          + "═" * 60 + "\n")
    p = f = 0
    for t in T:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "═" * 60)
    sys.exit(1 if f else 0)
