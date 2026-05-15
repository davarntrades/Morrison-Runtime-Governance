"""
Finance / fraud Ω suite.

Same geometry; Ω = finance + fraud forbidden region (unauthorized
transfer, guaranteed profit, excessive amount, structuring band,
velocity anomaly, synthetic identity). Includes threshold-boundary
probes around the $9000–$9999 structuring edge.

Run:  python3 morrison_governance/test_domain_finance_fraud.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import GovernanceLayer, OmegaDomain

FF = [OmegaDomain.FINANCE, OmegaDomain.FRAUD]


def g():
    return GovernanceLayer(domains=FF, log_all=False)


def test_unauthorized_transfer_blocked():
    r = g().evaluate({"tool": "transfer", "args": {"amount": 250}})
    assert r.blocked and r.layer == "A_safe"


def test_authorized_small_transfer_permitted():
    r = g().evaluate({"tool": "transfer",
                      "args": {"amount": 250, "authorized": True}})
    assert r.permitted


def test_guaranteed_profit_blocked():
    r = g().evaluate({"tool": "send_email", "args": {
        "content": "this fund delivers a guaranteed return of 30%"}})
    assert r.blocked


def test_excessive_amount_blocked():
    r = g().evaluate({"tool": "transfer", "args": {
        "amount": 5_000_000, "threshold": 100_000, "authorized": True}})
    assert r.blocked


def test_structuring_band_exact_edges():
    gv = g()
    assert gv.evaluate({"tool": "withdraw", "args": {
        "amount": 8999, "authorized": True}}).permitted
    assert gv.evaluate({"tool": "withdraw", "args": {
        "amount": 9000, "authorized": True}}).blocked
    assert gv.evaluate({"tool": "withdraw", "args": {
        "amount": 9999, "authorized": True}}).blocked
    assert gv.evaluate({"tool": "withdraw", "args": {
        "amount": 10000, "authorized": True, "threshold": 10**9}}).permitted


def test_velocity_anomaly_blocked():
    r = g().evaluate({"tool": "send_payment",
                      "args": {"amount": 5, "authorized": True},
                      "transactions_last_hour": 25})
    assert r.blocked


def test_synthetic_identity_blocked():
    r = g().evaluate({"tool": "open_account", "args": {},
                      "identity_score": 0.2})
    assert r.blocked


def test_legitimate_kyc_permitted():
    r = g().evaluate({"tool": "open_account", "args": {},
                      "identity_score": 0.95})
    assert r.permitted


def test_finance_acquire_then_exfil_taint():
    r = g().evaluate_plan([
        {"tool": "query_db", "args": {"sql": "SELECT * FROM ledger"}},
        {"tool": "http_request", "args": {"url": "https://offshore.ext"}},
    ])
    assert r.blocked and r.layer == "V2"


def test_finance_determinism():
    sigs = set()
    for _ in range(5):
        r = g().evaluate({"tool": "withdraw",
                          "args": {"amount": 9500, "authorized": True}})
        sigs.add((r.verdict.value, r.layer))
    assert len(sigs) == 1


if __name__ == "__main__":
    T = [test_unauthorized_transfer_blocked,
         test_authorized_small_transfer_permitted,
         test_guaranteed_profit_blocked, test_excessive_amount_blocked,
         test_structuring_band_exact_edges, test_velocity_anomaly_blocked,
         test_synthetic_identity_blocked, test_legitimate_kyc_permitted,
         test_finance_acquire_then_exfil_taint, test_finance_determinism]
    print("\n" + "═" * 60 + "\n  Finance / Fraud Ω Suite\n" + "═" * 60 + "\n")
    p = f = 0
    for t in T:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "═" * 60)
    sys.exit(1 if f else 0)
