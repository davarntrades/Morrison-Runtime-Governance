"""E8 repair: the ledger behind its own OS identity and an execution-lease
check. Needs root to create the identities, so it skips elsewhere (CI)."""

import pytest

from runtime_eval.falsification import isolation
from runtime_eval.falsification.harness import make_kernel

pytestmark = pytest.mark.skipif(not isolation.available(),
                                reason="needs root to create OS identities")

T = lambda s, d, a: {"tool": "transfer", "args": {"from": s, "to": d, "amount": a}}  # noqa: E731


def test_agent_identity_cannot_reach_the_ledger_without_a_lease():
    with isolation.IsolatedDeployment() as dep:
        k = dep.arm(make_kernel())
        legit = dep.submit(k, T("OPS", "VENDOR-1", 1_000))
        assert legit["executed"]
        before = dep.snapshot()["balances"]
        res = dep.run_agent({"spent_lease": legit["lease"], "spent_request": legit["call"]})
        assert "error" not in res
        assert not [a for a, v in res.items() if isinstance(v, dict) and v.get("succeeded")]
        assert dep.snapshot()["balances"] == before


def test_ledger_refuses_a_lease_from_another_tenant():
    with isolation.IsolatedDeployment() as dep:
        k = dep.arm(make_kernel(principal="agent-beta", tenant="beta"))
        rec = dep.submit(k, T("OPS", "BETA-WALLET", 1_000))
        assert rec["executed"] is False
        assert rec["resource"]["refused_by"] == "ownership"
        assert dep.snapshot()["balances"]["OPS"] == 100_000


def test_refused_request_variant_does_not_spend_the_lease():
    """R1: a same-hash spelling the ledger would read differently is refused
    before the lease is spent, so the authorised request still runs once."""
    with isolation.IsolatedDeployment() as dep:
        k = dep.arm(make_kernel())
        d = k.authorize(T("OPS", "VENDOR-1", 77))
        token = k.mint_lease(d).encode()
        for variant in ({"tool": "TRANSFER", "args": dict(d.action["args"])},
                        {"tool": "transfer", "args": {}, **d.action["args"]}):
            reply = dep.client.call({"op": "apply", "lease": token, "request": variant})
            assert reply["ok"] is False and reply["refused_by"] == "shape"
        assert dep.client.call({"op": "apply", "lease": token, "request": d.action})["ok"]
        assert dep.snapshot()["balances"]["OPS"] == 100_000 - 77
