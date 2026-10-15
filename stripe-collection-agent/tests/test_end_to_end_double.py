"""Full process-separated stack against the LOCAL Stripe double (offline).

This proves the wiring, the boundary and the scenario logic. It is NOT a
Stripe result; the live run (`.github/workflows/stripe-collection-live.yml`
or `python -m collection_agent.scenarios`) is the Stripe evidence.
"""

import json

from collection_agent.scenarios import FAILED, INCONCLUSIVE, Harness, write_evidence
from collection_agent.launcher import Stack


def test_all_scenarios_against_local_double(tmp_path):
    with Stack(tmp_path / "stack", use_double=True) as stack:
        h = Harness(stack)
        results = h.run_all()
        summary = write_evidence(tmp_path / "ev", stack, results)
    bad = [r for r in results if r["status"] in (FAILED, INCONCLUSIVE)]
    assert not bad, json.dumps(bad, indent=2, default=str)[:4000]
    assert summary["governance_evidence"]["verified"]
    assert summary["executor_evidence"]["verified"]
    assert summary["is_real_stripe"] is False


def test_executor_without_lease_never_reaches_stripe(tmp_path):
    from collection_agent.web import call
    with Stack(tmp_path / "stack", use_double=True) as stack:
        before = len(stack.gateway.client.v1.invoices.list({"limit": 100}).data)
        status, body = call("POST", f"{stack.exe_url}/execute", {"lease": "", "request": {
            "tool": "create_collection_invoice", "args": {"amount": 1}}})
        after = len(stack.gateway.client.v1.invoices.list({"limit": 100}).data)
    assert status == 403 and body["stripe_called"] is False and before == after
