# LIVE STRIPE TEST MODE: VERIFIED

Independent re-read of Stripe after the scenario run · backend `stripe-test-mode` · account `acct_1UQtP05V2GeL8QqN` · run `run-20261015T183508` · 2026-10-15T18:35:37Z

| Check | Result | Detail |
|---|---|---|
| evidence was produced against api.stripe.com (not the local double) | **PASS** | backend=stripe-test-mode |
| Stripe account of this key matches the run's account | **PASS** | acct_1UQtP05V2GeL8QqN |
| every invoice is test mode (livemode=false) | **PASS** | 5 invoices |
| no invoice anywhere for the unauthorized £5,000 | **PASS** |  |
| S1 invoice exists in Stripe for £500 | **PASS** | in_1UQtUk5V2GeL8QqN0gVy80Yl |
| S1 invoice metadata binds the Morrison operation, decision and action hash | **PASS** | {"morrison_operation_id": "op_2e87c4e1964a4e9b9b2c8a763893f399", "morrison_decision_id": "f292375663af42f0aca5f1b8e988fccb", "morrison_action_hash": "1148a415db |
| S1 invoice was finalised with a hosted payment URL | **PASS** |  |
| S10 payment: Stripe reports the S1 invoice paid in full | **PASS** | paid |
| Acme: only the one authorized invoice exists (S2/S3/S4/S6/S7/S8 created nothing) | **PASS** | 1 invoices |
| Northwind: only the operator-issued £600 invoice exists (S5 created nothing) | **PASS** | [('in_1UQtUg5V2GeL8QqNmRpvbupm', 60000)] |
| Contoso (S9 concurrency): issued total within the £1,000 ceiling, exactly 2 invoices | **PASS** | 2 invoices, total 100000 |
| Globex (S11): exactly one £1,500 invoice, created only after finance approval | **PASS** |  |
| Initech (S12): no invoice after the agreement was terminated | **PASS** | 0 invoices |
| executor record 0: redeemed lease ↔ Stripe invoice in_1UQtUk5V2GeL8QqN0gVy80Yl | **PASS** |  |
| executor record 5: redeemed lease ↔ Stripe invoice in_1UQtUs5V2GeL8QqN3uwK4CdG | **PASS** |  |
| executor record 6: redeemed lease ↔ Stripe invoice in_1UQtUs5V2GeL8QqNQvxR4fUR | **PASS** |  |
| executor record 7: redeemed lease ↔ Stripe invoice in_1UQtV15V2GeL8QqNKHlvKTdH | **PASS** |  |
| no operation id has more than one Stripe invoice (replays created nothing) | **PASS** | 4 governed invoices, 4 operation ids |
| executor refused 5 requests; none is a governed invoice of its own | **PASS** |  |
| Stripe invoices created through Morrison == leases redeemed | **PASS** | 4 vs 4 |
