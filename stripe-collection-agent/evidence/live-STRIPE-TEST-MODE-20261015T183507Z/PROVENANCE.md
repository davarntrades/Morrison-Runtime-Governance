# Provenance: live Stripe test-mode run

This is genuine **Stripe test-mode** evidence, produced against `api.stripe.com`. The offline results in `../offline-LOCAL-DOUBLE-not-stripe/` are from the local double and are **not** Stripe evidence.

| | |
|---|---|
| Workflow run | https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38786789211 (job 116600736477, "Live Stripe test mode") |
| Trigger | `workflow_dispatch`, `confirm=RUN-LIVE-STRIPE`, `interpreter=rule-based` (no model calls) |
| Commit | `469d3a852bacec3acfa5ea095fd0a1ab88b0ac5c` on `claude/stripe-morrison-collection-agent-7y0a6p` |
| Stripe account | `acct_1UQtP05V2GeL8QqN` (test mode, "Resurrection Tech — Morrison Demo" sandbox) |
| Run tag on Stripe customers | `run-20261015T183508` |
| Scenarios | 13/13 PASSED (`RESULTS.md`, `scenarios.json`) |
| Independent Stripe re-read | **LIVE STRIPE TEST MODE: VERIFIED**, 20/20 checks (`LIVE_VERIFICATION.md`) |
| Evidence chains | governance 23 records, executor 9 records; both verify |
| Bundle SHA-256 | `00c927ad7c42ed5119ad4662e4fa86cd75cef92f144fea0036d16fb5d031a4fe` (`evidence-bundle.tgz`; matches `EVIDENCE_SHA256` printed in the job log) |

## How these files got here

Artifact downloads are blocked from the build environment, so the workflow printed the evidence as a base64 tarball in its log. The tarball was decoded from the log, its SHA-256 was checked against the value printed by the runner (match), and it was extracted unchanged. `evidence-bundle.tgz` is that exact tarball. To re-check:

```bash
sha256sum evidence-bundle.tgz     # 00c927ad…a4fe
```

## Re-verified after download (outside CI)

- Both hash chains recomputed with Morrison's `EvidenceChain.verify()`: valid. Editing any record's `decision` or `reason` is detected.
- The S1 invoice metadata (`morrison_decision_id`, `morrison_action_hash`) matches a governance PERMIT record and the S1 decision.
- The S1 lease appears twice in the executor chain: redeemed once (PERMIT, executed), then refused on replay (S7: "already been redeemed").
- 4 executor PERMITs (Acme £500, Contoso £500 ×2, Globex £1,500) = 4 Stripe invoices created through Morrison. All 5 refusals (mutated amount, replay, no lease, forged lease, cancelled lease) record `executed=false`.

The Stripe invoice and payment states were re-read from Stripe by the workflow's separate `verify_live` step, using its own Stripe client. This build environment cannot reach `api.stripe.com`, so the invoices were not retrieved a second time from here. They can be inspected in the Stripe dashboard (test mode → Invoices), filtered by customers tagged `run-20261015T183508`.
