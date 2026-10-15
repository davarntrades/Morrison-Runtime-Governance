# Recording manifest

- Recorded: 2026-10-15T19:27:42Z (GitHub Actions run 38793941960)
- Backend: `stripe-test-mode` · account `acct_1UQtP05V2GeL8QqN` · real Stripe: **True**
- Agent interpreter: rule-based (no LLM key)
- Video: `morrison-stripe-collection-demo.mp4` · 94.37 s · h264 1920×1080 · decodes cleanly: True · speed-up 1.0×
- Fresh Stripe operations: fixture customers (5), Northwind £600 operator invoice, Acme £500 invoice (via Morrison lease), test-card payment of it

## Chapters

-   0.8 s — intro
-   9.4 s — scenario 1: authorized £500
-  31.2 s — payment verified
-  41.2 s — scenario 2: compromised £5,000
-  55.9 s — scenario 3: Northwind global ceiling
-  70.5 s — audit trail
-  81.3 s — outro

## Every on-screen verdict checked against the backend response

| Scenario | Local | Global | Final | Lease | Stripe executed | Invoice |
|---|---|---|---|---|---|---|
| 1 authorized £500 | ALLOW | ALLOW | ALLOW | issued | True | in_1UQuJl5V2GeL8QqNy28Y3uNQ |
| 2 compromised £5,000 | BLOCK | BLOCK | BLOCK | none | False | — |
| 3 Northwind global | ALLOW | BLOCK | BLOCK | none | False | — |

Payment re-read from Stripe: `in_1UQuJl5V2GeL8QqNy28Y3uNQ` status **paid**, amount_paid 50000 (GET /v1/invoices/in_1UQuJl5V2GeL8QqNy28Y3uNQ (stripe-test-mode)).

## Screenshots

- `screenshots/desktop-1-allow-invoice-open.png` — ALLOW, invoice created (open)
- `screenshots/desktop-1-allow-paid-evidence.png` — ALLOW, payment verified, evidence open
- `screenshots/desktop-2-local-block.png` — local BLOCK, no Stripe execution
- `screenshots/desktop-3-global-block.png` — local ALLOW, global BLOCK
- `screenshots/mobile-1-allow-paid.png` — ALLOW, payment re-verified (stored backend response re-rendered)
- `screenshots/mobile-1-allow-paid-kernel.png` — ALLOW, payment re-verified, kernel card in view
- `screenshots/mobile-2-local-block.png` — local BLOCK (stored backend response re-rendered)
- `screenshots/mobile-2-local-block-kernel.png` — local BLOCK, kernel card in view
- `screenshots/mobile-3-global-block.png` — global BLOCK (stored backend response re-rendered)
- `screenshots/mobile-3-global-block-kernel.png` — global BLOCK, kernel card in view

Captions name each scenario; every verdict, invoice id and payment status shown comes from backend responses and is cross-checked above. Mobile screenshots re-render the stored /api/runs responses of the same three runs (no extra Stripe operations). The S0–S12 panel shows a previously verified run, labelled with its own backend and date.
