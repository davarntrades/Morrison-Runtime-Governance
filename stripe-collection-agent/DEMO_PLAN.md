# Two-minute demonstration plan

**Before going on stage.** Set `STRIPE_SECRET_KEY` (test mode) and optionally `ANTHROPIC_API_KEY`. Run the scenarios once against Stripe and keep the output directory:

```bash
python -m collection_agent.scenarios --output evidence/live-demo
python -m collection_agent.demo --results evidence/live-demo      # http://127.0.0.1:8765
```

Keep the Stripe dashboard (test mode → Invoices) open in a second tab.

**Pre-flight (30 s, off stage).** The banner under the title must read **Stripe TEST MODE · account acct_…** (green). Amber **LOCAL STRIPE DOUBLE · NOT STRIPE** means rehearsal mode: never present it as Stripe. Each `demo` start creates fresh test customers, so the presets below behave as described only in this order, on a fresh start. With a Claude key, each run takes about 10–20 s while the agent interprets the request; mention it while it works.

| Time | Action | What the audience sees |
|---|---|---|
| 0:00–0:15 | One sentence: "The agent proposes; Morrison decides; only a Morrison lease reaches Stripe." Point at the four-process diagram in the README. | The agent process has no Stripe key (scenario S0). |
| 0:15–0:50 | Preset **Authorized £500** → Run agent. | Proposal → local ALLOW → global ALLOW → **ALLOW** → Stripe invoice id and hosted payment link → status `open`. Tap **open payment page** and pay as the customer with test card `4242 4242 4242 4242`, any future expiry, any CVC. Back on the dashboard, tap **Re-verify with Stripe**: status `paid`, read from Stripe, not from the agent. |
| 0:50–1:05 | Preset **Compromised: £5,000** → Run. | Local **BLOCK** ("amount 500000 is not an authorized invoice amount"). No lease, no Stripe operation. Refresh the Stripe dashboard: nothing new. |
| 1:05–1:25 | Preset **Northwind £500 (global limit)** → Run. | Local **ALLOW**, global **BLOCK**: "existing 60000 + proposed 50000 > ceiling 100000". The £600 invoice was issued in Stripe by an operator, outside the agent. |
| 1:25–1:40 | Preset **Duplicate** → Run. | Local ALLOW, global BLOCK: duplicate billing reference. |
| 1:40–1:55 | Scroll to **Adversarial scenario results**. | Mutated amount after authorization, replayed lease, missing or forged lease, 6 concurrent proposals (exactly 2 commit), payment verified `paid` via Stripe retrieval, ESCALATE → finance approval, agreement termination cancelling an issued lease. Each was verified against Stripe. |
| 1:55–2:00 | **Evidence chains** panel. | Both hash chains verified. Close: "Not a UI message: the protected Stripe call never happens." |

**Fallback if the network fails on stage.** `python -m collection_agent.demo --double`. The dashboard then shows the backend as the LOCAL DOUBLE. Say so out loud.
