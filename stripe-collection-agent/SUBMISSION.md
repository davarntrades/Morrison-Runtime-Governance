# Submission runbook

Current state: the live Stripe test-mode run **passed** on 2026-10-15 ([run 38786789211](https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38786789211), rule-based interpreter): 13/13 scenarios PASSED, and the independent Stripe re-read reports **LIVE STRIPE TEST MODE: VERIFIED**. Evidence: `evidence/live-STRIPE-TEST-MODE-20261015T183507Z/`. The offline results in `evidence/offline-LOCAL-DOUBLE-not-stripe/` remain separate and are not Stripe results. A second live run with **`interpreter=claude`** also passed ([run 38788586083](https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38788586083), 13/13, VERIFIED; evidence `evidence/live-STRIPE-TEST-MODE-CLAUDE-20261015T184811Z/`).

## 1. Add `STRIPE_TEST_SECRET_KEY` (iPhone, about 3 minutes)

**Get the test key (Safari):**
1. Open `https://dashboard.stripe.com/test/apikeys` and sign in. The URL contains `/test/`, so you are in test mode.
2. Under **Standard keys → Secret key**, tap **Reveal test key** and copy it. It must start with `sk_test_`. Never use a key starting with `sk_live_`; the workflow refuses it.

**Add it to GitHub (Safari, not the GitHub app):**
1. Open `https://github.com/davarntrades/Morrison-Runtime-Governance/settings/secrets/actions`. The repository **Settings** tab is not available in the GitHub iPhone app.
2. Tap **New repository secret**.
3. Name: `STRIPE_TEST_SECRET_KEY` (exactly). Secret: paste the `sk_test_…` key. Tap **Add secret**.
4. `ANTHROPIC_API_KEY` is already a repository secret (used by the AgentDojo workflow). Nothing to add for Claude.

## 2. Trigger the live run

The workflow runs against Stripe **only when dispatched manually** with the confirmation `RUN-LIVE-STRIPE`. Pushes run only the free offline suite.

**Easiest:** reply in this Claude session with "run the live Stripe test". Claude dispatches it through the GitHub API on branch `claude/stripe-morrison-collection-agent-7y0a6p`, then reads the result.

**Yourself, after the workflow file is on `main`:** GitHub shows a **Run workflow** button only for workflows that exist on the default branch.
1. In Safari, open `https://github.com/davarntrades/Morrison-Runtime-Governance/actions/workflows/stripe-collection-live.yml`.
2. Tap **Run workflow**.
3. **Use workflow from:** `claude/stripe-morrison-collection-agent-7y0a6p`.
4. **confirm:** `RUN-LIVE-STRIPE`.
5. **interpreter:** `claude`, or `rule-based` for no model calls.
6. Tap **Run workflow**.

Until the file is merged to `main`, use the Claude route above.

**Cost.** Stripe test mode is free. `interpreter=claude` makes a handful of Claude API calls in scenario S1 only. Each run creates about 5 test customers and 6 test invoices in your Stripe test account, tagged `[run-YYYYMMDDTHHMMSS]`.

## 3. What counts as "Stripe integration demonstrated"

All three must be true for the same run:

1. The job **Live Stripe test mode** is green. It fails unless every scenario passed **and** the independent re-read passed.
2. The run summary shows `Scenario results (Stripe test mode)` with backend `stripe-test-mode` and a real `acct_…` id, not `acct_double_resurrection`.
3. `LIVE_VERIFICATION.md` (in the run summary and the evidence) is headed **LIVE STRIPE TEST MODE: VERIFIED**.

`collection_agent.verify_live` re-reads every run-tagged customer's invoices from Stripe after the scenarios finish. It does not trust the harness's PASSED labels. It checks that:

- every invoice is `livemode=false`;
- no £5,000 invoice exists anywhere;
- the authorized £500 invoice exists, carries the Morrison operation id, decision id and action hash, is finalised with a hosted URL, and is `paid` in full;
- Acme has exactly 1 invoice (no effect from S2–S8);
- Northwind has only the operator's £600 invoice;
- Contoso has exactly 2 invoices within the £1,000 ceiling;
- Globex has exactly the one approved £1,500 invoice;
- Initech has none;
- every redeemed lease in the executor's evidence chain matches exactly one Stripe invoice, and no operation id has more than one invoice.

After a green run, Claude commits the evidence (decoded from the run log) to `evidence/live-<timestamp>/`, kept separate from `evidence/offline-LOCAL-DOUBLE-not-stripe/`.

You can also check it yourself in the Stripe dashboard: **Test mode → Invoices**, search for the run tag. Open the £500 invoice; its metadata shows `morrison_decision_id`, `morrison_action_hash` and `morrison_lease_id`.

## 4. Create and push the standalone public repository

`git` doesn't run on an iPhone, so use a GitHub Codespace. It runs in Safari, is free within the personal monthly allowance, and its terminal handles all steps.

1. **Open a Codespace on the branch.** In Safari, open `https://github.com/davarntrades/Morrison-Runtime-Governance/tree/claude/stripe-morrison-collection-agent-7y0a6p`, then **Code → Codespaces → Create codespace on claude/stripe-…**. If Safari shows the mobile site, use **aA → Request Desktop Website**.
2. **Authenticate `gh` as yourself.** The Codespace's built-in token can't create repositories. In the terminal:
   ```bash
   unset GITHUB_TOKEN
   gh auth login --hostname github.com --git-protocol https --web
   # copy the one-time code, open https://github.com/login/device, paste, approve
   gh auth setup-git
   ```
3. **Export, create, push:**
   ```bash
   stripe-collection-agent/scripts/export_standalone.sh /tmp/morrison-stripe-collection-agent
   cd /tmp/morrison-stripe-collection-agent
   git -C vendor/Morrison-Runtime-Governance log --oneline -1   # expect 06b9b55
   gh repo create davarntrades/morrison-stripe-collection-agent --public \
       --description "Autonomous Stripe collection agent governed by Morrison Runtime Governance (Stripe × Briefcase hackathon)" \
       --source . --remote origin --push
   ```
   If `gh repo create` is refused, create an empty **public** repository named `morrison-stripe-collection-agent` at `https://github.com/new` (no README, no licence). Then run:
   ```bash
   git remote add origin https://github.com/davarntrades/morrison-stripe-collection-agent.git
   git push -u origin main
   ```
4. **Check:** the new repository shows `vendor/Morrison-Runtime-Governance @ 06b9b55` as a submodule link. To clone it elsewhere: `git clone --recurse-submodules https://github.com/davarntrades/morrison-stripe-collection-agent.git`.
5. **Live run there (optional):** add `STRIPE_TEST_SECRET_KEY` (and `ANTHROPIC_API_KEY` for Claude) to the new repository's secrets, as in step 1. Its workflow is on `main`, so **Run workflow** works directly from Safari.
6. **Stop the Codespace** afterwards: `https://github.com/codespaces` → **⋯ → Stop codespace**.

The export contains only the hackathon application. Morrison is referenced, unmodified, as a submodule pinned to `06b9b55`. Re-export after the live evidence is committed so the public repository includes it.

## 5. Two-minute demo

See `DEMO_PLAN.md`. The dashboard needs a laptop or a Codespace. Run:

```bash
python -m collection_agent.demo --results evidence/live-<timestamp>
```

with `STRIPE_SECRET_KEY` set. The banner at the top must read **Stripe TEST MODE · account acct_…** before presenting. Amber **LOCAL STRIPE DOUBLE · NOT STRIPE** means you are in rehearsal mode.

## Minimum remaining steps before submission

1. Add `STRIPE_TEST_SECRET_KEY` (section 1).
2. Trigger the live run (section 2) and confirm the three conditions in section 3. If anything fails, Claude diagnoses it and the run is repeated. The integration is not demonstrated until then.
3. Commit the live evidence (Claude does this from the run log).
4. Export and push the standalone public repository (section 4), after step 3.
5. Rehearse the demo once on a machine with the test key (`DEMO_PLAN.md`), including paying the hosted invoice with card `4242 4242 4242 4242`.
6. Submit the public repository URL and the green workflow-run URL.
