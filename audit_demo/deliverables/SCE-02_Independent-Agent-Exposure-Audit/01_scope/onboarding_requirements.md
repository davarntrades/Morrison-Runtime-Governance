# Onboarding requirements and the 48-hour target

The 48-hour clock starts only when every item below is in place.

## The customer provides

1. **An authorised, isolated test environment** for the one agent and workflow in scope. Payment,
   messaging and identity calls must go to sandbox or inert endpoints. Production is never touched.
2. **A customer adapter** meeting `audit_demo/exposure/adapter.py`:
   - `declared_tools()`: the documented tool inventory.
   - `discover_operations()`: what the agent's credential can actually call (API gateway listing,
     service-account permissions).
   - `via_customer_controls()`: the path through the customer's own safeguards, returning what they
     report.
   - `direct()`: the same operation with no safeguard (test environment only).
   - `observe()`: read access to the systems of record (ledger, identity store, message logs, export
     logs).
   - `unobservable()`: state the audit cannot read, declared up front.
3. **The constraints** the organisation claims, in writing, and which control is meant to enforce
   each.
4. **Test approval credentials** for any approval workflow (so genuine approvals can be issued).
5. **A named technical contact** available during the 48 hours.

## Effort, as estimated from building this sample (SCE-02)

| Work | Before the clock (onboarding) | Inside the 48 hours |
|:--|:--|:--|
| Adapter wiring against the customer's sandbox | 1-3 days, depending on API maturity | Fixes only |
| Encode constraints as observable prohibited states | | 4-6 h |
| Write and dry-run ~25 scenarios | | 6-10 h |
| Run, verify, self-test, build pack | | under 1 h of compute |
| Interpret results, residual register, review | | 6-10 h |

## Verdict on the 48-hour target

The target is **credible only if the adapter exists before the clock starts.** The adapter is the
customer-specific part. Building one from scratch inside 48 hours is not credible for most
regulated environments, because it depends on sandbox access, permissions and API behaviour outside
the auditor's control. Price the adapter as a separate onboarding step, or limit eligibility to
customers whose agent framework already has an adapter.

Things that would stop the clock: no sandbox for external-state-changing tools; no read access to
the system of record (results become INCONCLUSIVE); approval systems with no test credentials;
tools discovered at runtime that were not in the agreed scope.
