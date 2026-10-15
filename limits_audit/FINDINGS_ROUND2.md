# Round 2 — peer-GO closure confirmation, BUG A, BUG B

Branch `claude/morrison-governance-fixes-round2`, forked from `5e739a3`.
Every number below came from a clean worktree at the pre-change commit, not a
stash.

| | passed | skipped |
|---|---|---|
| **Baseline** `5e739a3` (clean detached worktree) | **1123** | 1 |
| **After BUG A** | 1135 | 1 |
| **After BUG A + BUG B** | **1150** | 1 |

`MORRISON_SERVICE_PATH=/home/user/rte/governance-service` on both sides — the
worktree sits outside the repo's sibling-lookup path, and without it the
baseline reports "1117 passed, 7 skipped" purely because of where the worktree
lives. Stating the raw numbers without that would have misrepresented the
comparison.

---

# PART 1 — the exact originally-failing scenario

Script: `limits_audit/part1_exact_scenario.py`, run unmodified against two
engine commits. Domain mental-health-safety, tool `reply`, peer-supplied
`crisis_referral=true`, no prior authorization.

**A note on the configuration.** The request described the empty manifest as
"the config that previously masked the bug". The original finding recorded the
opposite pairing, so both are run and both are shown:

- **tool DECLARED** — the *recommended* config, and the one that **showed** the
  bug (PERMIT, executed)
- **empty manifest** — the one that **masked** it behind undeclared-tool
  ESCALATE

### BEFORE — engine `29b80e2`

```
  tool DECLARED in manifest (recommended)
    baseline (no claim)                BLOCK     A_safe        rule=failure_to_route_crisis_disclosure forged_claims=[] ran=0
    peer GO: crisis_referral=True      PERMIT    V4            rule=None                               forged_claims=[] ran=1   <-- PERMITTED AND DELIVERED
    peer GO: emergency_referral=True   PERMIT    V4            rule=None                               forged_claims=[] ran=1   <-- PERMITTED AND DELIVERED
    peer GO: route_to_support=True     PERMIT    V4            rule=None                               forged_claims=[] ran=1   <-- PERMITTED AND DELIVERED

  empty manifest, unknown_tool_policy=escalate (default)
    baseline (no claim)                BLOCK     A_safe        rule=failure_to_route_crisis_disclosure forged_claims=[] ran=0
    peer GO: crisis_referral=True      ESCALATE  unknown_tool  rule=undeclared_tool                    forged_claims=[] ran=0
    peer GO: emergency_referral=True   ESCALATE  unknown_tool  rule=undeclared_tool                    forged_claims=[] ran=0
    peer GO: route_to_support=True     ESCALATE  unknown_tool  rule=undeclared_tool                    forged_claims=[] ran=0

TOTAL DELIVERIES TO A USER IN CRISIS: 3
```

### AFTER — engine `5e739a3` (main) and this branch, identical

```
  tool DECLARED in manifest (recommended)
    baseline (no claim)                BLOCK     A_safe        rule=failure_to_route_crisis_disclosure forged_claims=[] ran=0
    peer GO: crisis_referral=True      BLOCK     A_safe        rule=failure_to_route_crisis_disclosure forged_claims=[] ran=0
    peer GO: emergency_referral=True   BLOCK     A_safe        rule=failure_to_route_crisis_disclosure forged_claims=[] ran=0
    peer GO: route_to_support=True     BLOCK     A_safe        rule=failure_to_route_crisis_disclosure forged_claims=[] ran=0

  empty manifest, unknown_tool_policy=escalate (default)
    ... identical, all BLOCK ...

TOTAL DELIVERIES TO A USER IN CRISIS: 0
```

**Answer to the explicit question: BLOCK, not ESCALATE.** `layer=A_safe`,
`rule=failure_to_route_crisis_disclosure`, `forged_claims=[]`, `ran=0` — in
both manifest configurations.

### Which layer caught it

**Not the lint gate** — that is a CI-time source check
(`morrison_governance/test_provenance_lint_gate.py`) and does nothing at
runtime. The chain, printed from the running engine:

```
1. derivation.py, independent derivation over the action's own content:
     crisis_referral = False
       basis: derivation: content actively steers away from support
2. provenance of the peer's claim in the Omega namespace:
     caller supplied crisis_referral = True
     value the rule actually reads   = False
     provenance class                = derived
     basis                           = derivation: content actively steers away from support
3. the Omega rule then fires normally (nothing suppressed it):
     verdict=BLOCK layer=A_safe rule=failure_to_route_crisis_disclosure
```

`morrison_governance/derivation.py` contradicts the peer's claim from the
reply's own text, DERIVED outranks UNTRUSTED
(`morrison_governance/provenance.py:66`), so the Ω rule fires exactly as it
does with no claim at all. `forged_claims` stays `[]` because
`crisis_referral` is not an AUTHORITY_FIELDS name — it never was, and that was
the original defect; it is now handled by provenance rather than by the list.

### The 23 original GO vectors

`limits_audit/test_4_peer_go_message.py`, unchanged:

```
      Total executions across all 23 GO vectors: 0
```

All 23 pass with the same verdicts as the original audit (A1–A6, E2, I1 BLOCK
at `trust_boundary`; the rest ESCALATE at `capability_policy`).

---

# PART 2 — BUG A: LangChain proxy governance

## What was wrong

**`_CallableToolProxy.__getattr__`** — pre-fix `integrations.py:542`:

```python
def __getattr__(self, item):
    return getattr(self._tool, item)
```

The proxy governed `__call__` and handed the **raw tool** to every other
attribute access. It is the fallback for a tool that refuses attribute
assignment — a pydantic v2 `BaseTool`, the LangChain default since 0.1 — and a
real `AgentExecutor` invokes tools as `tool.run(...)` / `tool.invoke(...)`,
never by calling the object. The proxy governed precisely the path production
does not take.

**`govern_langchain_tool`** — pre-fix `integrations.py:485-500`: the loop
wrapped the **first** of `func`/`_run`/`run`/`invoke` it found and `return`ed.

## Proof it was real — test output BEFORE the fix

`morrison_governance/test_langchain_proxy_governance.py` against the unfixed code:

```
FAILED test_mutable_tool_every_entry_point_is_governed[_run]
FAILED test_mutable_tool_every_entry_point_is_governed[run]
FAILED test_mutable_tool_every_entry_point_is_governed[invoke]
FAILED test_frozen_tool_proxy_governs_every_entry_point[func]
FAILED test_frozen_tool_proxy_governs_every_entry_point[_run]
FAILED test_frozen_tool_proxy_governs_every_entry_point[run]
FAILED test_frozen_tool_proxy_governs_every_entry_point[invoke]
FAILED test_proxy_refuses_an_unknown_callable_rather_than_passing_it_raw
8 failed, 4 passed
```

Each failure is `assert SIDE_EFFECTS == []` failing — a prohibited
`delete_database` actually executed.

## The fix

| Location | Change |
|---|---|
| `integrations.py:509` | `LANGCHAIN_EXECUTION_ATTRS` — 14 names, sync and async |
| `integrations.py:516` | `govern_langchain_tool` wraps **every** execution attribute, not the first |
| `integrations.py:559` | `_govern_bound` — one governed stand-in, async-aware |
| `integrations.py:616` | `_govern_coroutine` — async tools authorize, await, then commit |
| `integrations.py:643` | `_PROXY_PASSTHROUGH` — metadata only |
| `integrations.py:712` | `__getattr__` now **fail-closed**: metadata passes, non-callables pass, **every other callable is governed**, including names this adapter has never heard of |

The default is the opposite of the original: an unrecognised tool method is
exactly the case a passthrough gets wrong, and being wrong in this direction
costs a governed call that did not need to be, not an ungoverned one that did.

## AFTER

```
morrison_governance/test_langchain_proxy_governance.py .............. 14 passed
```

Including `test_proxy_refuses_an_unknown_callable_rather_than_passing_it_raw`,
which calls `proxy.execute_now(...)` — a method invented for the test — and
gets `GovernanceError` with zero side effects.

## The three related findings, each judged plainly

**1. `govern_langchain_tool` wrapping only the first attribute — REAL BYPASS.**
Not config-dependent. Any duck-typed tool whose entry points do not delegate
kept three of four raw. Fixed; proven by
`test_mutable_tool_every_entry_point_is_governed[_run|run|invoke]`.

**2. Verdict-only adapters under `on_block != "raise"` — REAL BYPASS reachable
only through a supported configuration.** `mcp_guard_call_tool`,
`autogen_guard_function_call` and `browser_action_guard` return a Decision and
execute nothing; the caller then executes outside the kernel, so there is no
second gate. Under the default `on_block="raise"` the exception stopped the
handler; under the documented `on_block="deny"` the refusal was advisory and
the next line ran the tool. **Fixed** — `_advisory_gate`
(`integrations.py:316`) makes all three raise on non-PERMIT regardless of
`on_block`.

*This is an API change.* `browser_action_guard(g, ...)` with `on_block="deny"`
previously returned a non-permitted Decision and now raises `GovernanceError`.
`test_integrations.py::test_browser_action_guard` asserted the old shape and
was updated, with the reason recorded in the test. `dispatch`/`authorize` still
honour `on_block`, because there the kernel gates execution itself.

**3. `AuthorizedCall.tool`/`.args` self-dispatch — REAL, and NOT fixable
in-library.** A caller that passes `.tool`/`.args` to its own dispatcher
executes without redeeming the lease: no single-use check, no evidence, and the
action can run twice. The caller holds the data; a library cannot stop it
calling its own function with values it already has. This is the same boundary
`kernel/mediation.py` documents for the kernel as a whole, and the mitigation
is the same — a resource-side execution lease (`mint_lease`). **Documented
explicitly** at `integrations.py:92`, rather than left implied. What *is*
enforceable is pinned: a refused call yields no `AuthorizedCall` at all, and
`execute_authorized` is single-use
(`test_refused_calls_yield_no_authorized_call`,
`test_execute_authorized_is_single_use`).

---

# PART 2 — BUG B: escalation routing

## What was wrong

From `limits_audit/FINDINGS.md` §3: nothing persisted (`unconfirmed()` empty,
ledger state `denied`), no notification target in `SecurityContext`'s 18
fields, verdict invariant across ten simulated years, 500 retries costing only
ledger growth, and ESCALATE indistinguishable from BLOCK at every caller
boundary.

## What was built

`morrison_governance/escalation.py` (new) + one hook in the kernel.

| Requirement | Implementation | Line |
|---|---|---|
| **1. Persisted, queryable** | `Escalation` record; `InMemoryEscalationStore` (mirrors `InMemoryContinuityStore`), `FileEscalationStore` (append-only JSONL, replayed on load, mirrors `FileContinuityStore`). Query by id, state, principal, tenant. | `escalation.py:81,119,175` |
| **2. Notification** | `EscalationRouter.notifier` — a callable invoked once per newly opened escalation. A webhook is `lambda e: requests.post(url, json=e.as_dict())`; polling via `router.pending()` is documented as the alternative. Chosen over building HTTP in-tree: that adds a dependency and a failure mode without adding a capability. A notifier that raises is recorded in `notify_failures` and **cannot change the verdict**. | `escalation.py:259` |
| **3. Timeout + default** | `ttl_s` (default 3600s) and `on_timeout`, **default `"block"`**. `sweep()` applies it; `outcome()` sweeps then reports. | `escalation.py:74,265,267` |
| Kernel hook | `GovernanceKernel(..., escalation_router=...)`; routed at the ESCALATE filing site, failure-isolated. `Decision.escalation` surfaces it. | `gate.py:311,318,1204,179` |

### Why BLOCK on timeout — stated explicitly

ESCALATE means "not authorised yet". If nobody answers, the request has not
become authorised, it has only aged. Auto-approving on timeout would make the
timeout itself the bypass: an agent could obtain any escalated action by
waiting, which is worse than the original gap because it looks like governance.
`on_timeout="escalate"` is offered for deployments that prefer an expired
request to stay open for review rather than be closed against the requester.

## Proof — `morrison_governance/test_escalation_routing.py`, 13 tests

The four scenarios demanded, in order:

1. **`test_escalate_is_persisted_and_queryable`** — ESCALATE on a $4.5M
   transfer; `router.pending()` returns it, queryable by id and by principal,
   `semantic_hash` matches the decision, `expires_at == created + ttl`, and
   `decision.as_dict()["escalation"]["id"]` carries it to the caller.
2. **`test_timeout_with_no_response_blocks_by_default`** — PENDING at t+0,
   PENDING at t+599, **EXPIRED at t+601**, `resolved_by="timeout"`, and the
   expired request no longer appears in `pending()`.
3. **`test_reviewer_approval_lets_the_original_action_proceed`** — ESCALATE →
   `execute` refused, 0 side effects → `router.approve(...)` at t+100 → re-propose
   with the minted artifact → **PERMIT** → `execute` runs, exactly once.
4. **`test_a_late_approval_cannot_revive_an_expired_request`** — approving
   after the timeout raises `ValueError: ... expired ...`; otherwise the
   timeout would be decorative.

Plus: `test_a_retrying_agent_does_not_flood_the_reviewer` (500 retries → **one**
review), `test_escalations_survive_a_restart` (JSONL replayed by a second
router), `test_a_broken_notifier_cannot_change_the_verdict`,
`test_reviewer_denial_keeps_the_action_refused`,
`test_the_approval_is_the_ordinary_artifact_not_a_second_authority` (wrong key
and untrusted issuer both refused by the existing trust boundary), and
`test_a_kernel_without_a_router_behaves_exactly_as_before`.

```
morrison_governance/test_escalation_routing.py ............. 13 passed
```

**The router mints no new authority.** `approve()` returns the ordinary
`ApprovalArtifact` the kernel already verifies — HMAC over the semantic action
hash, issuer checked against `trusted_issuers`, single-use nonce, TTL.

---

# Two bugs I introduced and had to fix

Reported as they happened, not after a second pass.

**1. Proxy lost its `__call__` fallback.** My rewrite resolved `__call__` via
`self._tool.__call__`, which a `BaseTool` does not have, so
`test_frozen_tool_proxy_still_governs_direct_call` failed with
`TypeError: 'delete_database' is not callable`. Fixed by falling back to the
tool's first execution-capable attribute — what the previous proxy was
constructed with.

**2. Notifier paged on every retry.** `route()` decided "first sighting" by
comparing `opened.created_at == now`, and five retries at the same model
instant all matched: `test_a_reviewer_is_notified_once_per_escalation` failed
`assert 5 == 1`. Fixed to key off `existing is None` from the store lookup.

A third failure, `test_governed_tool_still_permits_a_benign_action`, was my
**test's** bug — `get_data` was not in the manifest, so it escalated on the
undeclared-tool rule rather than on anything the fix touched. Manifest
corrected; no production change.

---

# Regressions

**One, in an existing test, caused deliberately by finding 2's fix.**
`test_integrations.py::test_browser_action_guard` asserted that
`browser_action_guard` under `on_block="deny"` returns a non-permitted
Decision. That behaviour is the bypass. The test now asserts `GovernanceError`,
with the contract change recorded in its docstring; the case's intent — a
dangerous browser action must not be permitted — is unchanged and enforced
more strongly.

**Nothing else.** 1123 → 1150 passed, 1 skipped both sides.

Control Room (`resurrection-tech-enterprise/governance-service`): **58 passed,
1 failed**, the same pre-existing environmental failure
(`test_govern_timing`, `read_file` undeclared in this checkout's manifest)
present before any of this work.

---

# Runnable commands for every claim

```bash
# PART 1 — exact scenario, before and after
ENGINE=<worktree-at-29b80e2> python3 limits_audit/part1_exact_scenario.py
ENGINE=$(pwd)               python3 limits_audit/part1_exact_scenario.py

# PART 1 — the 23 GO vectors
python3 limits_audit/test_4_peer_go_message.py

# BUG A
python3 -m pytest morrison_governance/test_langchain_proxy_governance.py -q

# BUG B
python3 -m pytest morrison_governance/test_escalation_routing.py -q

# Full suite (baseline comparison needs the same env var)
MORRISON_SERVICE_PATH=/path/to/governance-service \
  python3 -m pytest morrison_governance/ global_governance/ runtime_eval/ audit/ -q
```
