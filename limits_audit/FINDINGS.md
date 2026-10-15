# Limits Audit — Findings

Probes run against the repository at commit `d3f1f0c`, Python 3.11.15.
Every result below was produced by executing `limits_audit/test_{1,2,3}.py`
against the real `GovernanceKernel`. The existing suites
(`test_integrations.py`, `test_authorization_containment.py`,
`test_mediation.py` — 73 tests) pass unchanged; none of the findings below is
a regression, and none is covered by an existing test.

---

## 1. CONTAINMENT — **real, and partially acknowledged in-tree**

### (a) What the code does

The kernel is a genuine choke point *for callers that go through it*.
`GovernanceKernel.execute` (`morrison_governance/kernel/gate.py:1204`) will not
run an executor unless the decision is PERMIT, unspent, unexpired, unrevoked,
issued to this principal in this session under the ruleset still in force, and
the re-derived action hash matches the authorised hash. Probe 1.2 confirms the
hash binding: authorizing `get_data` and redeeming against `delete_database`
is refused with zero side effects. `GovernanceGuard` refuses to construct
without a `SecurityContext` (`integrations.py:169-177`), and an advisory guard
raises `GovernanceConfigurationError` from every execution-capable entry point
(probe 1.6).

### (b) Ungoverned paths that exist in the current code

Four, demonstrated executing unchecked:

**1. `_CallableToolProxy.__getattr__` returns the raw tool** — `integrations.py:542`

```python
def __getattr__(self, item):
    return getattr(self._tool, item)
```

`govern_langchain_tool` falls back to this proxy when the tool refuses
attribute assignment — the pydantic v2 case it was specifically written for
(`integrations.py:497-499`). The proxy governs `__call__` only. Every other
attribute, **including `run`, `invoke` and `_run`**, is delegated to the
unwrapped tool. Probe 1.4:

```
adapter returned: _CallableToolProxy
proxy(...)          -> blocked by governance  [the governed path]
proxy.func   (...)  -> RAN — UNGOVERNED   effects=1 new_evidence=0
proxy._run   (...)  -> RAN — UNGOVERNED   effects=1 new_evidence=0
proxy.run    (...)  -> RAN — UNGOVERNED   effects=1 new_evidence=0
proxy.invoke (...)  -> RAN — UNGOVERNED   effects=1 new_evidence=0
```

This is the most serious of the four: a LangChain `AgentExecutor` calls tools
as `tool.run(...)` / `tool.invoke(...)`, not by calling the tool object. A
deployment that wraps a pydantic v2 tool gets an object that *looks* governed
and is not, on the exact attribute the agent loop uses. `new_evidence=0` — the
execution leaves no trace in the hash chain either.

**2. `govern_langchain_tool` wraps only the first matching attribute** —
`integrations.py:485-500`. The loop `for attr in ("func","_run","run","invoke")`
wraps the first callable it finds and returns. Probe 1.3, on a duck-typed tool
of the shape the docstring advertises support for:

```
wrapped.func   (...) -> blocked by governance
wrapped._run   (...) -> RAN — UNGOVERNED
wrapped.run    (...) -> RAN — UNGOVERNED
wrapped.invoke (...) -> RAN — UNGOVERNED
```

Scope note, stated plainly: in genuine LangChain `BaseTool`/`StructuredTool`,
`invoke` → `run` → `_run` → `func`, so wrapping `func` does transitively cover
them. This finding bites duck-typed and custom tool objects, which the adapter
explicitly supports ("Works with objects exposing `.name` and one of
`func` / `_run` / `run` / `invoke`"), not stock LangChain classes.

**3. Three adapters return a verdict and never execute** —
`mcp_guard_call_tool` (`:661`), `autogen_guard_function_call` (`:577`),
`browser_action_guard` (`:636`). The executor is the caller's, outside the
kernel. Probe 1.5:

```
mcp_guard_call_tool          on_block=deny  effects=1 | verdict=ESCALATE returned, caller executed anyway
mcp_guard_call_tool          on_block=raise effects=0 | GovernanceError raised before the handler body
```

Both of these adapters' own docstrings say so ("a hook that only inspects the
verdict and then calls the function itself is an ungoverned path"). Under the
**default** `on_block="raise"` an exception stops the handler, so the
enforcement is real but is carried by an exception the caller can catch, not
by a structural choke point. Under `on_block="deny"` — a supported, documented
setting — the refusal is advisory.

**4. `AuthorizedCall` exposes `.tool` / `.args`** — `integrations.py:106-111`.
The docstring for `openai_partition_tool_calls` states that returning
`AuthorizedCall` objects means "partition then execute the allowed list
yourself is no longer an ungoverned path". For a **refused** call that holds:
nothing is handed back. For a **permitted** call it does not:

```
caller self-dispatched from ac.tool/ac.args -> evidence delta=0
lease still redeemable afterwards -> True
total executions of the same authorization: 2
```

The "exactly once" property is enforced on the redemption path only, not on the
data the adapter hands back. Lower severity than the others — the action was
permitted anyway — but the single-use lease and the evidence record are both
skipped.

### (c) The structural limitation, which the repo states itself

`kernel/mediation.py:1-55` is explicit and correct: the kernel is a *library*,
so "its authority is exactly as complete as the caller's discipline." A second
SDK, raw HTTP, or a credential the agent holds directly executes unseen.
Execution leases move the check to the resource side, but only for resources
that verify them. `test_authorization_containment.py:241`
(`test_d2_containment_holds_while_a_prohibited_effect_occurs`) demonstrates a
prohibited disclosure occurring with every kernel-side containment check
passing, and the repo keeps that test *because* it succeeds.

**Verdict: the limitation is real.** There is no ungoverned branch *inside*
`GovernanceKernel.execute`, and the hash/lease binding holds. But four
concrete routes to unchecked tool execution exist in the adapter layer today,
one of them (`_CallableToolProxy`) on the default path for the most common
real-world LangChain tool shape. The broader "a library cannot mediate what
does not call it" limit is stated accurately in-tree and is not overclaimed.

---

## 2. COVERAGE — **the limitation as described is mostly NOT present; the real gap is elsewhere**

### (a) What the governor checks

There is **no tool registry** in this codebase, so "a registered tool not
wired into the check" is not the right shape for the gap. The governor
classifies *actions into capabilities*, from tool-name morphology, argument
shape, argument values, and nested/embedded payloads
(`kernel/capabilities.py:171`). 15 canonical capabilities, all 15 mapped to a
policy (`kernel/policy.py:31-52`):

| policy | capabilities |
|---|---|
| `deny` | `log.tamper` |
| `approval` | `agent.delegate`, `backup.destructive`, `code.execute`, `credential.change`, `credential.read`, `data.destructive`, `iam.privileged`, `infra.destructive`, `payment.move_funds`, `persistence.establish`, `scope.wildcard`, `security_control.modify` |
| `allow` | `data.external_move`, `data.read` |

Unmapped capabilities: **none**.

Undeclared tools fail closed. `SecurityContext.tool_manifest` is
**additive only** — declaring `delete_database` with `capabilities=[]` still
classifies it `data.destructive` and escalates (probe 2.3), so a careless or
malicious manifest is not a bypass. Unmapped browser actions
(`drag`, `press_key`, `set_cookie`, `print_page`) all reach the kernel as
`browser_<action>` and escalate via the undeclared-tool rule (probe 2.5).

### (b) The interfaces that ARE and ARE NOT wired in

Probe 2.2, every public entry point in `integrations.py`, driven with an action
the kernel escalates:

**Kernel is the caller of the executor (9):** `GovernanceGuard.dispatch`,
`governed_run`, `openai_guarded_dispatch`, `claude_guarded_dispatch`,
`browser_guarded_action`, `WorkflowGovernor.run`, `wrap_mcp_call_tool`,
`govern_langchain_tool`, `register_autogen_guard`. All 9: **0 side effects.**

**Verdict-only — caller executes (5):** `mcp_guard_call_tool`,
`autogen_guard_function_call`, `browser_action_guard` (1 side effect each
under `on_block="deny"`), `openai_partition_tool_calls`,
`claude_filter_tool_use` (0 here only because the refused call yields no
`AuthorizedCall`; see finding 1(b)4).

**Advisory by documented design (4):** `check_plan` / `WorkflowGovernor.submit`,
`GovernanceGuard.allow`, `GovernanceGuard.preview`,
`GovernanceCallbackHandler.on_tool_start`. `GovernanceLayer.evaluate` is
reachable directly and returns `.permitted` — 1 side effect when a caller
branches on it.

### (c) The one real configuration gap

`unknown_tool_policy="permit"` (`gate.py:929-937`) is a supported value that
turns the undeclared-tool check off entirely:

```
unknown_tool_policy=escalate  -> ESCALATE  layer=unknown_tool
unknown_tool_policy=block     -> BLOCK     layer=unknown_tool
unknown_tool_policy=permit    -> PERMIT    layer=V4
```

A completely novel tool then reaches PERMIT on the capability path alone.
The default is `escalate`, and `gate.py:922-928` records that the previous
`if self.ctx.tool_manifest:` guard — which made the rule silently inert for
unconfigured deployments — was deliberately removed.

**Verdict: not present as described.** There is no registered-but-ungoverned
tool, because there is no registry and classification is semantic rather than
name-based. The genuine coverage gap is the *adapter* split in 2(b) —
5 of 18 entry points return a verdict rather than enforcing one — which is the
same finding as §1, not an independent one.

---

## 3. ESCALATION HANDLING — **real, and unambiguous**

### (a) What the code does

`ESCALATE` is a **synchronous refusal**. `Decision.permitted` is
`verdict == PERMIT` (`gate.py:224`), so `execute()` refuses in 0.33 ms
(probe 3.2) with zero side effects. Nothing waits, nothing blocks, nothing is
suspended.

There is no escalation *workflow* of any kind:

- **No queue.** `kernel.unconfirmed() == []`, ledger state is `denied`.
  ESCALATE does not reserve a trajectory slot (`gate.py:1186`). The only
  durable artefact is an append-only evidence record (probe 3.3).
- **No notification.** `grep` for `pending_approval|approval_queue|await_approval|request_approval|human_review` over `morrison_governance/` returns nothing. `SecurityContext` has 18 fields; none is a reviewer, webhook, or callback (probe 3.8).
- **No timeout, and no default if nobody answers.** The verdict is invariant in elapsed time (probe 3.4):

```
t+0    -> ESCALATE   t+1d   -> ESCALATE   t+1y   -> ESCALATE
t+1h   -> ESCALATE   t+30d  -> ESCALATE   t+10y  -> ESCALATE
```

  No auto-approve, no escalate-to-block, no expiry of the request itself.
- **No rate limit on a never-answered retry.** 500 authorize+execute rounds:
  500 ESCALATE, 0 side effects, 1002 ledger entries, 1000 evidence records,
  0 reservations held against a cap of 64 (probe 3.5). Because ESCALATE does
  not reserve, retries never trip the cap. Unbounded ledger and evidence-chain
  growth is the only consequence.

### (b) The one clock that exists

The only exit from ESCALATE is a signed `ApprovalArtifact` installed in the
**trusted context** — `SecurityContext.approvals`. A caller cannot supply one
in the call args; probe 3.6 shows that attempt returning ESCALATE, and the same
artifact in `SecurityContext` returning PERMIT and executing. It is single-use
(nonce), bound to the semantic action hash, issuer-checked, and carries a
**300-second default TTL** (`trust.py:335`). Probe 3.7 confirms expired
artifacts, untrusted issuers, and an approval for a $100 transfer replayed
against $4.5M are all refused.

That TTL bounds **how long an answer stays valid**. It does not bound the wait
for one. It is the only clock anywhere near escalation.

### (c) Where it lands for a caller

At every caller-facing boundary, ESCALATE is handled identically to BLOCK
(probe 3.9): `on_block="raise"` raises `GovernanceError`, `on_block="deny"`
returns `executed=False`. A calling agent cannot distinguish "ask a human" from
"never allowed" without reading `.verdict` or `.escalated` itself.

**Verdict: the limitation is real, and the "waits indefinitely" framing is
too generous.** The system does not wait — it refuses immediately and forgets.
The human-in-the-loop step is entirely out of band: some external service must
notice the evidence record, obtain a human decision, mint an HMAC artifact, and
install it in the context within its TTL. None of that machinery exists in this
repository, and there is no interface for it beyond `SecurityContext.approvals`.
A deployment that reads "ESCALATE" as "a human will be asked" would be wrong;
in the code as written, ESCALATE means "refused, pending an approval artifact
that nothing in this system will ever go and get."
