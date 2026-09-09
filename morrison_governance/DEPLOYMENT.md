# Deploying Morrison Runtime Governance in real agent stacks

`morrison_governance.integrations` provides fail-closed, dependency-free
adapters. None of these imports pull in the host framework — they duck-type
the framework's native shapes — so the module is safe to import anywhere.

## Two objects, one authority

| | `GovernanceLayer` | `GovernanceKernel` |
|---|---|---|
| Role | reasoning / policy evaluation | **the veto authority** |
| Answers | "does this trajectory reach Ω?" | "may this transition execute, now, here?" |
| Holds | rules | trust boundary, capability policy, trusted destinations, approvals, session trajectory, evidence chain |
| Use for | planning, shadow mode, analysis | **everything that can execute** |

Nothing in this module dispatches on a `GovernanceLayer` verdict.
`GovernanceGuard` requires a `SecurityContext`, builds a kernel from it, and
every adapter executes inside `kernel.execute()`. A guard constructed without
one raises `GovernanceConfigurationError` rather than becoming a silently
weaker guard — that configuration is what let eight of ten catastrophic actions
reach the executor before it was fixed, and it is now an error at the
integration point.

## Common setup

```python
import os
from morrison_governance import GovernanceLayer, OmegaDomain, GovernanceGuard
from morrison_governance.kernel import Principal, SecurityContext

gov = GovernanceLayer(
    domains=[OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE,
             OmegaDomain.DATA_PRIVACY],
    admissibility_checks=None,                 # opt into V4 if you have a role model
    internal_email_domains=("yourco.com",),    # taint allowlist
    internal_url_hosts=("intranet.yourco.com",),
    log_all=True,
)

# The trust boundary. Built from AUTHENTICATED SESSION STATE and deployment
# configuration — never from anything a tool call can write.
ctx = SecurityContext(
    principal=Principal(id=session.agent_id, tenant=session.tenant),
    signing_key=os.environb[b"GOVERNANCE_APPROVAL_KEY"],
    trusted_issuers=frozenset({"security-review"}),
    internal_url_hosts=("intranet.yourco.com",),
    internal_email_domains=("yourco.com",),
    internal_cidrs=("10.0.0.0/8",),            # see "Destinations" below
    tool_manifest=TOOL_MANIFEST,               # tool -> [capability, ...]
    unknown_tool_policy="escalate",            # or "block"
)

guard = GovernanceGuard(gov, security_context=ctx, on_block="raise")
```

`on_block="raise"` throws `GovernanceError` (recommended for middleware).
`on_block="deny"` returns the `Decision` so you can answer the model
with a tool error instead of aborting the turn.

**One guard is one session.** The kernel holds that session's trajectory, so
build a guard per agent session, not one per process. A decision minted in one
session cannot be redeemed in another.

### Analysis without enforcement

```python
advisory = GovernanceGuard.advisory(gov)     # no SecurityContext, cannot execute
advisory.check_plan(steps)                   # reasoning: fine
advisory.dispatch(...)                       # raises GovernanceConfigurationError
```

Use this for shadow mode, dashboards and offline scoring. It cannot be wired in
front of a real executor by accident.

### Destinations

`internal` is a trust fact, not a network fact. Loopback and RFC1918 addresses
are **not** internal unless you declare them in `internal_cidrs` /
`internal_url_hosts`, because an attacker-controlled collector on the agent's
own VPC is the ordinary shape of a real exfiltration. Set
`trust_private_networks=True` only if you cannot enumerate your ranges yet.
Link-local addresses and cloud instance-metadata endpoints
(`169.254.169.254`, `metadata.google.internal`, …) are refused under every
configuration.

---

## OpenAI tool calling

```python
from morrison_governance import openai_guarded_dispatch

resp = client.chat.completions.create(model=..., tools=..., messages=msgs)
tool_calls = resp.choices[0].message.tool_calls

tool_messages = openai_guarded_dispatch(
    guard, tool_calls,
    dispatch=lambda name, args: TOOLS[name](**args),
)
msgs += tool_messages   # blocked calls become an error tool message
```

A parallel batch is ONE trajectory. Each call is authorised in order and a
PERMIT reserves its place in the session before the next call is decided, so a
read and its exfiltration issued together are not both dispatched. Independent
parallel calls are unaffected.

Use `openai_partition_tool_calls(guard, tool_calls)` for
`(authorized, denied)`. `authorized` holds `AuthorizedCall` objects carrying a
single-use lease — redeem each with `guard.execute_authorized(ac, executor)`
rather than dispatching it yourself:

```python
authorized, denied = openai_partition_tool_calls(guard, tool_calls)
for ac in authorized:
    ok, out = guard.execute_authorized(ac, lambda call: TOOLS[call["tool"]](**call["args"]))
```

## Claude tool-use chains

```python
from morrison_governance import claude_filter_tool_use

msg = client.messages.create(model=..., tools=..., messages=history)

# One call does both halves:
results = claude_guarded_dispatch(
    guard, msg.content, dispatch=lambda name, args: TOOLS[name](**args))
history.append({"role": "user", "content": results})

# Or split them, then redeem each authorisation through the kernel:
authorized, denied_results = claude_filter_tool_use(guard, msg.content)
for ac in authorized:
    ok, out = guard.execute_authorized(ac, lambda call: TOOLS[call["tool"]](**call["args"]))
```

## LangChain

```python
from morrison_governance import (
    govern_langchain_tool, GovernanceCallbackHandler,
)

safe_tools = [govern_langchain_tool(guard, t) for t in tools]
agent = create_react_agent(llm, safe_tools, prompt)

# or gate via callbacks without wrapping tools:
agent.invoke(inputs, config={"callbacks": [GovernanceCallbackHandler(guard)]})
```

## AutoGen

```python
from morrison_governance import register_autogen_guard

assistant = ConversableAgent("assistant", llm_config=...)
register_function(my_tool, caller=assistant, executor=user, name="my_tool")
register_autogen_guard(user, guard)   # wraps user.function_map in place
```

Or gate manually inside an execution hook with
`autogen_guard_function_call(guard, name, arguments)`.

## Browser agents

```python
from morrison_governance import browser_action_guard

def step(action, target="", value=None):
    # The kernel performs the action as the executor of its own decision.
    _, performed, out = browser_guarded_action(
        guard, action, lambda call: driver.perform(action, target, value),
        target=target, value=value)
    return out
```

Browser actions are mapped onto governable tools (`download`→source,
`submit`/`upload`→egress, `execute_js`→exec) so Ω rules and V2 taint apply.

## MCP servers

```python
from morrison_governance import wrap_mcp_call_tool

@server.call_tool()
async def call_tool(name, arguments):
    ...

server._call_tool = wrap_mcp_call_tool(guard, server._call_tool)
```

Supports sync and async handlers. Or call
`mcp_guard_call_tool(guard, name, arguments)` at the top of the handler.

## Shell execution

```python
from morrison_governance import governed_run

# command is evaluated BEFORE any process is spawned
result = governed_run(guard, ["ls", "/data"], capture_output=True, text=True)
```

A blocked command raises `GovernanceError` and never reaches `subprocess`.

## Enterprise workflows (multi-step DAG / pipeline)

```python
from morrison_governance import WorkflowGovernor

wg = WorkflowGovernor(guard)

# REASONING: whole-plan analysis up front — the V2 taint analysis sees the full
# DAG. This authorises nothing.
wg.submit(workflow_steps)

# VETO: authorise and execute each step through the kernel, in order. The
# kernel holds the trajectory, so you no longer pass history yourself.
outcomes = wg.run(workflow_steps, executor=run)
```

---

## Deployment posture

- **Fail closed.** Default `on_block="raise"`. Never wrap adapters in a
  bare `except` that swallows `GovernanceError`.
- **Deny-by-default egress.** With no allowlist configured, any
  acquire→external-sink chain is blocked at V2 (the multi-turn fix). Set
  `internal_email_domains` / `internal_url_hosts` to permit legitimate
  internal flows.
- **Pre-execution only.** Governance gates *before* a tool runs; it does
  not sandbox a tool that has already executed.
- **Determinism.** Adapters add no randomness; identical inputs → identical
  verdicts (CI-stable). Tool-name synonyms and argument encodings are folded to
  one canonical semantic form before policy runs, so `run_shell` cannot execute
  what `shell` is refused. See `LIMITATIONS.md` for residual gaps.
- **Decisions are single-use leases.** A PERMIT carries a decision id, semantic
  action hash, session, principal, ruleset hash and expiry. `execute()` consumes
  it atomically; reuse, expiry, a changed ruleset, a foreign session, or a
  subsequent BLOCK on the same transition all refuse it. Release what you do
  not execute with `guard.release(decision)`.
- **Approvals are single-use and bound to the transition.** The nonce is
  consumed at authorisation, so one approval cannot mint two PERMITs, and the
  binding is to the semantic hash, so respelling the call does not dodge it.
- **Policy changes take effect.** After mutating `ctx.policy_values`, call
  `kernel.refresh_ruleset()`; outstanding decisions issued under the old
  ruleset are then refused at execute.
- **Audit hook.** Pass `GovernanceGuard(gov, security_context=ctx, audit=fn)`
  to receive every `Decision` for logging/SIEM regardless of verdict.

## Reproduction

```
python3 -m pytest morrison_governance/test_integrations.py -q          # adapter suite
python3 -m pytest morrison_governance/test_governed_execution_veto.py -q  # adversarial acceptance suite
python3 morrison_governance/demo_integrations.py                      # runnable walk-through
```
