# Deploying Morrison Runtime Governance in real agent stacks

`morrison_governance.integrations` provides fail-closed, dependency-free
adapters. None of these imports pull in the host framework — they duck-type
the framework's native shapes — so the module is safe to import anywhere.

Common setup:

```python
from morrison_governance import (
    GovernanceLayer, OmegaDomain, GovernanceGuard,
)

gov = GovernanceLayer(
    domains=[OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE,
             OmegaDomain.DATA_PRIVACY],
    admissibility_checks=None,                 # opt into V4 if you have a role model
    internal_email_domains=("yourco.com",),    # taint allowlist
    internal_url_hosts=("intranet.yourco.com",),
    log_all=True,
)
guard = GovernanceGuard(gov, on_block="raise") # or "deny" to branch yourself
```

`on_block="raise"` throws `GovernanceError` (recommended for middleware).
`on_block="deny"` returns the `GovernanceResult` so you can answer the model
with a tool error instead of aborting the turn.

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

Use `openai_partition_tool_calls(guard, tool_calls)` if you want
`(allowed, denied)` and to handle them separately.

## Claude tool-use chains

```python
from morrison_governance import claude_filter_tool_use

msg = client.messages.create(model=..., tools=..., messages=history)
allowed, denied_results = claude_filter_tool_use(guard, msg.content)

# execute `allowed`, then send denied_results straight back as tool_result
history.append({"role": "user", "content": denied_results + executed_results})
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
    browser_action_guard(guard, action, target, value)  # raises if unsafe
    return driver.perform(action, target, value)
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

# whole-plan gate up front — the V2 taint analysis sees the full DAG
wg.submit(workflow_steps)

# or stream with history so a late exfil step is caught vs early reads
history = []
for step in workflow_steps:
    wg.step_gate(step, history=history)   # raises if unsafe in context
    run(step); history.append(step)
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
  verdicts (CI-stable). See `LIMITATIONS.md` for residual gaps
  (tool-name spoofing, keyword obfuscation).
- **Audit hook.** Pass `GovernanceGuard(gov, audit=fn)` to receive every
  `GovernanceResult` for logging/SIEM regardless of verdict.

## Reproduction

```
python3 morrison_governance/test_integrations.py     # 13 adapter tests
python3 morrison_governance/demo_integrations.py      # runnable walk-through
```
