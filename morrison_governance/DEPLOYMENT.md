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
- **Decisions are single-use leases.** A PERMIT carries a decision id, exact and
  semantic action hashes, authorization identity, session, principal, tenant,
  ruleset hash and expiry. `execute()` compares the whole binding to its stored
  reservation and consumes
  it atomically; reuse, expiry, a changed ruleset, a foreign session, or a
  subsequent BLOCK on the same transition all refuse it. Release what you do
  not execute with `guard.release(decision)`.
- **Approvals are single-use and context-bound.** The signature covers the
  authorization action, principal, tenant, issuance window, and mandatory
  strong nonce. Broad tool families do not share authority. Deployments may
  configure explicit authorization equivalences; that registry participates in
  the ruleset hash and changes invalidate outstanding decisions.
- **Policy changes take effect.** After mutating `ctx.policy_values`, call
  `kernel.refresh_ruleset()`; outstanding decisions issued under the old
  ruleset are then refused at execute.
- **Audit hook.** Pass `GovernanceGuard(gov, security_context=ctx, audit=fn)`
  to receive every `Decision` for logging/SIEM regardless of verdict.

## Resource-side enforcement

**Argument classification is defence in depth. The guarantee is what the
executor's credentials can do.** The kernel decides from the *text* of a
proposed call; the resource decides what that text *does*. Those can differ,
and when they do the resource wins.

The external review that found `SQL-LEX-01` (see
[`VIOLATION_LEDGER.md`](../runtime_eval/results/VIOLATION_LEDGER.md)) showed
this directly: a tool declared `data.read` was PERMITTED to run
`DROP/**/TABLE customers`, `TRUNCATE customers` and
`UPDATE accounts SET balance=0`, because SQL was matched by a regular
expression. SQL, shell commands, file paths and URLs are now read structurally
(`kernel/sql.py`, `kernel/shell.py`, `kernel/paths.py`,
`kernel/destinations.py`): SQL is tokenised under five dialects with comments
removed and every statement classified, the strictest deciding; anything
dynamic or unparseable escalates. That closes the reported cases. It does not
make text classification a guarantee, and it cannot:

- a `SELECT` can call a user-defined function that writes, deletes or calls
  out; no text classifier can know what `SELECT archive_old_rows()` does;
- a view, trigger or rule on the server can turn a read into a write;
- a dialect, driver or client that reads the same bytes differently from the
  five modelled dialects (or from the two URL parsers modelled) is a new
  parser differential;
- a program not in the shell allowlist is escalated as `code.execute`, but a
  program *in* it can still be pointed at something it should not touch;
- the credential-path table is a list, and lists are incomplete.

So a deployment must make the resource enforce the same intent:

| Tool declared as | Resource-side control that makes the declaration true |
|---|---|
| `data.read` over SQL | A database role with `SELECT` only (PostgreSQL: `default_transaction_read_only = on` for the role, no `CREATE`/`TEMP`, `REVOKE EXECUTE ON ALL FUNCTIONS` except an allowlist; MySQL: `GRANT SELECT` only, no `FILE`/`SUPER`/`PROCESS`); or a read replica the executor cannot write to |
| Any SQL tool | Disable multi-statement execution in the driver; never let the agent hold DDL, `GRANT`, `COPY ... PROGRAM`, `xp_cmdshell`, `LOAD_FILE` or `INTO OUTFILE` rights |
| File reads | The executor's OS identity cannot read credential stores (`~/.ssh`, `~/.aws`, `/etc/shadow`, `/proc/*/environ`, mounted secrets); a read-only bind mount of the working tree |
| Shell | No shell tool where possible; otherwise a sandbox (container/VM, read-only root, no network, seccomp) where the executor has no destructive privileges to misuse |
| Egress | A forward proxy that enforces the same host allowlist as `internal_url_hosts`, resolving the URL itself, so a parser differential cannot reach a host the kernel judged internal |

When the two layers disagree, the resource-side control is the one that
holds. The kernel's job is to refuse early, explain why, record evidence, and
govern trajectories the resource cannot see; it is not a substitute for least
privilege.

## Complete mediation checklist

Every Morrison guarantee assumes **every consequential effect passes through
`GovernanceKernel`**. The kernel cannot make that true; the deployment must.
The full analysis (conditions M1–M7, what the library can and cannot enforce)
is in [`docs/research/COMPLETE_MEDIATION_ANALYSIS.md`](../docs/research/COMPLETE_MEDIATION_ANALYSIS.md).
This is the short form. An unchecked box is an ungoverned path.

**Credentials (M1)**
- [ ] The agent process holds **no** credential for a consequential resource:
      no API keys, database URLs or cloud tokens in its environment, files,
      prompt, tool configuration or memory. Credentials live only in the
      executor (tool server, gateway, sidecar) the agent must ask.
- [ ] The agent's identity cannot read credential stores (`~/.aws`, `~/.ssh`,
      `~/.kube`, `~/.docker`, `~/.netrc`, `~/.pgpass`, `/proc/*/environ`,
      mounted secrets) and cannot reach the cloud metadata service
      (`169.254.169.254`, `metadata.google.internal`), which issues role
      credentials to anything that asks. Block it at the network layer, or
      require IMDSv2 with hop limit 1.
- [ ] Credentials the executor holds are least-privilege for what the tool
      manifest declares (a `data.read` tool gets a read-only database role; see
      "Resource-side enforcement").

**Resource-side checks (M2, M3)**
- [ ] Each consequential resource refuses requests that do not carry a valid
      Morrison execution lease (`kernel.mint_lease` +
      `mediation.LeaseVerifier` at the gateway), verified by the resource, not
      by the caller.
- [ ] Lease registry is shared and atomic across verifiers, so a lease is
      single-use deployment-wide.

**Network egress (M4)**
- [ ] Egress from the agent's network position is default-deny. The only
      allowed destinations are the governed executors and a forward proxy
      that enforces the same host allowlist as `internal_url_hosts` and
      resolves URLs itself (closing parser differentials).
- [ ] DNS is restricted to the proxy's resolver (no DNS exfiltration channel).

**Shell and code execution (M4)**
- [ ] No general shell tool, where possible. Where one is needed, every spawn
      goes through `governed_run` (or a governed wrapper), and the process runs
      in a sandbox (container/VM, read-only root, no network, seccomp, no
      credentials, non-root) where its privileges, not its arguments, bound
      the damage.
- [ ] The agent cannot install packages, write to its own code, or load
      plugins at run time.

**MCP and tool frameworks (M2, M5)**
- [ ] Every MCP server the agent can reach is behind `wrap_mcp_call_tool` or a
      Morrison gateway; no MCP server is configured directly in the agent's
      client.
- [ ] Every tool in the framework's registry is a Morrison-governed wrapper
      (`mediation_selftest.audit_tools(registry)` checks this), including
      `run`/`invoke`/`_run` aliases.
- [ ] The inventory of consequential resources and tools is maintained;
      a new tool is ungoverned until it is added to the manifest.

**Configuration integrity (M6) and reconciliation (M7)**
- [ ] The agent cannot write the policy, tool manifest, allowlists, approval
      keys or continuity store.
- [ ] The deployment reconciles effects observed at each resource against
      Morrison's evidence chain (execution-intent and outcome records); an
      effect with no decision is an incident. The library's
      `kernel.reconcile` settles only Morrison's own unconfirmed dispatches,
      not effects it never saw.

### Self-test

Run from **where the agent runs** (same container, OS identity, environment
and network position):

```bash
python -m morrison_governance.mediation_selftest --network \
    --egress-probe example.com:443 \
    --governance-path /etc/morrison \
    --mcp-gateway morrison-gateway.internal \
    --resource-probe https://db-gateway.internal/mutate-dry-run
```

It reports FAIL for secret-shaped environment variables (names only; values are
never read), readable credential files, a reachable metadata service, direct
egress that bypasses the proxy, writable governance files, and a resource that
accepts a request without a lease; WARN for an available shell and for MCP
servers not routed through the gateway. In Python, `audit_tools(registry)`
flags tools that are not governed wrappers. Exit status 0 / 1 (FAIL) / 2 (WARN
only).

A pass means no **obvious** bypass is visible from that process. It does not
establish complete mediation: it cannot see credentials baked into a tool's
own configuration, sockets inherited from a parent process, other processes in
the same network namespace, or what an executor does after a valid lease.
Point `--resource-probe` only at an endpoint where accepting the request is
harmless.

## Reproduction

```
python3 -m pytest morrison_governance/test_integrations.py -q          # adapter suite
python3 -m pytest morrison_governance/test_governed_execution_veto.py -q  # adversarial acceptance suite
python3 morrison_governance/demo_integrations.py                      # runnable walk-through
```

## Exported authority migration

Detached mrl2 leases require external Ed25519 signing, actual request binding
and a shared atomic issuer/redemption registry. Use `LeaseVerifier.execute()`
to verify and dispatch the same snapshot. See
[lease migration](../docs/security/lease-v2-migration.md) for compatibility,
continuity and deployment scope.
