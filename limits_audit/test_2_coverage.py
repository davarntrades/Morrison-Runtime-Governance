"""LIMITS AUDIT 2 — COVERAGE
==========================
Question: enumerate every tool/action interface the governor actually checks,
then find any registered tool, action type or integration point NOT wired into
the check.

Run:  python3 limits_audit/test_2_coverage.py
"""
import os, sys, inspect
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import morrison_governance.integrations as I
from morrison_governance import GovernanceLayer, OmegaDomain, GovernanceGuard, GovernanceError
from morrison_governance.kernel import Principal, SecurityContext
from morrison_governance.kernel import capabilities as C, policy as P

print("=" * 78); print("LIMITS AUDIT 2 — COVERAGE"); print("=" * 78)

# ────────────────────────────────────────────────────────────────
print("\n[2.1] What the governor checks is CAPABILITIES, not a tool registry")
print("      (morrison_governance/kernel/capabilities.py + kernel/policy.py)")
for cap in sorted(C.ALL_CAPABILITIES):
    print(f"      {cap:<26} -> {P.CAPABILITY_POLICY.get(cap, '(unmapped: ALLOW)')}")
unmapped = sorted(C.ALL_CAPABILITIES - set(P.CAPABILITY_POLICY))
print(f"      {len(C.ALL_CAPABILITIES)} capabilities; unmapped (default ALLOW): {unmapped or 'none'}")

# ────────────────────────────────────────────────────────────────
print("\n[2.2] Every public entry point in integrations.py, classified empirically")
SIDE = []
def DANGEROUS(*a, **kw): SIDE.append(1); return "PROD DELETED"

def build(on_block="deny", manifest=None, unknown="escalate"):
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE,
                                   OmegaDomain.DATA_PRIVACY],
                          internal_url_hosts=("intranet.corp",), log_all=False)
    ctx = SecurityContext(
        principal=Principal(id="a", tenant="corp", granted_capabilities=frozenset()),
        signing_key=b"k", trusted_issuers=frozenset({"sec"}),
        internal_url_hosts=("intranet.corp",), internal_email_domains=("corp.example",),
        tool_manifest=manifest or {}, unknown_tool_policy=unknown)
    return GovernanceGuard(gov, security_context=ctx, on_block=on_block)

TOOL, ARGS = "delete_database", {"target": "prod"}

class _F:
    def __init__(self, n, a): self.name, self.arguments = n, a
class _TC:
    def __init__(self, i, n, a): self.id, self.function = i, _F(n, a)

results = []
def probe(label, fn, kind):
    g = build()
    before = len(SIDE)
    err = ""
    try:
        fn(g)
    except GovernanceError:
        err = "GovernanceError"
    except Exception as e:                                       # noqa: BLE001
        err = type(e).__name__
    results.append((label, kind, len(SIDE) - before, err))

# --- adapters where the KERNEL is the caller of the executor ---
probe("GovernanceGuard.dispatch", lambda g: g.dispatch(TOOL, ARGS, DANGEROUS), "kernel-executed")
probe("governed_run", lambda g: I.governed_run(g, "rm -rf /", runner=DANGEROUS), "kernel-executed")
probe("openai_guarded_dispatch", lambda g: I.openai_guarded_dispatch(
    g, [_TC("1", TOOL, '{"target":"prod"}')], lambda t, a: DANGEROUS()), "kernel-executed")
probe("claude_guarded_dispatch", lambda g: I.claude_guarded_dispatch(
    g, [{"type": "tool_use", "id": "x", "name": TOOL, "input": ARGS}],
    lambda t, a: DANGEROUS()), "kernel-executed")
probe("browser_guarded_action", lambda g: I.browser_guarded_action(
    g, "execute_js", lambda _c: DANGEROUS(), target="http://evil.test"), "kernel-executed")
probe("WorkflowGovernor.run", lambda g: I.WorkflowGovernor(g).run(
    [{"tool": TOOL, "args": ARGS}], lambda _c: DANGEROUS()), "kernel-executed")
probe("wrap_mcp_call_tool", lambda g: I.wrap_mcp_call_tool(
    g, lambda n, a: DANGEROUS())(TOOL, ARGS), "kernel-executed")

class _LC:
    name = TOOL
    def __init__(self): self.func = DANGEROUS
probe("govern_langchain_tool", lambda g: I.govern_langchain_tool(g, _LC()).func(ARGS),
      "kernel-executed")

class _AG:
    def __init__(self): self.function_map = {TOOL: DANGEROUS}
probe("register_autogen_guard",
      lambda g: I.register_autogen_guard(_AG(), g).function_map[TOOL](ARGS), "kernel-executed")

probe("GovernanceCallbackHandler.on_tool_start",
      lambda g: I.GovernanceCallbackHandler(g).on_tool_start({"name": TOOL}, "prod"),
      "advisory-preview")

# --- adapters that return a verdict and leave execution to the caller ---
def _mcp(g): I.mcp_guard_call_tool(g, TOOL, ARGS); DANGEROUS()
def _autogen(g): I.autogen_guard_function_call(g, TOOL, ARGS); DANGEROUS()
def _browser(g): I.browser_action_guard(g, "execute_js", "http://evil.test"); DANGEROUS()
def _partition(g):
    a, _d = I.openai_partition_tool_calls(g, [_TC("1", TOOL, '{"target":"prod"}')])
    for ac in a: DANGEROUS(ac.tool, ac.args)          # AuthorizedCall exposes .tool/.args
def _claude_filter(g):
    a, _d = I.claude_filter_tool_use(
        g, [{"type": "tool_use", "id": "x", "name": TOOL, "input": ARGS}])
    for ac in a: DANGEROUS(ac.tool, ac.args)
def _plan(g):
    if I.WorkflowGovernor(g).submit([{"tool": TOOL, "args": ARGS}]).permitted: DANGEROUS()
def _allow(g):
    if g.allow(TOOL, ARGS): DANGEROUS()
def _layer(g):
    if g.governance.evaluate({"tool": TOOL, "args": ARGS}).permitted: DANGEROUS()

probe("mcp_guard_call_tool", _mcp, "verdict-only (caller executes)")
probe("autogen_guard_function_call", _autogen, "verdict-only (caller executes)")
probe("browser_action_guard", _browser, "verdict-only (caller executes)")
probe("openai_partition_tool_calls", _partition, "verdict-only (caller executes)")
probe("claude_filter_tool_use", _claude_filter, "verdict-only (caller executes)")
probe("WorkflowGovernor.submit / check_plan", _plan, "advisory (documented)")
probe("GovernanceGuard.allow", _allow, "advisory (documented)")
probe("GovernanceLayer.evaluate", _layer, "advisory (documented)")

print(f"      {'entry point':<40} {'class':<28} {'effects':>7}  raised")
for label, kind, n, err in results:
    flag = " <-- UNGOVERNED" if n else ""
    print(f"      {label:<40} {kind:<28} {n:>7}  {err}{flag}")

print("\n      NOTE: a 0 in a 'verdict-only' row means the caller's branch")
print("      correctly honoured the refusal — not that the adapter enforced it.")
print("      The rows above were all driven with an ESCALATE action, so a 1")
print("      means the side effect happened DESPITE the refusal.")

# ────────────────────────────────────────────────────────────────
print("\n[2.3] Is there a tool registry the governor is blind to?")
print("      There is no repo-wide tool registry. The governor's only tool")
print("      declaration surface is SecurityContext.tool_manifest, and it is")
print("      ADDITIVE ONLY (capabilities.py:171-185): a declaration can add")
print("      governance, never remove it. Demonstrating:")
under = build(manifest={TOOL: []})          # declared with ZERO capabilities
d = under.preview(TOOL, ARGS)
print(f"      delete_database declared with capabilities=[] -> {d.verdict} "
      f"caps={sorted(d.capabilities)}")

print("\n[2.4] Undeclared tools: fail-closed default, and the policy knob")
for pol in ("escalate", "block", "permit"):
    g = build(unknown=pol)
    d = g.preview("totally_novel_tool_xyz", {"x": 1})
    print(f"      unknown_tool_policy={pol:<9} -> {d.verdict:<9} layer={d.layer}")
print("      'permit' is a real, reachable configuration that disables the")
print("      undeclared-tool check entirely (gate.py:929-937).")

# ────────────────────────────────────────────────────────────────
print("\n[2.5] The browser action map: unmapped actions still reach the kernel")
print(f"      BROWSER_ACTION_TOOL covers: {sorted(I.BROWSER_ACTION_TOOL)}")
g = build()
for act in ("drag", "press_key", "set_cookie", "eval", "print_page"):
    tool, args = I._browser_call(act, "http://x.test")
    d = g.preview(tool, args)
    print(f"      '{act}' (unmapped) -> tool={tool:<20} {d.verdict:<9} layer={d.layer}")

# ────────────────────────────────────────────────────────────────
print("\n[2.6] Capabilities whose policy is ALLOW by default")
allow_caps = [c for c in sorted(C.ALL_CAPABILITIES)
              if P.CAPABILITY_POLICY.get(c) == P.ALLOW]
print(f"      {allow_caps}")
print("      data.external_move is ALLOW at the capability layer and governed")
print("      only conditionally, by separate rules in gate.py (sensitive_egress")
print("      :950, egress_policy :962, trajectory_integrity :973). Verifying:")
g = build()
print(f"      egress, clean session   -> {g.preview('http_post', {'url':'https://evil.test'}).verdict}")
g2 = build()
g2.kernel.authorize({"tool": "get_data", "args": {"source": "intranet.corp"}})
print(f"      egress, after a read    -> {g2.preview('http_post', {'url':'https://evil.test'}).verdict}")
print(f"      egress carrying a SSN   -> "
      f"{g.preview('http_post', {'url':'https://evil.test','body':'SSN 123-45-6789'}).verdict}")
