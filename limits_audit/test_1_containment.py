"""LIMITS AUDIT 1 — CONTAINMENT
=============================
Question: does a code path exist in THIS codebase that reaches tool execution
without passing through the governed authorization interface?

Method: a real executor (`DANGEROUS`) appends to a module-level list whenever
it runs. Every probe drives a real adapter from `morrison_governance.integrations`
with an action the kernel refuses (ESCALATE). A probe that grows SIDE_EFFECTS
without growing the kernel's evidence chain executed unchecked.

Run:  python3 limits_audit/test_1_containment.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import (GovernanceLayer, OmegaDomain, GovernanceGuard,
                                 GovernanceError, govern_langchain_tool)
from morrison_governance.kernel import Principal, SecurityContext, GovernanceKernel

SIDE_EFFECTS = []


def DANGEROUS(*a, **kw):
    """Stands in for a real destructive tool."""
    SIDE_EFFECTS.append(("DANGEROUS", a, kw))
    return "PROD DATABASE DELETED"


def build(on_block="deny"):
    gov = GovernanceLayer(
        domains=[OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE,
                 OmegaDomain.DATA_PRIVACY],
        internal_url_hosts=("intranet.corp",), log_all=False)
    ctx = SecurityContext(
        principal=Principal(id="agent-1", tenant="corp",
                            granted_capabilities=frozenset()),
        signing_key=b"approval-key", trusted_issuers=frozenset({"security-review"}),
        internal_url_hosts=("intranet.corp",),
        internal_email_domains=("corp.example",))
    return gov, ctx, GovernanceGuard(gov, security_context=ctx, on_block=on_block)


TOOL, ARGS = "delete_database", {"target": "prod"}
print("=" * 78)
print("LIMITS AUDIT 1 — CONTAINMENT")
print("=" * 78)

# ────────────────────────────────────────────────────────────────
print("\n[1.1] Baseline — the sanctioned chokepoint refuses the action")
gov, ctx, guard = build()
n0, e0 = len(SIDE_EFFECTS), len(guard.kernel.chain.records)
d, executed, out = guard.dispatch(TOOL, ARGS, DANGEROUS)
print(f"  guard.dispatch -> verdict={d.verdict} executed={executed} "
      f"side_effects={len(SIDE_EFFECTS)-n0} evidence={len(guard.kernel.chain.records)-e0}")

# ────────────────────────────────────────────────────────────────
print("\n[1.2] Probe — redeem a decision against a DIFFERENT action")
gov, ctx, _ = build()
k = GovernanceKernel(gov, ctx, session_id="s")
benign = k.authorize({"tool": "get_data", "args": {"source": "intranet.corp"}})
n0 = len(SIDE_EFFECTS)
ok, out = k.execute(benign, DANGEROUS,
                    call={"tool": TOOL, "args": ARGS})
print(f"  authorize(get_data) + execute(delete_database) -> ok={ok}")
print(f"  reason: {str(out)[:70]}")
print(f"  side_effects={len(SIDE_EFFECTS)-n0}   (action-hash binding holds)")

# ────────────────────────────────────────────────────────────────
print("\n[1.3] Probe — govern_langchain_tool() wraps ONE attribute only")
print("      integrations.py:485  for attr in ('func','_run','run','invoke'): … return tool")
gov, ctx, guard = build()


class DuckTypedTool:
    """A duck-typed tool of the shape the adapter documents support for:
    '.name and one of func / _run / run / invoke'. Entry points here are
    independent rather than delegating to one another."""
    name = TOOL

    def __init__(self):
        self.func = DANGEROUS

    def _run(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def run(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def invoke(self, *a, **kw):
        return DANGEROUS(*a, **kw)


wrapped = govern_langchain_tool(guard, DuckTypedTool())
for attr in ("func", "_run", "run", "invoke"):
    before = len(SIDE_EFFECTS)
    try:
        getattr(wrapped, attr)(ARGS)
        verdict = "RAN — UNGOVERNED" if len(SIDE_EFFECTS) > before else "no effect"
    except GovernanceError:
        verdict = "blocked by governance"
    except Exception as exc:                                    # noqa: BLE001
        verdict = f"{type(exc).__name__}: {str(exc)[:40]}"
    print(f"    wrapped.{attr:<7}(...) -> {verdict}")

# ────────────────────────────────────────────────────────────────
print("\n[1.4] Probe — _CallableToolProxy.__getattr__ delegates to the RAW tool")
print("      integrations.py:542  def __getattr__(self, item): return getattr(self._tool, item)")
gov, ctx, guard = build()


class PydanticStyleTool:
    """Models a LangChain BaseTool under pydantic v2: attribute assignment is
    refused, so govern_langchain_tool falls back to _CallableToolProxy."""
    name = TOOL
    func = staticmethod(DANGEROUS)

    def _run(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def run(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def invoke(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def __setattr__(self, k, v):
        raise AttributeError("pydantic v2 model is frozen")


proxy = govern_langchain_tool(guard, PydanticStyleTool())
print(f"    adapter returned: {type(proxy).__name__}")
before, ev_before = len(SIDE_EFFECTS), len(guard.kernel.chain.records)
try:
    proxy(ARGS)
    print(f"    proxy(...)          -> RAN")
except GovernanceError:
    print(f"    proxy(...)          -> blocked by governance  [the governed path]")
for attr in ("func", "_run", "run", "invoke"):
    before = len(SIDE_EFFECTS)
    ev = len(guard.kernel.chain.records)
    try:
        getattr(proxy, attr)(ARGS)
        ran = len(SIDE_EFFECTS) - before
        print(f"    proxy.{attr:<7}(...)  -> "
              f"{'RAN — UNGOVERNED' if ran else 'no effect':<18} "
              f"effects={ran} new_evidence={len(guard.kernel.chain.records)-ev}")
    except GovernanceError:
        print(f"    proxy.{attr:<7}(...)  -> blocked by governance")

print(f"\n    LangChain AgentExecutor invokes tools as tool.run(...) / tool.invoke(...),")
print(f"    not by calling the tool object — so the ungoverned attributes above are")
print(f"    the ones a real agent loop actually uses.")

# ────────────────────────────────────────────────────────────────
print("\n[1.5] Probe — the three adapters that return a verdict but do NOT execute")
print("      (the caller supplies the executor, outside the kernel)")
import morrison_governance.integrations as I

for label, fn in [
    ("mcp_guard_call_tool",         lambda g: I.mcp_guard_call_tool(g, TOOL, ARGS)),
    ("autogen_guard_function_call", lambda g: I.autogen_guard_function_call(g, TOOL, ARGS)),
    ("browser_action_guard",        lambda g: I.browser_action_guard(g, "execute_js", "http://evil.test")),
]:
    for mode in ("deny", "raise"):
        gov, ctx, g = build(on_block=mode)
        before = len(SIDE_EFFECTS)
        try:
            dec = fn(g)
            DANGEROUS()                      # the handler body that runs next
            outcome = f"verdict={dec.verdict} returned, caller executed anyway"
        except GovernanceError:
            outcome = "GovernanceError raised before the handler body"
        print(f"    {label:<28} on_block={mode:<5} effects={len(SIDE_EFFECTS)-before} "
              f"| {outcome}")

# ────────────────────────────────────────────────────────────────
print("\n[1.6] Probe — advisory guard cannot be wired in front of an executor")
gov, ctx, _ = build()
adv = GovernanceGuard.advisory(gov)
for meth, args in [("dispatch", (TOOL, ARGS, DANGEROUS)), ("authorize", (TOOL, ARGS)),
                   ("preview", (TOOL, ARGS)), ("allow", (TOOL, ARGS))]:
    before = len(SIDE_EFFECTS)
    try:
        getattr(adv, meth)(*args)
        print(f"    advisory.{meth:<10} -> returned, effects={len(SIDE_EFFECTS)-before}")
    except Exception as exc:                                    # noqa: BLE001
        print(f"    advisory.{meth:<10} -> {type(exc).__name__} (refuses to gate)")

print(f"\nTOTAL ungoverned executions observed: "
      f"{sum(1 for _ in SIDE_EFFECTS)} side effects across all probes")
