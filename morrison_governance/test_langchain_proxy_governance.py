"""BUG A — every execution-capable path on a governed tool must be governed.

`govern_langchain_tool` has two failure modes, both on the path a real
LangChain deployment actually uses:

  1. It wrapped only the FIRST of `func` / `_run` / `run` / `invoke` and
     returned. A duck-typed tool whose entry points do not delegate to one
     another kept the rest raw.

  2. When the tool refuses attribute assignment — a pydantic v2 BaseTool, the
     default since LangChain 0.1 — it fell back to `_CallableToolProxy`, whose
     `__getattr__` returned the UNWRAPPED tool for every attribute. The proxy
     governed `__call__` and nothing else. A LangChain AgentExecutor invokes
     tools as `tool.run(...)` / `tool.invoke(...)`, never by calling the object,
     so the proxy governed exactly the path production does not take.

Both are proven here against a prohibited action, counting real side effects.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import (  # noqa: E402
    GovernanceError, GovernanceGuard, GovernanceLayer, OmegaDomain,
    govern_langchain_tool,
)
from morrison_governance.kernel import Principal, SecurityContext  # noqa: E402

SIDE_EFFECTS: list = []


def DANGEROUS(*a, **kw):
    """Stands in for a real destructive tool."""
    SIDE_EFFECTS.append(("DANGEROUS", a, kw))
    return "PROD DATABASE DELETED"


TOOL = "delete_database"
ARGS = {"target": "prod"}

_SEQ = [0]


@pytest.fixture
def guard():
    _SEQ[0] += 1
    gov = GovernanceLayer(
        domains=[OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE,
                 OmegaDomain.DATA_PRIVACY],
        internal_url_hosts=("intranet.corp",), log_all=False)
    ctx = SecurityContext(
        principal=Principal(id=f"lc-{_SEQ[0]}", tenant="corp",
                            granted_capabilities=frozenset()),
        signing_key=b"approval-key",
        trusted_issuers=frozenset({"security-review"}),
        internal_url_hosts=("intranet.corp",),
        # Both tools are declared, so the undeclared-tool rule is not what
        # decides any case here: the prohibited one must be refused on its own
        # merits and the benign one must be permitted on its own merits.
        tool_manifest={TOOL: [], "get_data": []})
    return GovernanceGuard(gov, security_context=ctx, on_block="deny")


@pytest.fixture(autouse=True)
def _clear():
    SIDE_EFFECTS.clear()
    yield


class MutableDuckTool:
    """A duck-typed tool of the shape the adapter documents support for.
    Entry points are independent rather than delegating to one another."""

    name = TOOL

    def __init__(self):
        self.func = DANGEROUS

    def _run(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def run(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def invoke(self, *a, **kw):
        return DANGEROUS(*a, **kw)


class FrozenPydanticStyleTool:
    """Models a LangChain BaseTool under pydantic v2: attribute assignment is
    refused, so govern_langchain_tool falls back to _CallableToolProxy."""

    name = TOOL
    description = "deletes a database"
    func = staticmethod(DANGEROUS)

    def _run(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def run(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def invoke(self, *a, **kw):
        return DANGEROUS(*a, **kw)

    def dict(self):
        return {"name": self.name}

    def __setattr__(self, k, v):
        raise AttributeError("pydantic v2 model is frozen")


EXECUTION_ATTRS = ["func", "_run", "run", "invoke"]


@pytest.mark.parametrize("attr", EXECUTION_ATTRS)
def test_mutable_tool_every_entry_point_is_governed(guard, attr):
    """Finding 1: only the first matching attribute used to be wrapped."""
    wrapped = govern_langchain_tool(guard, MutableDuckTool())
    with pytest.raises(GovernanceError):
        getattr(wrapped, attr)(ARGS)
    assert SIDE_EFFECTS == [], f".{attr} executed a prohibited action"


@pytest.mark.parametrize("attr", EXECUTION_ATTRS)
def test_frozen_tool_proxy_governs_every_entry_point(guard, attr):
    """Finding 2: the proxy governed __call__ and nothing else.

    This is the one that matters in deployment: an AgentExecutor calls
    `.run(...)` / `.invoke(...)`.
    """
    proxy = govern_langchain_tool(guard, FrozenPydanticStyleTool())
    with pytest.raises(GovernanceError):
        getattr(proxy, attr)(ARGS)
    assert SIDE_EFFECTS == [], f"proxy.{attr} executed a prohibited action"


def test_frozen_tool_proxy_still_governs_direct_call(guard):
    proxy = govern_langchain_tool(guard, FrozenPydanticStyleTool())
    with pytest.raises(GovernanceError):
        proxy(ARGS)
    assert SIDE_EFFECTS == []


def test_governed_tool_still_permits_a_benign_action(guard):
    """Not over-blocking: a permitted call still runs, through every path."""
    class Benign:
        name = "get_data"

        def __init__(self):
            self.func = lambda *a, **kw: "rows"

        def run(self, *a, **kw):
            return "rows"

        def invoke(self, *a, **kw):
            return "rows"

    wrapped = govern_langchain_tool(guard, Benign())
    assert wrapped.run({"source": "intranet.corp"}) == "rows"
    assert wrapped.invoke({"source": "intranet.corp"}) == "rows"


def test_proxy_passes_metadata_through_untouched(guard):
    """Introspection must keep working — governing a tool is not hiding it."""
    proxy = govern_langchain_tool(guard, FrozenPydanticStyleTool())
    assert proxy.name == TOOL
    assert proxy.description == "deletes a database"
    assert proxy.dict() == {"name": TOOL}


def test_proxy_refuses_an_unknown_callable_rather_than_passing_it_raw(guard):
    """Fail closed: a callable the proxy does not recognise is still governed.

    The original defect was a passthrough default. A tool method this adapter
    has never heard of must not become an ungoverned execution path just
    because it is not on a list.
    """
    class ToolWithExoticEntryPoint:
        name = TOOL

        def execute_now(self, *a, **kw):
            return DANGEROUS(*a, **kw)

        def __setattr__(self, k, v):
            raise AttributeError("frozen")

    proxy = govern_langchain_tool(guard, ToolWithExoticEntryPoint())
    with pytest.raises(GovernanceError):
        proxy.execute_now(ARGS)
    assert SIDE_EFFECTS == [], "an unrecognised callable executed ungoverned"


# ═══════════════════════════════════════════════════════════════
# Related finding 3 — AuthorizedCall self-dispatch
# ═══════════════════════════════════════════════════════════════

def test_refused_calls_yield_no_authorized_call(guard):
    """What the batch adapters DO guarantee: a refusal hands back nothing."""
    from morrison_governance.integrations import openai_partition_tool_calls

    class _F:
        def __init__(self, n, a):
            self.name, self.arguments = n, a

    class _TC:
        def __init__(self, i, n, a):
            self.id, self.function = i, _F(n, a)

    authorized, denied = openai_partition_tool_calls(
        guard, [_TC("1", TOOL, '{"target":"prod"}')])
    assert authorized == []
    assert [d.tool for d in denied] == [TOOL]


def test_execute_authorized_is_single_use(guard):
    """The lease is enforced on the sanctioned path.

    Self-dispatch from `.tool`/`.args` bypasses this, which is documented on
    AuthorizedCall and is not fixable in-library — the caller holds the data.
    What is enforceable is that redeeming twice fails.
    """
    from morrison_governance.integrations import openai_partition_tool_calls

    class _F:
        def __init__(self, n, a):
            self.name, self.arguments = n, a

    class _TC:
        def __init__(self, i, n, a):
            self.id, self.function = i, _F(n, a)

    authorized, _denied = openai_partition_tool_calls(
        guard, [_TC("1", "get_data", '{"source":"intranet.corp"}')])
    assert len(authorized) == 1
    ran = []
    ok1, _ = guard.execute_authorized(authorized[0], lambda c: ran.append(c))
    ok2, _ = guard.execute_authorized(authorized[0], lambda c: ran.append(c))
    assert ok1 is True and ok2 is False
    assert len(ran) == 1, "the lease was redeemed twice"
