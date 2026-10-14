"""Regression tests for falsification findings G1, E12 and E10
(runtime_eval/results/REPAIR_REFALSIFICATION.md). Each test reproduces the
counterexample and asserts the repaired outcome."""

import json
import threading

from morrison_governance import GovernanceLayer, OmegaRule
from morrison_governance.domains import OmegaDomain
from morrison_governance.kernel import GovernanceKernel
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.trust import Principal, SecurityContext

DOMAINS = [OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY, OmegaDomain.DATA_PRIVACY,
           OmegaDomain.ENTERPRISE, OmegaDomain.COMPLIANCE]
LIMIT = 25_000
OWNERS = {"SHARED": "acme", "OPS": "acme", "BETA-OPS": "beta"}


def T(src, dst, amount):
    return {"tool": "transfer", "args": {"from": src, "to": dst, "amount": amount}}


def _outflow_rule(src, limit):
    def check(state):
        args = state.get("args")
        args = json.loads(args) if isinstance(args, str) else args or {}
        if state.get("tool") != "transfer" or args.get("from") != src:
            return False
        total = 0
        for i in range(int(state.get("step", 0))):
            a = state.get(f"step_{i}_args") or {}
            if state.get(f"step_{i}_tool") == "transfer" and a.get("from") == src:
                total += int(a.get("amount", 0))
        return total + int(args.get("amount", 0)) > limit
    return OmegaRule(OmegaDomain.CUSTOM, f"outflow_{src}", "aggregate outflow", check)


def _scopes(call):
    if call.get("tool") == "transfer":
        return [f"account:{call['args']['from']}"]
    return []


def _kernel(principal, store, tenant="acme", scoped=True, owners=None):
    ctx = SecurityContext(
        principal=Principal(id=principal, tenant=tenant), continuity_store=store,
        tool_manifest={"transfer": ["payment.move_funds"]},
        policy_values={"payment_auto_approve_max": 10_000},
        resource_scopes=_scopes if scoped else None,
        owned_resource_args={"transfer": ("from",)} if owners is not None else {},
        resource_tenants=owners)
    layer = GovernanceLayer(domains=DOMAINS, custom_rules=[_outflow_rule("SHARED", LIMIT)],
                            log_all=False)
    return GovernanceKernel(layer, ctx)


def _run(kernel, call, effects):
    d = kernel.authorize(call)
    if d.permitted:
        ok, _ = kernel.execute(d, lambda a: effects.append(a))
    return d


# ── G1: a limit on a shared resource holds across principals ─────────
def test_g1_two_principals_cannot_jointly_exceed_a_shared_limit():
    store, effects = InMemoryContinuityStore(), []
    a, b = _kernel("agent-a", store), _kernel("agent-b", store)
    for k, dst in ((a, "A1"), (a, "A2"), (b, "B1"), (b, "B2")):
        _run(k, T("SHARED", dst, 9_000), effects)
    assert sum(e["args"]["amount"] for e in effects) <= LIMIT


def test_g1_without_scopes_the_counterexample_still_reproduces():
    store, effects = InMemoryContinuityStore(), []
    a, b = _kernel("agent-a", store, scoped=False), _kernel("agent-b", store, scoped=False)
    for k, dst in ((a, "A1"), (a, "A2"), (b, "B1"), (b, "B2")):
        _run(k, T("SHARED", dst, 9_000), effects)
    assert sum(e["args"]["amount"] for e in effects) == 36_000


def test_g1_simultaneous_principals_cannot_jointly_exceed_a_shared_limit():
    store, effects = InMemoryContinuityStore(), []
    kernels = [_kernel(f"agent-{i}", store) for i in range(8)]
    barrier = threading.Barrier(len(kernels))

    def go(i, k):
        barrier.wait()
        _run(k, T("SHARED", f"P{i}", 9_000), effects)

    threads = [threading.Thread(target=go, args=(i, k)) for i, k in enumerate(kernels)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(e["args"]["amount"] for e in effects) <= LIMIT


def test_g1_released_reservation_frees_the_shared_budget():
    store, effects = InMemoryContinuityStore(), []
    a, b = _kernel("agent-a", store), _kernel("agent-b", store)
    held = [a.authorize(T("SHARED", "A1", 9_000)), a.authorize(T("SHARED", "A2", 9_000))]
    assert all(d.permitted for d in held)
    assert not b.authorize(T("SHARED", "B1", 9_000)).permitted
    assert a.release(held[1])
    assert _run(b, T("SHARED", "B1", 9_000), effects).permitted


def test_g1_scope_resolver_failure_refuses():
    store = InMemoryContinuityStore()
    k = _kernel("agent-a", store)
    k.ctx.resource_scopes = lambda call: (_ for _ in ()).throw(RuntimeError("down"))
    d = k.authorize(T("SHARED", "A1", 1_000))
    assert d.verdict == "BLOCK" and d.rule == "resource_scope_unresolved"


# ── E12: ownership comes from a registry, not the shape of an id ─────
def test_e12_opaque_account_of_another_tenant_is_refused():
    k = _kernel("beta-agent", InMemoryContinuityStore(), tenant="beta", owners=OWNERS)
    effects = []
    d = _run(k, T("OPS", "BETA-PAYEE", 1_000), effects)
    assert d.verdict == "BLOCK" and d.rule == "cross_tenant" and not effects


def test_e12_unregistered_account_fails_closed():
    k = _kernel("acme-agent", InMemoryContinuityStore(), owners=OWNERS)
    for rid in ("UNKNOWN", " OPS", "ops"):
        d = k.authorize(T(rid, "X", 1_000))
        assert d.verdict == "BLOCK" and d.rule == "resource_owner_unknown", rid


def test_e12_own_account_is_permitted_and_registry_failure_refuses():
    k = _kernel("acme-agent", InMemoryContinuityStore(), owners=OWNERS)
    assert k.authorize(T("OPS", "X", 1_000)).permitted

    def broken(_):
        raise RuntimeError("registry down")
    k2 = _kernel("acme-agent", InMemoryContinuityStore(), owners=broken)
    assert k2.authorize(T("OPS", "X", 1_000)).rule == "resource_owner_unknown"


def test_e12_missing_owned_argument_is_refused():
    k = _kernel("acme-agent", InMemoryContinuityStore(), scoped=False, owners=OWNERS)
    d = k.authorize({"tool": "transfer", "args": {"to": "X", "amount": 1}})
    assert d.verdict == "BLOCK" and d.rule == "resource_owner_unknown"


# ── E10: no effect without a sealed record naming its decision ───────
def test_e10_recorder_down_before_dispatch_means_no_effect_and_decision_unspent():
    k = _kernel("agent-a", InMemoryContinuityStore(), scoped=False)
    d = k.authorize(T("OPS", "X", 1_000))
    real_append = k.chain.append

    def broken(*a, **kw):
        raise RuntimeError("evidence store unavailable")
    k.chain.append = broken
    effects = []
    ok, _ = k.execute(d, lambda a: effects.append(a))
    assert ok is False and not effects
    k.chain.append = real_append
    ok, _ = k.execute(d, lambda a: effects.append(a))
    assert ok is True and len(effects) == 1


def test_e10_outcome_failure_after_commit_leaves_intent_and_is_sealed_later():
    k = _kernel("agent-a", InMemoryContinuityStore(), scoped=False)
    d = k.authorize(T("OPS", "X", 1_000))
    real = k.chain.record_execution

    def broken(*a, **kw):
        raise RuntimeError("evidence store unavailable")
    k.chain.record_execution = broken
    effects = []
    ok, _ = k.execute(d, lambda a: effects.append(a))
    assert ok is True and len(effects) == 1
    intents = [r for r in k.chain.records if r.layer == "execution_intent"]
    assert len(intents) == 1 and intents[0].authorization["decision_id"] == d.decision_id
    assert not [r for r in k.chain.records if r.layer == "execution"]
    k.chain.record_execution = real
    assert k.flush_evidence() == 1
    assert len([r for r in k.chain.records if r.layer == "execution"]) == 1
    assert k.chain.verify()[0]


def test_r2_concurrent_executions_keep_the_evidence_chain_intact():
    """R2: the intent record (sealed under the kernel lock) and outcome records
    (sealed after the executor returns) were appended concurrently, and the
    chain lost its links. Executions overlap here, as they do with real I/O."""
    import sys
    import time
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for _ in range(10):
            k = _kernel("agent-a", InMemoryContinuityStore(), scoped=False)
            k.ctx.max_outstanding_reservations = 0
            ds = [k.authorize(T("OPS", f"E{i}", 1)) for i in range(16)]
            barrier = threading.Barrier(len(ds))

            def go(d):
                barrier.wait()
                k.execute(d, lambda a: time.sleep(0.001))
            ts = [threading.Thread(target=go, args=(d,)) for d in ds]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            assert k.chain.verify()[0]
    finally:
        sys.setswitchinterval(old)


def test_g1_limit_is_rolling_by_default_and_lifetime_with_window_zero():
    """V-G1c: shared history older than continuity_window_s (default 3600 s)
    leaves the trajectory, so the default limit is a rolling one. With
    continuity_window_s=0 nothing ages out and the limit holds for life."""
    import time as _time
    from morrison_governance.kernel import gate as gate_mod

    def run(window):
        store, effects = InMemoryContinuityStore(), []
        a = _kernel("agent-a", store)
        a.ctx.continuity_window_s = window
        for dst in ("A1", "A2"):
            _run(a, T("SHARED", dst, 9_000), effects)
        real = _time.time

        class _Later:
            def __getattr__(self, name):
                return getattr(_time, name)

            @staticmethod
            def time():
                return real() + 3_601.0
        saved, gate_mod.time = gate_mod.time, _Later()
        try:
            b = _kernel("agent-b", store)
            b.ctx.continuity_window_s = window
            for dst in ("B1", "B2"):
                _run(b, T("SHARED", dst, 9_000), effects)
        finally:
            gate_mod.time = saved
        return sum(e["args"]["amount"] for e in effects)

    assert run(3_600.0) == 36_000          # documented rolling window
    assert run(0.0) <= LIMIT               # lifetime limit
