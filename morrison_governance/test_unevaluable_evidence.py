"""
Evidence-integrity tests for refused (unevaluable) proposals.

THE INVARIANT UNDER TEST
────────────────────────
    Two materially different rejected proposals must remain distinguishable
    in immutable evidence.

A refusal replaces the caller's proposal with a shared inert placeholder so it
can travel the normal decision/evidence pipeline. That placeholder is the same
object for every refusal, so the *evaluated* action hash is necessarily shared:

    malformed_A ──▶ hash(__unevaluable__)
    malformed_B ──▶ hash(__unevaluable__)

That collapse is acceptable for the evaluated-action identity and NOT
acceptable as the only identity in the record. The chain preserved is:

    original proposed action
      → validation / evaluation failure
      → normalised `__unevaluable__` refusal object
      → BLOCK

with `original_input_digest` binding the first and `action_hash` the third.

WHAT IS DELIBERATELY *NOT* ASSERTED
───────────────────────────────────
That the original input is recoverable from evidence. It is not, and should
not be: the input is already known to be malformed and may carry sensitive or
unrenderable content, so only a digest and a value-free shape are stored.
Distinguishability is the requirement; reconstruction is not.
"""

from __future__ import annotations

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.evidence_fingerprint import (
    DIGEST_UNAVAILABLE, input_digest, structural_fingerprint, structural_shape,
)
from morrison_governance.result import GovernanceVerdict


DOMAINS = [OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY]


def _layer() -> GovernanceLayer:
    return GovernanceLayer(domains=DOMAINS, log_all=False)


def _kernel():
    from morrison_governance.test_kernel_redteam import _kernel as mk
    return mk()


# Two proposals that are materially different but land on the SAME placeholder.
MALFORMED_A = {"tool": "read_file", "args": None}
MALFORMED_B = {"tool": "write_file", "args": None}


# ═══════════════════════════════════════════════════════════════
# §1 — the six required properties, at the kernel (evidence-bearing) surface
# ═══════════════════════════════════════════════════════════════


def test_1_two_different_malformed_proposals_both_block():
    k = _kernel()
    a, b = k.authorize(MALFORMED_A), k.authorize(MALFORMED_B)
    assert a.verdict == "BLOCK", f"{a.verdict} at {a.layer}"
    assert b.verdict == "BLOCK", f"{b.verdict} at {b.layer}"


def test_1b_verdict_is_not_order_dependent():
    """The same malformed call must get the same verdict regardless of what
    was authorised before it. This failed before `unevaluable_input` was
    exempted from the BLOCK→ESCALATE authority downgrade: the first refusal in
    a session came back ESCALATE and later ones BLOCK, because an earlier
    denial in the ledger changed the reclassification."""
    first = _kernel().authorize(MALFORMED_A)
    k = _kernel()
    k.authorize(MALFORMED_B)
    second = k.authorize(MALFORMED_A)
    assert first.verdict == second.verdict == "BLOCK"
    assert first.layer == second.layer == "unevaluable_input"


def test_2_both_are_machine_identifiable_as_unevaluable():
    k = _kernel()
    for call in (MALFORMED_A, MALFORMED_B):
        d = k.authorize(call)
        assert d.layer == "unevaluable_input"
        assert d.evidence is not None
        assert d.evidence.layer == "unevaluable_input"


def test_3_original_input_evidence_identities_are_distinguishable():
    """The load-bearing assertion."""
    k = _kernel()
    a, b = k.authorize(MALFORMED_A), k.authorize(MALFORMED_B)
    assert a.original_input_digest and b.original_input_digest
    assert a.original_input_digest != b.original_input_digest, (
        "two materially different malformed proposals share one audit identity"
    )
    assert a.evidence.original_input_digest != b.evidence.original_input_digest
    # And the binding is sealed into the record hash, not merely attached.
    assert a.evidence.record_hash != b.evidence.record_hash


def test_3b_original_input_digest_is_bound_into_the_record_hash():
    """A field that is not covered by the seal is decoration, not evidence."""
    d = _kernel().authorize(MALFORMED_A)
    record = d.evidence
    sealed = record.record_hash
    record.original_input_digest = "tampered"
    record.record_hash = ""
    record.seal()
    assert record.record_hash != sealed, (
        "original_input_digest is not covered by the evidence seal"
    )


def test_4_normalised_refusal_representation_may_be_shared():
    """The placeholder collapse is expected and is not itself the defect —
    this pins that the fix did not work by making the placeholder unique,
    which would have defeated its purpose."""
    k = _kernel()
    a, b = k.authorize(MALFORMED_A), k.authorize(MALFORMED_B)
    assert a.action_hash == b.action_hash
    assert a.action == b.action


def test_5_evidence_generation_cannot_fail_open(monkeypatch):
    """If fingerprinting raises, the refusal must still be a recorded BLOCK
    carrying the sentinel — never an exception escaping `authorize`, and never
    a missing record."""
    from morrison_governance.kernel import gate

    def _boom(_value):
        raise RuntimeError("fingerprinting exploded")

    monkeypatch.setattr(gate, "input_digest", _boom)
    monkeypatch.setattr(gate, "structural_shape", _boom)

    d = _kernel().authorize(MALFORMED_A)
    assert d.verdict == "BLOCK"
    assert d.original_input_digest == DIGEST_UNAVAILABLE
    assert d.evidence is not None, "refusal was not recorded"


def test_6_evidence_failure_cannot_turn_block_into_permit(monkeypatch):
    from morrison_governance.kernel import gate

    def _boom(_value):
        raise MemoryError("out of memory building evidence")

    monkeypatch.setattr(gate, "input_digest", _boom)
    monkeypatch.setattr(gate, "structural_shape", _boom)

    for call in (MALFORMED_A, MALFORMED_B, {}, {"tool": 1}, 42):
        d = _kernel().authorize(call)
        assert d.verdict != "PERMIT", f"{call} -> PERMIT under evidence failure"


def test_6b_library_refusal_also_survives_evidence_failure(monkeypatch):
    from morrison_governance import core

    def _boom(_value):
        raise RuntimeError("fingerprinting exploded")

    monkeypatch.setattr(core, "input_digest", _boom)
    monkeypatch.setattr(core, "structural_shape", _boom)

    r = _layer().evaluate(MALFORMED_A)
    assert r.verdict is GovernanceVerdict.BLOCK
    assert r.metadata["unevaluable"] is True
    assert r.metadata["original_input_digest"] == DIGEST_UNAVAILABLE


# ═══════════════════════════════════════════════════════════════
# §2 — the library surface carries the same binding
# ═══════════════════════════════════════════════════════════════


def test_library_refusals_are_distinguishable():
    g = _layer()
    a, b = g.evaluate(MALFORMED_A), g.evaluate(MALFORMED_B)
    assert a.metadata["original_input_digest"] != b.metadata["original_input_digest"]


def test_library_refusal_records_stage_and_entry_point():
    r = _layer().evaluate_openai([42])
    assert r.metadata["refusal_stage"] == "input_validation"
    assert r.metadata["refusal_entry_point"] == "evaluate_openai"


def test_rule_failure_records_stage_and_rule():
    from morrison_governance.domains import OmegaRule

    def _broken(_state):
        raise RuntimeError("rule predicate is broken")

    g = _layer()
    g.add_rule(OmegaRule(domain=OmegaDomain.CYBERSECURITY, name="broken_rule",
                         description="raises", check=_broken))
    r = g.evaluate({"tool": "http_request", "args": {"url": "https://x.com"}})
    assert r.metadata["refusal_stage"] == "rule_evaluation"
    assert r.metadata["failed_rule"] == "broken_rule"


def test_reason_strings_do_not_embed_raw_user_values():
    """Reasons land in immutable evidence. A raw value there both persists
    possibly-sensitive data and, for an object, means a user-controlled
    `__repr__` ran inside the audit path."""
    secret = "sk-live-SUPERSECRET-0123456789"
    r = _layer().evaluate({"tool": 12345, "args": {"token": secret}})
    blob = r.reason + str(r.metadata)
    assert secret not in blob, "a raw argument value reached the refusal record"


def test_fingerprint_never_calls_user_repr():
    class Hostile:
        def __repr__(self):
            raise AssertionError("__repr__ must not be called")

        def __str__(self):
            raise AssertionError("__str__ must not be called")

        def __iter__(self):
            raise AssertionError("__iter__ must not be called")

        def __eq__(self, other):
            raise AssertionError("__eq__ must not be called")

        def __hash__(self):
            raise AssertionError("__hash__ must not be called")

    r = _layer().evaluate({"tool": "read_file", "args": {"x": Hostile()}})
    assert r.verdict is GovernanceVerdict.BLOCK
    assert r.metadata["original_input_digest"] != DIGEST_UNAVAILABLE


# ═══════════════════════════════════════════════════════════════
# §3 — the fingerprint's own guarantees
# ═══════════════════════════════════════════════════════════════


def test_fingerprint_is_deterministic():
    value = {"b": [1, 2, {"c": "x"}], "a": {"k": None}}
    assert structural_fingerprint(value) == structural_fingerprint(value)
    assert input_digest(value) == input_digest(dict(reversed(list(value.items()))))


def test_fingerprint_handles_cycles():
    cyclic = {}
    cyclic["self"] = cyclic
    assert "<cycle>" in structural_fingerprint(cyclic)
    assert input_digest(cyclic) != DIGEST_UNAVAILABLE

    a, b = [], []
    a.append(b)
    b.append(a)
    assert input_digest(a) != DIGEST_UNAVAILABLE


def test_fingerprint_is_bounded_for_oversized_input():
    huge = list(range(1_000_000))
    fp = structural_fingerprint(huge)
    assert len(fp) < 20_000, f"fingerprint grew to {len(fp)} chars"
    # ...but still records the true size, so a 1M-element list and a
    # 2M-element list are not confused.
    assert input_digest(huge) != input_digest(list(range(2_000_000)))


def test_fingerprint_is_bounded_for_deep_nesting():
    deep: object = "leaf"
    for _ in range(5000):
        deep = [deep]
    fp = structural_fingerprint(deep)
    assert "<depth" in fp
    assert input_digest(deep) != DIGEST_UNAVAILABLE


def test_fingerprint_handles_non_serialisable_values():
    for value in (object(), lambda: None, type, NotImplemented, Ellipsis,
                  {1, 2, 3}, frozenset("ab"), b"\xff\xfe", float("nan")):
        assert input_digest({"v": value}) != DIGEST_UNAVAILABLE


def test_fingerprint_distinguishes_materially_different_values():
    cases = [
        {"tool": "a"}, {"tool": "b"}, {"tool": 1}, {"tool": "1"},
        {"tool": True}, {"tool": None}, {}, {"args": {}},
        [1, 2], [2, 1], (1, 2), "12",
    ]
    digests = [input_digest(c) for c in cases]
    assert len(set(digests)) == len(cases), "distinct inputs collided"


def test_fingerprint_distinguishes_long_strings_past_the_truncation_point():
    a = "x" * 5000 + "A"
    b = "x" * 5000 + "B"
    assert input_digest(a) != input_digest(b)


def test_structural_shape_carries_no_user_values():
    secret = "sk-live-SUPERSECRET"
    shape = structural_shape({"token": secret, "n": 42})
    assert secret not in shape
    assert "42" not in shape.replace("[", " ").replace("]", " ").split()


def test_fingerprint_is_total_against_a_hostile_type():
    """Even reading the TYPE's name can be made to raise. The fingerprint must
    still return a value rather than propagate."""
    class HostileMeta(type):
        def __getattribute__(cls, name):
            if name in ("__qualname__", "__name__", "__module__"):
                raise RuntimeError("no name for you")
            return type.__getattribute__(cls, name)

    class Hostile(metaclass=HostileMeta):
        pass

    assert input_digest(Hostile()) != DIGEST_UNAVAILABLE
    assert "<untypeable>" in structural_fingerprint(Hostile())


# ═══════════════════════════════════════════════════════════════
# §4 — empty submission vs dropped proposal
#
# `evaluate_openai([])` remains PERMIT, and the semantics are explicitly
# "zero proposed actions, therefore nothing to withhold authority from" —
# NOT "an attempted action disappeared and was treated as empty".
# ═══════════════════════════════════════════════════════════════


def test_genuinely_empty_proposal_set_permits():
    r = _layer().evaluate_openai([])
    assert r.verdict is GovernanceVerdict.PERMIT
    assert not r.metadata.get("unevaluable")


def test_one_malformed_proposal_blocks():
    r = _layer().evaluate_openai([42])
    assert r.verdict is GovernanceVerdict.BLOCK
    assert r.metadata["unevaluable"] is True


def test_parsing_failure_cannot_become_an_empty_list():
    """The original defect: `from_openai` discards an item matching neither of
    its branches, leaving an empty trajectory that inherits the empty-list
    PERMIT. Validation runs BEFORE extraction precisely so a parse failure can
    never reach that path."""
    g = _layer()
    empty = g.evaluate_openai([])
    dropped = g.evaluate_openai([42])
    assert empty.verdict is GovernanceVerdict.PERMIT
    assert dropped.verdict is GovernanceVerdict.BLOCK
    assert empty.verdict != dropped.verdict


@pytest.mark.parametrize("n", [1, 2, 5])
def test_n_proposals_with_one_malformed_cannot_collapse_to_n_minus_1(n):
    """A batch containing a malformed proposal must be refused as a batch. It
    must NOT silently evaluate the remaining N-1 and report on those — the
    caller would receive a verdict about a plan they did not submit."""
    good = {"tool": "read_file", "args": {"path": "/tmp/x"}}
    batch = [good] * n + [42]
    r = _layer().evaluate_openai(batch)
    assert r.verdict is GovernanceVerdict.BLOCK
    assert r.metadata["unevaluable"] is True


def test_langchain_batch_with_one_malformed_is_refused():
    good = {"tool": "read_file", "tool_input": {"path": "/tmp/x"}}
    r = _layer().evaluate_langchain([good, 42])
    assert r.verdict is GovernanceVerdict.BLOCK
    assert r.metadata["unevaluable"] is True


def test_plan_with_one_malformed_step_is_refused_as_a_whole():
    good = {"tool": "read_file", "args": {"path": "/tmp/x"}}
    r = _layer().evaluate_plan([good, {"tool": None, "args": {}}, good])
    assert r.verdict is GovernanceVerdict.BLOCK
    assert r.metadata["unevaluable"] is True
