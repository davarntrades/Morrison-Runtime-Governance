"""Provenance lint gate — residual 9.4.

WHAT THIS CLOSES

`_sec_authorized()` is list-free: it asks a fact's provenance, never its
spelling, so an invented `guardian_ack` cannot authorise anything no matter
what it is called. But six Ω rules depend on a SPECIFIC external authorisation
by name (`hipaa_authorized`, `admin_approved`, …) and were converted by hand to
the trusted-only contract. Nothing stopped the seventh.

A new rule written as

    check=lambda s: (... and not s.get("underwriter_approved", False))

would read a caller-supplied attestation ungated and re-open the class one rule
at a time. The failure mode is quiet: the rule looks exactly like its
neighbours, the suite passes, and the hole is only visible to someone who knows
the contract exists.

WHAT THIS IS NOT

This is NOT the trust boundary, and it must not be mistaken for one. The
boundary is provenance (`provenance.py`); this is a CODE REVIEW AID that
enforces the calling convention so an author cannot bypass the boundary by
accident. Deleting this gate weakens nothing that is already written — it only
removes the warning for what is written next.

The gate carries its own failure test. A gate nobody has seen fail is a gate
nobody should trust; `test_gate_detects_a_deliberately_regressed_rule` plants
the exact defect and asserts the gate catches it.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

ENGINE_ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Modules that define Ω rules. A new rule module belongs here.
RULE_MODULES = [
    ENGINE_ROOT / "morrison_governance" / "domains.py",
    ENGINE_ROOT / "runtime_eval" / "domains" / "composite_omega.py",
]

#: The SHAPE of a name that asserts somebody else's decision. Matching this is
#: not what makes a field an attestation — provenance is. It is what makes a
#: bare `s.get()` on it worth a human's attention.
_ATTESTATION_SUFFIXES = (
    "_approved", "_authorized", "_authorised", "_verified", "_confirmed",
    "_cleared", "_signoff", "_signed_off", "_endorsed", "_ack",
    "_acknowledged", "_countersigned", "_attested", "_certified",
    "_validated", "_sanctioned", "_ratified",
)

#: Exact names that assert an external decision without matching a suffix.
_ATTESTATION_NAMES = frozenset({
    "authorized", "authorised", "approved", "verified", "sanctioned",
    "consent_verified", "consented_purposes", "pci_compliant_endpoint",
    "delegation_scope", "destination_internal", "destination_external",
    "is_internal", "internal", "trusted", "privileged", "break_glass",
    "override", "policy_override", "sanitized", "sanitised", "redacted",
    "anonymized", "anonymised", "deidentified", "human_review",
    "security_review", "admin_authorized", "change_approved",
})

#: Reads that ALREADY carry the contract. Calling one of these is the fix.
_GATED_READERS = frozenset({
    "_attested", "_attested_value", "_sec_truthy_attested",
    "attested", "attested_truthy", "any_attested",
})

#: Names that look like attestations but are SELF-DESCRIPTIONS of the action —
#: "this reply routes to support". They are governed by independent derivation
#: (DERIVED outranks UNTRUSTED), not by a trust boundary, and reading them with
#: `.get()` is correct. Each entry is a deliberate decision, not an oversight.
_SELF_DESCRIPTION_EXEMPT = frozenset({
    "route_to_support", "crisis_referral", "emergency_referral",
    "contains_phi", "contains_pii", "contains_sensitive",
    "contains_customer_data", "safety_disabled",
})

#: Marker an author may place on the same line to record a justified exception.
_ESCAPE = "provenance-exempt:"

#: The receiver name an Ω predicate uses for its state mapping.
_STATE_NAMES = frozenset({"s", "state", "st"})


def _is_attestation_shaped(name: str) -> bool:
    if name in _SELF_DESCRIPTION_EXEMPT:
        return False
    return name in _ATTESTATION_NAMES or name.endswith(_ATTESTATION_SUFFIXES)


def _ungated_attestation_reads(source: str, label: str) -> list[str]:
    """Every `s.get("<attestation>")` / `s["<attestation>"]` in `source`.

    Collected via the AST rather than a regex: an earlier gate in this repo
    learned that a text scan over source also matches prose and reported
    English words as findings.
    """
    tree = ast.parse(source)
    lines = source.splitlines()
    offenders: list[str] = []

    def receiver_is_state(node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id in _STATE_NAMES

    def exempted(lineno: int) -> bool:
        # The marker may sit anywhere in the comment block immediately above
        # the read, not only on the line before it: a justification worth
        # writing is usually several lines long, and requiring the marker on
        # the last line would push authors toward one-word reasons.
        idx = lineno - 1
        window = lines[max(0, idx - 8): idx + 1]
        return any(_ESCAPE in ln for ln in window)

    for node in ast.walk(tree):
        name = None
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and receiver_is_state(node.func.value)
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            if node.func.attr in _GATED_READERS:
                continue
            name = node.args[0].value
        elif (isinstance(node, ast.Subscript)
              and receiver_is_state(node.value)
              and isinstance(node.slice, ast.Constant)
              and isinstance(node.slice.value, str)):
            name = node.slice.value

        if name and _is_attestation_shaped(name) and not exempted(node.lineno):
            offenders.append(f"{label}:{node.lineno}: s.get({name!r})")
    return offenders


@pytest.mark.parametrize("path", RULE_MODULES, ids=lambda p: p.name)
def test_no_rule_reads_an_attestation_through_an_ungated_get(path):
    """An Ω rule must not read an external authorisation as ordinary state.

    Use `_attested(s, name)` — or, if the field is genuinely a self-description
    of the action rather than somebody else's decision, add it to
    `_SELF_DESCRIPTION_EXEMPT` above with a reason, or mark the line
    `# provenance-exempt: <why>`. Both routes are deliberate and reviewable;
    a bare `.get()` is neither.
    """
    if not path.exists():
        pytest.skip(f"{path.name} not present")
    offenders = _ungated_attestation_reads(
        path.read_text(encoding="utf-8"), path.name)
    assert not offenders, (
        "Ω rules read a caller-supplied attestation without a provenance "
        "contract:\n  " + "\n  ".join(offenders) +
        "\n\nA caller can set any of these. Read them with `_attested(s, ...)` "
        "so only a fact the deployment established satisfies the rule.")


def test_gate_detects_a_deliberately_regressed_rule():
    """The gate must be able to fail. Plant the exact defect and prove it.

    A gate nobody has seen fail is a gate nobody should trust — the lesson
    `test_lint_gate.py` exists to record.
    """
    regressed = (
        'OmegaRule(\n'
        '    domain=D, name="payout_without_signoff", description="",\n'
        '    check=lambda s: (s.get("tool") == "pay"\n'
        '                     and not s.get("underwriter_approved", False)),\n'
        ')\n'
    )
    found = _ungated_attestation_reads(regressed, "<regressed>")
    assert any("underwriter_approved" in f for f in found), (
        "the gate failed to detect an ungated attestation read — it is not "
        "protecting anything")


def test_gate_does_not_flag_the_gated_form():
    ok = ('check=lambda s: (s.get("tool") == "pay"\n'
          '                 and not _attested(s, "underwriter_approved")),\n')
    assert _ungated_attestation_reads(ok, "<ok>") == []


def test_gate_does_not_flag_self_descriptions_or_subject_matter():
    """Observations the rules legitimately reason about must not be flagged."""
    fine = ('check=lambda s: (s.get("user_state") == "active_crisis"\n'
            '                 and not s.get("route_to_support")\n'
            '                 and s.get("category") != "safe"\n'
            '                 and s.get("tone") == "dismissive"),\n')
    assert _ungated_attestation_reads(fine, "<fine>") == []


def test_escape_hatch_is_honoured_and_visible():
    marked = ('check=lambda s: (\n'
              '    # provenance-exempt: set by the ingest pipeline, not the caller\n'
              '    s.get("pipeline_validated")),\n')
    assert _ungated_attestation_reads(marked, "<marked>") == []
