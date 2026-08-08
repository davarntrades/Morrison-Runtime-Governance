"""The lint gate must stay actionable.

WHAT WENT WRONG

.github/workflows/pylint.yml ran stock pylint with no project configuration and
no --fail-under, so the default threshold of 10.00 applied against a codebase
scoring 8.14. It failed 29 of 29 completed runs — it had never passed once.

A check that has never passed is worse than none: nobody can act on it, so
everybody stops reading it, and it then hides the findings that matter. It did.
84 error-class findings sat under 1,776 style messages, including three
invisible zero-width-space characters and a genuine latent TypeError
(PlannerInfo(kind=...) behind a hasattr guard that is True for every class).

WHAT THESE TESTS PROTECT

The repair is easy to undo by accident — lowering fail-under to make a build
pass, or adding an error-class check to the disable list. Both would restore
the useless-gate state without anyone noticing. So:

  1. fail-on=E must remain. Measured, not assumed: a file containing an
     undefined name moved the aggregate score only 9.78 -> 9.77 and still
     passed fail-under. A score dilutes with repository size; only fail-on
     catches a single new defect.
  2. fail-under must not be lowered.
  3. Error-class checks must never be disabled wholesale.
"""

from __future__ import annotations

import configparser
import pathlib

import pytest

ENGINE_ROOT = pathlib.Path(__file__).resolve().parents[1]
PYLINTRC = ENGINE_ROOT / ".pylintrc"

# The floor agreed when the gate was repaired. Raising it is a deliberate
# improvement; lowering it is how a gate quietly dies.
MIN_FAIL_UNDER = 9.50

# Disabling any of these would return the gate to reporting only cosmetics.
ERROR_CLASS_CHECKS = {
    "undefined-variable", "used-before-assignment", "no-member",
    "not-callable", "unexpected-keyword-arg", "no-value-for-parameter",
    "invalid-character-zero-width-space", "return-in-finally",
    "dangerous-default-value", "unused-import", "unused-variable",
    "too-many-function-args", "invalid-sequence-index",
}


def _config():
    if not PYLINTRC.exists():
        pytest.fail(".pylintrc is missing — the lint gate reverts to stock "
                    "defaults, which this repository has never satisfied")
    cp = configparser.ConfigParser()
    cp.read(PYLINTRC)
    return cp


def test_fail_under_is_not_lowered():
    cp = _config()
    raw = cp.get("MAIN", "fail-under", fallback=None)
    assert raw is not None, "fail-under is unset — pylint reverts to 10.00"
    assert float(raw) >= MIN_FAIL_UNDER, (
        f"fail-under {raw} is below the agreed floor {MIN_FAIL_UNDER}. Lowering "
        f"it to make a build pass is the suppression this gate exists to avoid; "
        f"fix the findings instead.")


def test_fail_on_error_class_is_enabled():
    """The load-bearing half of the gate.

    fail-under alone is not sufficient and this is measured, not asserted: a
    single file with an undefined name moved the score 9.78 -> 9.77 and still
    passed. Only fail-on catches one new defect in a large tree.
    """
    cp = _config()
    fail_on = cp.get("MAIN", "fail-on", fallback="")
    assert "E" in [p.strip() for p in fail_on.split(",")], (
        "fail-on must include E so any error-class finding fails the build "
        "regardless of the aggregate score")


def test_no_error_class_check_is_disabled():
    cp = _config()
    disabled = {
        line.strip().rstrip(",")
        for line in cp.get("MESSAGES CONTROL", "disable", fallback="").split("\n")
        if line.strip() and not line.strip().startswith("#")
    }
    leaked = disabled & ERROR_CLASS_CHECKS
    assert not leaked, (
        f"error-class checks disabled: {sorted(leaked)}. These catch real "
        f"defects — the gate found a latent TypeError and three invisible "
        f"characters once it could be read. Disable convention noise, not these.")


def test_every_disable_carries_a_reason():
    """A disable without a stated reason is indistinguishable from suppression."""
    text = PYLINTRC.read_text()
    block = text.split("disable =", 1)[1].split("[", 1)[0] if "disable =" in text else ""
    lines = [ln for ln in block.split("\n") if ln.strip()]
    entries = [ln for ln in lines if not ln.strip().startswith("#")]
    comments = [ln for ln in lines if ln.strip().startswith("#")]
    assert comments, "the disable list carries no explanatory comments at all"
    # Roughly one rationale line per two disabled checks is the observed shape;
    # this catches a bulk paste of disables with no justification.
    assert len(comments) >= len(entries) / 3, (
        f"{len(entries)} disabled checks but only {len(comments)} comment lines "
        f"— every disable needs a stated reason, or it reads as suppression")
