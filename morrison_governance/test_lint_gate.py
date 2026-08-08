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


def test_every_third_party_import_is_accounted_for_in_the_lint_environment():
    """Local and CI must see the same import graph.

    The first attempt at repairing this gate passed locally and failed on CI
    with exit 30. Cause: the lint job installs a minimal dependency set, so
    `import pytest` was unresolvable there and raised import-error (E0401),
    which fail-on=E then caught. Locally pytest is installed, so it never
    appeared.

    A gate whose result depends on which machine runs it is not a gate. Every
    third-party module the code imports must therefore be EITHER installed by
    the lint workflow OR listed in ignored-modules — never neither.
    """
    import re

    workflow = (ENGINE_ROOT / ".github" / "workflows" / "pylint.yml").read_text()
    installed = set(re.findall(r"pip install ([\w\s-]+)", workflow))
    installed = {tok for group in installed for tok in group.split()}

    cp = _config()
    ignored = {
        m.strip()
        for m in cp.get("MAIN", "ignored-modules", fallback="").replace("\n", ",").split(",")
        if m.strip()
    }

    stdlib = set(getattr(__import__("sys"), "stdlib_module_names", set()))
    first_party = {"morrison_governance", "runtime_eval", "redteam", "multi_agent_eval",
                   "global_governance", "audit", "artifacts", "_repo_paths"}

    # Collected via the AST, not a regex. A text scan over source also matches
    # prose — an earlier version of this test reported "its" and "the" as
    # third-party packages, harvested from sentences like "import the module".
    import ast

    imported = set()
    for p in ENGINE_ROOT.rglob("*.py"):
        if any(x in p.parts for x in (".git", "__pycache__", ".venv", "build", "dist")):
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:      # skip relative imports
                    imported.add(node.module.split(".")[0])

    unaccounted = sorted(imported - stdlib - first_party - ignored - installed
                         - {"__future__"})
    assert not unaccounted, (
        f"third-party imports neither installed by the lint workflow nor in "
        f"ignored-modules: {unaccounted}. Under fail-on=E each becomes an "
        f"import-error on CI while passing locally — the exact local/CI split "
        f"that made this gate untrustworthy.")


_BUILTIN_GENERICS = {"dict", "list", "set", "tuple", "frozenset", "type"}


def _looks_like_type_expression(node) -> bool:
    """Is this assignment value a TYPE ALIAS rather than ordinary runtime code?

    Needed because `|` is overwhelmingly set/dict union in this codebase, not a
    PEP 604 type union. A previous version of this check treated every `BinOp`
    on the right of an assignment as an alias and reported five offenders that
    were all real code:

        merged = set(baseline.verdicts) | set(current.verdicts)
        printable = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

    Those are legal on every supported Python. A type alias is built only from
    names, attributes, subscripts and literals — the moment a Call, a set/dict
    display or a comprehension appears, it is a value expression and the runtime
    version question does not arise.
    """
    import ast as _ast

    if not isinstance(node, (_ast.Subscript, _ast.BinOp)):
        return False
    allowed = (_ast.Subscript, _ast.BinOp, _ast.Name, _ast.Attribute, _ast.Tuple,
               _ast.List, _ast.Constant, _ast.Load, _ast.BitOr, _ast.Store)
    return all(isinstance(sub, allowed) for sub in _ast.walk(node))


def test_modern_generics_in_evaluated_annotations_defer_evaluation():
    """Class-level annotations are evaluated at class-creation time.

    `payload: dict | list[dict]` inside a @dataclass, in a module WITHOUT
    `from __future__ import annotations`, raises TypeError on Python < 3.10 —
    the module cannot even be imported. That is a genuine incompatibility, not
    a lint opinion, and the pylint 3.8 matrix job is what surfaced it
    (unsupported-binary-operation, exit 30).

    Function-body annotations are never evaluated. The future import defers the
    rest — but NOT type aliases, because an alias is an ordinary runtime value
    on the right of an assignment, not an annotation. Treating the future import
    as blanket immunity is what let stability.py:42 through and failed the 3.8
    job a second time, so the two categories are scanned separately below.
    """
    import ast

    offenders = []
    for path in ENGINE_ROOT.rglob("*.py"):
        if any(x in path.parts for x in (".git", "__pycache__", ".venv", "build", "dist")):
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue

        defers = any(
            isinstance(n, ast.ImportFrom) and n.module == "__future__"
            and any(a.name == "annotations" for a in n.names)
            for n in tree.body
        )

        evaluated = []

        # (1) Type ALIASES — checked in EVERY module, deferred or not. The alias
        #     is a value expression evaluated at import:
        #         PerturbFn = Callable[[dict, int], list[dict]]
        #     `from __future__ import annotations` does nothing for it.
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign) and _looks_like_type_expression(stmt.value):
                evaluated.append(stmt.value)

        # (2) Annotations proper — only dangerous when the module does NOT defer.
        if not defers:
            for stmt in tree.body:
                # Module-level annotated assignment: `X: dict[str, T] = {...}`.
                # Only those directly in tree.body: an AnnAssign inside a
                # function body is never evaluated. Missing this case is what
                # let planners.py:87 through.
                if isinstance(stmt, ast.AnnAssign) and stmt.annotation:
                    evaluated.append(stmt.annotation)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    # Class-level annotations run at class-creation time.
                    evaluated += [st.annotation for st in node.body
                                  if isinstance(st, ast.AnnAssign) and st.annotation]
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    a = node.args
                    for arg in list(a.args) + list(a.posonlyargs) + list(a.kwonlyargs):
                        if arg.annotation:
                            evaluated.append(arg.annotation)
                    if node.returns:
                        evaluated.append(node.returns)

        for expr in evaluated:
            lineno = getattr(expr, "lineno", 0)
            for sub in ast.walk(expr):
                # PEP 604 union: `X | Y` — 3.10+ at runtime
                if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr):
                    offenders.append(
                        f"{path.relative_to(ENGINE_ROOT)}:{lineno}: PEP 604 union")
                    break
                # Builtin generic subscript: `dict[str, int]` — 3.9+ at runtime
                if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) \
                        and sub.value.id in _BUILTIN_GENERICS:
                    offenders.append(
                        f"{path.relative_to(ENGINE_ROOT)}:{lineno}: builtin generic")
                    break

    assert not offenders, (
        "class-level annotations using modern generic syntax are evaluated at "
        "import time and break on older Python. Add `from __future__ import "
        "annotations` to these modules:\n  " + "\n  ".join(sorted(set(offenders))))
