"""Repository portability — no code may depend on a developer's home directory.

THE FAILURE THIS PREVENTS

Scripts and tests here used to begin:

    sys.path.insert(0, "/home/user/Morrison-Runtime-Governance")
    sys.path.insert(0, "/home/user/resurrection-tech-enterprise/governance-service")

The obvious failure is a crash on a machine without those paths — that is how
CI broke (`ModuleNotFoundError: No module named 'cyber_rules'`).

The dangerous failure is the quiet one. On a machine that HAS those paths — a
second clone, a renamed directory, a runner that checks out elsewhere — the
import succeeds against the OTHER tree. A red-team script whose whole purpose
is to prove a bypass is closed then examines code that is not the code under
test, and reports success. Demonstrated before the fix: a sentinel added to
the checkout under test was invisible to the script running inside it.

So these tests assert two different things:

  1. no absolute home-directory path appears in path resolution (the crash)
  2. resolution actually lands on THIS checkout (the silent wrong tree)

(2) is the one that matters. A test that only checked (1) would pass on a
codebase that had swapped one wrong constant for another.
"""

from __future__ import annotations

import ast
import os
import pathlib
import re
import subprocess
import sys

import pytest

ENGINE_ROOT = pathlib.Path(__file__).resolve().parents[1]

_HOME_PREFIX = re.compile(r"^/(home|Users)/")


def _python_files():
    for p in ENGINE_ROOT.rglob("*.py"):
        if any(part in {".git", ".venv", "build", "dist", "__pycache__"} for part in p.parts):
            continue
        yield p


def _home_path_sys_path_calls(source: str):
    """Home-directory literals passed to sys.path.insert/append — via the AST.

    Deliberately NOT a text search. A regex over source also matches prose:
    this module's own docstring quotes the old lines, and so does
    redteam/_repo_paths.py, which exists to explain why they were removed. A
    guard that fires on its own documentation trains people to delete the
    documentation.

    It also correctly ignores attack-payload DATA such as
    "/home/user/.ssh/id_rsa" — those literals are the point of the test corpus,
    not filesystem coupling. Only a literal handed to sys.path counts.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in ("insert", "append"):
            continue
        target = node.func.value
        # sys.path.insert(...) / path.insert(...) after `from sys import path`
        is_sys_path = (
            (isinstance(target, ast.Attribute) and target.attr == "path"
             and isinstance(target.value, ast.Name) and target.value.id == "sys")
            or (isinstance(target, ast.Name) and target.id == "path")
        )
        if not is_sys_path:
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) \
                    and _HOME_PREFIX.match(arg.value):
                found.append((getattr(node, "lineno", 0), arg.value))
    return found


def test_no_home_directory_paths_in_path_resolution():
    """(1) The crash. No sys.path manipulation may name a home directory."""
    offenders = []
    for p in _python_files():
        src = p.read_text(encoding="utf-8", errors="replace")
        for lineno, literal in _home_path_sys_path_calls(src):
            offenders.append(f"{p.relative_to(ENGINE_ROOT)}:{lineno}: {literal}")
    assert not offenders, (
        "sys.path manipulation must resolve relative to the repository, not a "
        "home directory:\n  " + "\n  ".join(offenders))


def test_the_guard_actually_detects_the_pattern_it_forbids():
    """The guard must fail on the old code, or it proves nothing.

    A scanner that silently matches nothing passes on any codebase. This feeds
    it the exact line that used to be at the top of every redteam script.
    """
    offending = 'import sys\nsys.path.insert(0, "/home/user/Morrison-Runtime-Governance")\n'
    assert _home_path_sys_path_calls(offending), "guard fails to detect a real offender"
    # And must NOT fire on attack-payload data or on prose describing the pattern.
    payload = 'CALL = {"tool": "read_file", "args": {"path": "/home/user/.ssh/id_rsa"}}\n'
    assert not _home_path_sys_path_calls(payload), "guard must not flag attack-payload data"
    prose = '"""Docs: we used to call sys.path.insert(0, "/home/user/x") here."""\n'
    assert not _home_path_sys_path_calls(prose), "guard must not flag its own documentation"


def test_service_path_resolves_relative_to_this_checkout():
    """(2) The silent wrong tree — the failure that actually mattered.

    The default must be derived from THIS file's location, so it follows the
    checkout rather than pointing at a fixed machine path.
    """
    from morrison_governance import test_kernel_redteam as tkr
    resolved = pathlib.Path(tkr.SERVICE_PATH).resolve()
    expected = (ENGINE_ROOT.parent / "resurrection-tech-enterprise"
                / "governance-service").resolve()
    if os.environ.get("MORRISON_SERVICE_PATH"):
        pytest.skip("MORRISON_SERVICE_PATH is set; the derived default is overridden")
    assert resolved == expected, (
        f"service path {resolved} is not derived from this checkout "
        f"({ENGINE_ROOT}); it must follow the repository, not a fixed path")


def test_redteam_helper_resolves_to_this_checkout():
    sys.path.insert(0, str(ENGINE_ROOT / "redteam"))
    try:
        import _repo_paths
    finally:
        sys.path.pop(0)
    assert pathlib.Path(_repo_paths.ROOT).resolve() == ENGINE_ROOT, (
        f"redteam ROOT {_repo_paths.ROOT} must be this checkout ({ENGINE_ROOT})")


def test_redteam_scripts_import_the_checkout_they_live_in():
    """The decisive test: run inside a COPY and confirm it imports the copy.

    Before the fix this failed silently — the script imported the original
    tree and reported on it. Copying rather than mocking is the only way to
    catch that, because the bug is invisible while both trees agree.
    """
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        copy = pathlib.Path(tmp) / "checkout"
        shutil.copytree(
            ENGINE_ROOT, copy,
            ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", "build", "dist"))

        # A sentinel that exists ONLY in the copy. If a script resolves paths
        # correctly it imports the copy and sees it.
        probe = copy / "redteam" / "_portability_probe.py"
        probe.write_text(
            "import sys, os\n"
            "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
            "import _repo_paths as _rp\n"
            "_rp.install()\n"
            "import morrison_governance\n"
            "print(morrison_governance.__file__)\n")

        out = subprocess.run(
            [sys.executable, str(probe)], capture_output=True, text=True,
            cwd=str(copy), timeout=120,
            # Scrub any override so the DERIVED default is what is tested.
            env={k: v for k, v in os.environ.items()
                 if k not in ("MORRISON_ROOT", "MORRISON_SERVICE_PATH", "PYTHONPATH")},
        )
        assert out.returncode == 0, f"probe failed: {out.stderr[-600:]}"
        loaded = pathlib.Path(out.stdout.strip()).resolve()
        assert str(loaded).startswith(str(copy.resolve())), (
            f"a script inside {copy} imported morrison_governance from {loaded} "
            f"— it is testing a different checkout than the one it lives in")


def test_redteam_scripts_skip_cleanly_without_the_service_repo():
    """A missing sibling repo is a missing input, not a governance failure.

    Exiting 0 with an explanation keeps that distinction; crashing would read
    in CI as though the engine were broken — which is exactly how this looked
    before (`ModuleNotFoundError: No module named 'cyber_rules'`).
    """
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["MORRISON_SERVICE_PATH"] = "/nonexistent/governance-service"
    out = subprocess.run(
        [sys.executable, str(ENGINE_ROOT / "redteam" / "evidence_test.py")],
        capture_output=True, text=True, env=env, timeout=120,
        cwd=str(ENGINE_ROOT))
    assert out.returncode == 0, (
        f"missing service repo must skip cleanly, not fail: {out.stderr[-400:]}")
    assert "SKIP" in out.stdout, f"the skip must be stated, not silent: {out.stdout[:300]}"
