"""Disposable sandbox and the tool-effect semantics.

`apply_action` is the single definition of what a file-system tool does. The
executor applies it to the real sandbox; the global tier applies the same
function to a trusted in-memory snapshot to project a trajectory. The only
tool whose effects are NOT modelled is `run_tests`, which executes repository
code (including code the agent wrote) in a confined subprocess.

Nothing here decides admissibility. Nothing here executes model output as
code except `run_tests`, which runs the sandbox's own test suite.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parent / "templates"
TEMPLATE_SUFFIX = ".tmpl"
MAX_FILE_BYTES = 256 * 1024
MAX_PATH_CHARS = 200
TEST_TIMEOUT_S = 60

READ_ONLY_TOOLS = frozenset({"read_file", "list_files"})
FS_TOOLS = frozenset({"read_file", "list_files", "write_file", "delete_file",
                      "move_file", "run_command"})
EXEC_TOOLS = frozenset({"run_tests"})
ACTION_TOOLS = FS_TOOLS.union(EXEC_TOOLS)
REPORT_TOOL = "report_completion"

_SKIP_PARTS = {"__pycache__"}


class ToolError(Exception):
    """The action is malformed or outside the sandbox. Nothing was changed."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fs_hash(fs: dict) -> str:
    """Identity of a whole file-system state."""
    h = hashlib.sha256()
    for path in sorted(fs):
        h.update(path.encode("utf-8") + b"\0" + sha256_bytes(fs[path]).encode() + b"\n")
    return h.hexdigest()


def fs_diff(before: dict, after: dict) -> list:
    """Changed paths with before/after content hashes (None = absent)."""
    out = []
    for path in sorted(set(before) | set(after)):
        b, a = before.get(path), after.get(path)
        if b != a:
            out.append({"path": path,
                        "before_sha256": sha256_bytes(b) if b is not None else None,
                        "after_sha256": sha256_bytes(a) if a is not None else None})
    return out


def clean_path(raw) -> str:
    """Normalise an agent-supplied path; refuse anything that can leave the root."""
    if not isinstance(raw, str) or not raw.strip():
        raise ToolError("path must be a non-empty string")
    if "\0" in raw or len(raw) > MAX_PATH_CHARS:
        raise ToolError("invalid path")
    candidate = raw.strip().replace("\\", "/")
    if candidate.startswith("/") or re.match(r"^[A-Za-z]:", candidate) or candidate.startswith("~"):
        raise ToolError("absolute paths are outside the sandbox")
    norm = posixpath.normpath(candidate)
    if norm in (".", "") or norm == ".." or norm.startswith("../"):
        raise ToolError("path escapes the sandbox")
    if any(part in _SKIP_PARTS for part in norm.split("/")):
        raise ToolError("path is not addressable")
    return norm


def _need(args: dict, key: str):
    if key not in args:
        raise ToolError("missing argument '%s'" % key)
    return args[key]


def _content_bytes(value) -> bytes:
    if not isinstance(value, str):
        raise ToolError("content must be a string")
    data = value.encode("utf-8")
    if len(data) > MAX_FILE_BYTES:
        raise ToolError("content exceeds %d bytes" % MAX_FILE_BYTES)
    return data


def _target(fs: dict, raw) -> str:
    """A path that will be written. Refuses a path that differs from an
    existing one only by case: on a case-insensitive file system (macOS by
    default) it would silently overwrite the other file."""
    p = clean_path(raw)
    if p not in fs and any(q.lower() == p.lower() for q in fs):
        raise ToolError("%s collides with an existing path that differs only by case" % p)
    return p


def _is_dir(fs: dict, path: str) -> bool:
    prefix = path.rstrip("/") + "/"
    return any(p.startswith(prefix) for p in fs)


# ── simulated shell (no host command is ever run) ────────────────────────
def _sed(fs: dict, script: str, path: str) -> None:
    if len(script) < 4 or script[0] != "s":
        raise ToolError("sed: only s/OLD/NEW/[g] is supported")
    delim = script[1]
    parts = script[2:].split(delim)
    if len(parts) < 3:
        raise ToolError("sed: malformed expression")
    old, new, flags = parts[0], parts[1], parts[2]
    if path not in fs:
        raise ToolError("sed: %s: no such file" % path)
    try:
        pattern = re.compile(old)
    except re.error as e:
        raise ToolError("sed: bad pattern: %s" % e)
    text = fs[path].decode("utf-8", "replace")
    lines = text.split("\n")
    count = 0 if "g" in flags else 1
    fs[path] = "\n".join(pattern.sub(new, line, count=count) for line in lines).encode("utf-8")


def _run_one(fs: dict, argv: list) -> str:
    if not argv:
        return ""
    cmd, rest = argv[0], argv[1:]
    if cmd == "true":
        return ""
    if cmd == "rm":
        paths = [a for a in rest if not a.startswith("-")]
        force = any(a.startswith("-") and "f" in a for a in rest)
        recursive = any(a.startswith("-") and "r" in a.lower() for a in rest)
        if not paths:
            raise ToolError("rm: missing operand")
        for raw in paths:
            p = clean_path(raw)
            if p in fs:
                del fs[p]
            elif recursive and _is_dir(fs, p):
                for q in [q for q in fs if q.startswith(p + "/")]:
                    del fs[q]
            elif not force:
                raise ToolError("rm: %s: no such file" % p)
        return ""
    if cmd in ("mv", "cp"):
        if len(rest) != 2:
            raise ToolError("%s: expected SRC DST" % cmd)
        src, dst = clean_path(rest[0]), clean_path(rest[1])
        if src not in fs:
            raise ToolError("%s: %s: no such file" % (cmd, src))
        if _is_dir(fs, dst):
            dst = posixpath.join(dst, posixpath.basename(src))
        dst = _target(fs, dst)
        fs[dst] = fs[src]
        if cmd == "mv" and dst != src:
            del fs[src]
        return ""
    if cmd == "sed":
        if len(rest) != 3 or rest[0] != "-i":
            raise ToolError("sed: only `sed -i 's/OLD/NEW/[g]' FILE` is supported")
        _sed(fs, rest[1], _target(fs, rest[2]))
        return ""
    if cmd == "echo":
        for op in (">>", ">"):
            if op in rest:
                i = rest.index(op)
                if i != len(rest) - 2:
                    raise ToolError("echo: redirection target must be last")
                text = " ".join(rest[:i]) + "\n"
                p = _target(fs, rest[i + 1])
                prior = fs.get(p, b"") if op == ">>" else b""
                fs[p] = prior + _content_bytes(text)
                return ""
        return " ".join(rest) + "\n"
    if cmd == "cat":
        out = []
        for raw in rest:
            p = clean_path(raw)
            if p not in fs:
                raise ToolError("cat: %s: no such file" % p)
            out.append(fs[p].decode("utf-8", "replace"))
        return "".join(out)
    if cmd == "ls":
        prefix = clean_path(rest[0]) + "/" if rest else ""
        return "\n".join(sorted(p for p in fs if p.startswith(prefix))) + "\n"
    raise ToolError("unsupported command '%s' (the sandbox shell supports "
                    "rm, mv, cp, sed -i, echo [>|>>], cat, ls, true)" % cmd)


def run_shell(fs: dict, command) -> str:
    if not isinstance(command, str) or not command.strip():
        raise ToolError("command must be a non-empty string")
    try:
        tokens = shlex.split(command)
    except ValueError as e:
        raise ToolError("cannot parse command: %s" % e)
    for tok in tokens:
        if tok == "<" or any(bad in tok for bad in ("|", ";", "`", "$(")):
            raise ToolError("unsupported shell syntax in %r (no pipes, ';', "
                            "substitution or input redirection)" % tok)
    out, segment = [], []
    for tok in tokens + ["&&"]:
        if tok == "&&":
            out.append(_run_one(fs, segment))
            segment = []
        else:
            segment.append(tok)
    return "".join(out)


def apply_action(fs: dict, action: dict):
    """Pure tool semantics. Returns (new_fs, observation). Raises ToolError.

    `run_tests` is NOT applied here (it is not a pure function of `fs`); the
    caller decides how to treat it. The global tier treats it as no effect.
    """
    tool = action.get("tool")
    args = action.get("args")
    if not isinstance(args, dict):
        raise ToolError("args must be an object")
    new = dict(fs)
    if tool == "read_file":
        p = clean_path(_need(args, "path"))
        if p not in fs:
            raise ToolError("%s: no such file" % p)
        return new, fs[p].decode("utf-8", "replace")
    if tool == "list_files":
        prefix = args.get("path") or ""
        prefix = clean_path(prefix) + "/" if prefix else ""
        return new, "\n".join(sorted(p for p in fs if p.startswith(prefix)))
    if tool == "write_file":
        p = _target(fs, _need(args, "path"))
        new[p] = _content_bytes(_need(args, "content"))
        return new, "wrote %s (%d bytes)" % (p, len(new[p]))
    if tool == "delete_file":
        p = clean_path(_need(args, "path"))
        if p not in fs:
            raise ToolError("%s: no such file" % p)
        del new[p]
        return new, "deleted %s" % p
    if tool == "move_file":
        src, dst = clean_path(_need(args, "src")), _target(fs, _need(args, "dst"))
        if src not in fs:
            raise ToolError("%s: no such file" % src)
        new[dst] = new.pop(src)
        return new, "moved %s -> %s" % (src, dst)
    if tool == "run_command":
        out = run_shell(new, _need(args, "command"))
        return new, out or "ok"
    if tool == "run_tests":
        return new, "(run_tests is not modelled)"
    raise ToolError("unknown tool '%s'" % tool)


# ── OS confinement for code that runs in the sandbox ─────────────────────
def _sandbox_exec_profile(writable: list) -> str:
    allow = " ".join('(subpath "%s")' % w.replace('"', "") for w in writable)
    return ("(version 1)(allow default)(deny network*)"
            "(deny file-write* (require-not (require-any %s "
            '(literal "/dev/null") (literal "/dev/tty"))))' % allow)


def confinement(writable: list):
    """(argv prefix, label). Best available OS confinement on this host."""
    if sys.platform == "darwin" and os.path.exists("/usr/bin/sandbox-exec"):
        real = [os.path.realpath(w) for w in writable]
        return ["/usr/bin/sandbox-exec", "-p", _sandbox_exec_profile(real)], "macos-sandbox-exec:no-network,writes-confined"
    if sys.platform.startswith("linux") and shutil.which("unshare"):
        try:
            ok = subprocess.run(["unshare", "-rn", "true"], capture_output=True,
                                timeout=5).returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
        if ok:
            return ["unshare", "-rn"], "linux-unshare:no-network"
    return [], "none:rlimits-only"


def _limits():                                       # pragma: no cover - child process
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024,) * 2)
    except (ImportError, ValueError, OSError):
        pass


def run_python(root: str, argv: list, tmpdir: str, timeout: int = TEST_TIMEOUT_S):
    """Run `python -I -B <argv>` with cwd=root under the best confinement."""
    prefix, label = confinement([root, tmpdir])
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
           "TMPDIR": tmpdir, "HOME": tmpdir, "LC_ALL": "C.UTF-8"}
    cmd = prefix + [sys.executable, "-I", "-B"] + list(argv)
    try:
        proc = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True,
                              timeout=timeout,
                              preexec_fn=_limits if os.name == "posix" else None)
        return proc.returncode, proc.stdout, proc.stderr, label
    except subprocess.TimeoutExpired:
        return -9, "", "timeout after %ss" % timeout, label


class Sandbox:
    """One disposable scenario checkout on disk."""

    def __init__(self, scenario_id: str, base_dir: str):
        src = TEMPLATES / scenario_id
        if not src.is_dir():
            raise ValueError("unknown scenario template %r" % scenario_id)
        self.scenario_id = scenario_id
        self.base = os.path.realpath(base_dir)
        self.root = tempfile.mkdtemp(prefix="sandbox-%s-" % scenario_id, dir=self.base)
        self.tmp = tempfile.mkdtemp(prefix="sandbox-tmp-", dir=self.base)
        for path in sorted(src.rglob("*" + TEMPLATE_SUFFIX)):
            rel = path.relative_to(src).as_posix()[:-len(TEMPLATE_SUFFIX)]
            dest = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(path, dest)
        self.baseline = self.snapshot()

    @staticmethod
    def template_files(scenario_id: str) -> dict:
        src = TEMPLATES / scenario_id
        return {p.relative_to(src).as_posix()[:-len(TEMPLATE_SUFFIX)]: p.read_bytes()
                for p in sorted(src.rglob("*" + TEMPLATE_SUFFIX))}

    def snapshot(self) -> dict:
        out = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_PARTS)
            for name in filenames:
                if name.endswith(".pyc"):
                    continue
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    continue
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                with open(full, "rb") as handle:
                    out[rel] = handle.read()
        return out

    def state_hash(self) -> str:
        return fs_hash(self.snapshot())

    def _resolve(self, rel: str) -> str:
        full = os.path.realpath(os.path.join(self.root, rel))
        if not (full == self.root or full.startswith(self.root + os.sep)):
            raise ToolError("path escapes the sandbox")
        return full

    def materialise(self, new_fs: dict) -> None:
        """Make the on-disk tree equal `new_fs`."""
        current = self.snapshot()
        for rel in sorted(set(current) - set(new_fs)):
            os.remove(self._resolve(rel))
        for rel, data in sorted(new_fs.items()):
            if current.get(rel) != data:
                full = self._resolve(rel)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "wb") as handle:
                    handle.write(data)

    def run_tests(self):
        code, out, err, label = run_python(
            self.root, ["-m", "unittest", "discover", "-s", "tests", "-t", "."], self.tmp)
        tail = (err or out)[-1500:]
        return code == 0, "exit=%s confinement=%s\n%s" % (code, label, tail), label

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)


def copy_fs_to_dir(fs: dict, root: str) -> None:
    for rel, data in fs.items():
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(data)
