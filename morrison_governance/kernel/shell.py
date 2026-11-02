"""Structural shell command classification.

Found while checking whether the SQL finding (VIOLATION_LEDGER `SQL-LEX-01`)
generalised: with `tool_manifest={"run_maintenance": ["data.read"]}` and the
command in a `command` argument, these were PERMITTED because the only shell
check was one regular expression (`rm -rf`, `mkfs`, `shred`, `dd if=`):

    find /data -delete
    find /data -exec rm {} +
    echo cm0gLXJmIC9kYXRh | base64 -d | sh
    $(printf "\\x72\\x6d") -rf /data

A value in a command argument IS a command, so it is read as one: split into
simple commands on `; && || | &` and newlines, wrappers (`sudo`, `env`,
`nohup`, `timeout`, `xargs` ...) peeled, and each program classified by what it
does. The posture is an ALLOWLIST: a program not known to be read-only is
`code.execute`, which the policy escalates. Command substitution, process
substitution, a program named by a variable, and text that does not tokenise
are dynamic and fail closed the same way.

Applied only to arguments that carry a command (`command`, `cmd`, `shell`,
`script`, ... or any string argument of a shell-family tool). Shell-shaped text
elsewhere is left to the lexical floor in `capabilities`.

Defence in depth: the guarantee is that the executor's OS identity cannot do
what policy forbids (see DEPLOYMENT.md, "Resource-side enforcement").

Deterministic: no clock, no RNG, no I/O.
"""

from __future__ import annotations

import posixpath
import re
import shlex

CAP_CODE_EXEC = "code.execute"
CAP_DATA_DESTRUCTIVE = "data.destructive"
CAP_INFRA_DESTRUCTIVE = "infra.destructive"
CAP_DATA_WRITE = "data.write"
CAP_PERSISTENCE = "persistence.establish"
CAP_SECURITY_CONTROL = "security_control.modify"
CAP_IAM_PRIVILEGED = "iam.privileged"
CAP_CREDENTIAL_CHANGE = "credential.change"
CAP_EXTERNAL_DATA_MOVE = "data.external_move"

COMMAND_KEYS = frozenset({"command", "cmd", "shell", "script", "cmdline",
                          "command_line", "commandline", "shell_command", "bash",
                          "sh", "exec", "run_command"})

READ_ONLY = frozenset({
    "ls", "dir", "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep",
    "rg", "ag", "wc", "stat", "du", "df", "pwd", "whoami", "id", "date", "echo",
    "printf", "file", "which", "type", "uname", "hostname", "sort", "uniq", "cut",
    "tr", "diff", "cmp", "md5sum", "sha1sum", "sha256sum", "sha512sum", "basename",
    "dirname", "realpath", "readlink", "test", "[", "true", "false", "ps", "uptime",
    "free", "jq", "column", "nl", "tac", "tree", "lsblk", "lscpu", "env", "printenv",
    "base64", "xxd", "od", "hexdump", "strings", "zcat", "gunzip", "zgrep",
})
DESTRUCTIVE = frozenset({
    "rm", "rmdir", "unlink", "shred", "srm", "wipe", "wipefs", "dd", "mke2fs",
    "fdisk", "sfdisk", "parted", "truncate", "blkdiscard", "fstrim", "format",
})
CODE = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "busybox",
    "eval", "source", ".", "python", "python2", "python3", "perl", "ruby", "node",
    "nodejs", "deno", "bun", "php", "lua", "awk", "gawk", "mawk", "nawk", "sed",
    "osascript", "powershell", "pwsh", "cmd", "su", "ssh", "parallel", "expect",
    "gdb", "vim", "vi", "emacs", "make", "npm", "npx", "pip", "pip3", "go",
    "cargo", "java", "docker", "podman", "kubectl", "helm", "terraform", "ansible",
    "aws", "gcloud", "az", "git",
})
PERSIST = frozenset({"crontab", "at", "batch", "launchctl", "chkconfig",
                     "update-rc.d", "schtasks"})
SECURITY = frozenset({"iptables", "ip6tables", "nft", "ufw", "firewall-cmd",
                      "setenforce", "auditctl", "aa-disable", "chattr", "sysctl"})
IAM = frozenset({"passwd", "chpasswd", "usermod", "useradd", "userdel", "adduser",
                 "deluser", "groupadd", "groupmod", "gpasswd", "visudo", "chown",
                 "chmod", "chgrp", "setfacl", "setcap"})
INFRA = frozenset({"kill", "killall", "pkill", "reboot", "shutdown", "halt",
                   "poweroff", "init", "telinit", "systemctl", "service", "umount",
                   "swapoff", "mount"})
EGRESS = frozenset({"curl", "wget", "scp", "rsync", "nc", "ncat", "netcat",
                    "socat", "ftp", "sftp", "telnet", "tftp", "mail", "sendmail"})
WRITE = frozenset({"mv", "cp", "tee", "ln", "install", "touch", "mkdir", "tar",
                   "zip", "unzip", "gzip", "split", "patch"})
# Programs that run their first non-option argument as another program.
WRAPPERS = frozenset({"sudo", "doas", "env", "nohup", "nice", "ionice", "timeout",
                      "time", "command", "builtin", "exec", "stdbuf", "chroot",
                      "setsid", "unbuffer", "caffeinate", "watch", "flock"})
# Programs that run commands they are given: classified as code AND recursed.
RUNNERS = frozenset({"xargs", "parallel", "find", "watch"})
_FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_FIND_WRITE = frozenset({"-delete", "-fprint", "-fprint0", "-fprintf", "-fls"})

_DYNAMIC = re.compile(r"\$\(|`|<\(|>\(|\$\{[^}]*[:/#%^,@]")
_OPERATORS = frozenset({";", "&", "&&", "||", "|", "|&", ";;", "(", ")", "{", "}",
                        "\n"})
_REDIRECT = re.compile(r"^\d*(>>?|>\||&>>?)$")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _program(token: str) -> str:
    name = posixpath.basename(token.replace("\\", ""))
    return name.lower()


def _simple_commands(tokens: list[str]) -> list[list[str]]:
    out: list[list[str]] = [[]]
    for t in tokens:
        if t in _OPERATORS:
            out.append([])
        else:
            out[-1].append(t)
    return [c for c in out if c]


def _classify_argv(argv: list[str], depth: int = 0) -> set[str]:
    caps: set[str] = set()
    if depth > 8:
        return {CAP_CODE_EXEC}
    i = 0
    # Redirections anywhere in the command.
    for k, t in enumerate(argv):
        if _REDIRECT.match(t) and k + 1 < len(argv):
            target = argv[k + 1]
            if target == "/dev/null":
                continue
            if target.startswith("/dev/"):
                caps |= {CAP_DATA_DESTRUCTIVE, CAP_INFRA_DESTRUCTIVE}
            else:
                caps.add(CAP_DATA_WRITE)
    argv = [t for k, t in enumerate(argv)
            if not _REDIRECT.match(t) and not (k > 0 and _REDIRECT.match(argv[k - 1]))
            and not re.match(r"^\d*<", t)]
    while i < len(argv) and _ASSIGN.match(argv[i]):
        i += 1
    if i >= len(argv):
        return caps
    head = argv[i]
    if head.startswith("$") or "*" in head or "?" in head:
        return caps | {CAP_CODE_EXEC}               # program chosen at run time
    prog = _program(head)
    rest = argv[i + 1:]

    if prog in WRAPPERS:
        j = 0
        while j < len(rest) and (rest[j].startswith("-") or _ASSIGN.match(rest[j])
                                 or (prog == "timeout" and re.match(r"^[\d.]+[smhd]?$", rest[j]))):
            j += 1
        if prog in ("sudo", "doas", "su"):
            caps.add(CAP_IAM_PRIVILEGED)
        if j >= len(rest):
            return caps
        return caps | _classify_argv(rest[j:], depth + 1)
    if prog == "find":
        flags = set(rest)
        if flags & _FIND_WRITE:
            caps |= {CAP_DATA_DESTRUCTIVE} if "-delete" in flags else {CAP_DATA_WRITE}
        for k, t in enumerate(rest):
            if t in _FIND_EXEC:
                sub = []
                for u in rest[k + 1:]:
                    if u in (";", "+", "\\;"):
                        break
                    sub.append(u)
                caps.add(CAP_CODE_EXEC)
                caps |= _classify_argv(sub, depth + 1)
        return caps
    if prog in ("xargs", "parallel"):
        j = 0
        while j < len(rest) and rest[j].startswith("-"):
            j += 1
        caps.add(CAP_CODE_EXEC)
        return caps | (_classify_argv(rest[j:], depth + 1) if j < len(rest) else set())
    if prog in READ_ONLY:
        if prog in ("env", "printenv") and rest and not rest[0].startswith("-"):
            return caps | _classify_argv(rest, depth + 1) if prog == "env" else caps
        return caps
    if prog in DESTRUCTIVE or prog.startswith("mkfs"):
        return caps | {CAP_DATA_DESTRUCTIVE, CAP_INFRA_DESTRUCTIVE}
    if prog in PERSIST:
        return caps | {CAP_PERSISTENCE, CAP_CODE_EXEC}
    if prog in SECURITY:
        return caps | {CAP_SECURITY_CONTROL}
    if prog in IAM:
        return caps | {CAP_IAM_PRIVILEGED, CAP_CREDENTIAL_CHANGE}
    if prog in INFRA:
        return caps | {CAP_INFRA_DESTRUCTIVE}
    if prog in EGRESS:
        return caps | {CAP_EXTERNAL_DATA_MOVE}
    if prog in WRITE:
        return caps | {CAP_DATA_WRITE}
    # CODE, and every program not listed: what it does is not known here.
    return caps | {CAP_CODE_EXEC}


def shell_capabilities(text: str) -> set[str]:
    """Capabilities of a command string. Fails closed to `code.execute` on
    dynamic constructs and on text that does not tokenise."""
    if not isinstance(text, str) or not text.strip():
        return set()
    caps: set[str] = set()
    if _DYNAMIC.search(text):
        caps.add(CAP_CODE_EXEC)
    try:
        lexer = shlex.shlex(text.replace("\\\n", " "), posix=True,
                            punctuation_chars=";&|()<>")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        tokens = []
        for tok in lexer:
            tokens.extend(["\n"] if tok == "\n" else [tok])
    except ValueError:
        return caps | {CAP_CODE_EXEC}
    # shlex keeps newlines inside whitespace-split tokens; split them out.
    flat: list[str] = []
    for t in tokens:
        parts = t.split("\n")
        for k, p in enumerate(parts):
            if k:
                flat.append("\n")
            if p:
                flat.append(p)
    for argv in _simple_commands(flat):
        caps |= _classify_argv(argv)
    return caps
