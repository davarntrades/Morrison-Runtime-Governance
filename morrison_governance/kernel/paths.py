"""Structural classification of filesystem paths.

Found while checking whether the SQL finding (VIOLATION_LEDGER `SQL-LEX-01`)
generalised: with `tool_manifest={"read_file": ["data.read"]}` these were
PERMITTED, because credential files were recognised by substrings of the
flattened text (`id_rsa`, `credential`, `passwd`, `.env`) and by Ω rules that
read the raw argument:

    /etc/sh*dow                  a glob the tool expands to /etc/shadow
    %2fetc%2fshadow              percent-encoded
    ~/.ssh/id_ed25519            a key type the substring list did not name
    ~/.netrc  ~/.pgpass  ~/.kube/config  ~/.docker/config.json
    /proc/self/environ           the process's environment, i.e. its secrets

A path argument is now canonicalised (percent-decoding, Unicode folding,
backslashes, `..` segments, repeated slashes, `~`) and matched against a table
of credential locations by PATH SHAPE, with glob patterns in the argument
matched the other way round (does the pattern reach a credential location?).

Still a list, so still incomplete; the guarantee is that the executor's OS
identity cannot read these files (DEPLOYMENT.md, "Resource-side enforcement").

Deterministic: no clock, no RNG, no I/O.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re

CAP_CREDENTIAL_READ = "credential.read"
CAP_CREDENTIAL_CHANGE = "credential.change"
CAP_PERSISTENCE = "persistence.establish"

PATH_KEYS = frozenset({"path", "paths", "file", "files", "filename", "file_name",
                       "filepath", "file_path", "src", "source", "source_path",
                       "dir", "directory", "folder", "glob", "pattern", "location",
                       "target", "target_path", "dest_path", "output", "input"})

# Credential and secret locations, as fnmatch patterns over a canonical
# absolute path ('*' matches across '/'). Each has a CONCRETE example so a glob
# in the argument can be tested against it.
_CREDENTIAL_LOCATIONS: tuple[tuple[str, str], ...] = (
    ("*/etc/shadow", "/etc/shadow"),
    ("*/etc/gshadow", "/etc/gshadow"),
    ("*/etc/master.passwd", "/etc/master.passwd"),
    ("*/etc/sudoers", "/etc/sudoers"),
    ("*/etc/sudoers.d/*", "/etc/sudoers.d/admin"),
    ("*/etc/ssh/ssh_host_*key", "/etc/ssh/ssh_host_ed25519_key"),
    ("*/.ssh/id_*", "/root/.ssh/id_ed25519"),
    ("*/.ssh/*_key", "/root/.ssh/deploy_key"),
    ("*/.ssh/authorized_keys*", "/root/.ssh/authorized_keys"),
    ("*/.aws/credentials", "/root/.aws/credentials"),
    ("*/.aws/config", "/root/.aws/config"),
    ("*/.azure/*", "/root/.azure/accessTokens.json"),
    ("*/.config/gcloud/*", "/root/.config/gcloud/credentials.db"),
    ("*/.kube/config", "/root/.kube/config"),
    ("*/.docker/config.json", "/root/.docker/config.json"),
    ("*/.netrc", "/root/.netrc"),
    ("*/_netrc", "/root/_netrc"),
    ("*/.pgpass", "/root/.pgpass"),
    ("*/.my.cnf", "/root/.my.cnf"),
    ("*/.git-credentials", "/root/.git-credentials"),
    ("*/.npmrc", "/root/.npmrc"),
    ("*/.pypirc", "/root/.pypirc"),
    ("*/.vault-token", "/root/.vault-token"),
    ("*/.env", "/app/.env"),
    ("*/.env.*", "/app/.env.production"),
    ("*/proc/*/environ", "/proc/self/environ"),
    ("*/proc/*/mem", "/proc/self/mem"),
    ("*/run/secrets/*", "/run/secrets/db_password"),
    ("*/var/run/secrets/*", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
    ("*/.gnupg/*", "/root/.gnupg/private-keys-v1.d/key.key"),
    ("*/.password-store/*", "/root/.password-store/bank.gpg"),
    ("*/library/keychains/*", "/users/u/library/keychains/login.keychain-db"),
    ("*.pem", "/etc/tls/server.pem"),
    ("*.key", "/etc/tls/server.key"),
    ("*.p12", "/etc/tls/server.p12"),
    ("*.pfx", "/etc/tls/server.pfx"),
    ("*.jks", "/etc/tls/server.jks"),
    ("*.keystore", "/etc/tls/server.keystore"),
    ("*/.bash_history", "/root/.bash_history"),
    ("*/.zsh_history", "/root/.zsh_history"),
    ("*/.psql_history", "/root/.psql_history"),
    ("*/.mysql_history", "/root/.mysql_history"),
)
# Writing one of these establishes access that outlives the session.
_PERSISTENCE_LOCATIONS = ("*/.ssh/authorized_keys*", "*/etc/sudoers", "*/etc/sudoers.d/*",
                          "*/etc/cron*", "*/var/spool/cron/*", "*/.bashrc", "*/.profile",
                          "*/.zshrc", "*/etc/systemd/*", "*/library/launch*")

_LOOKS_LIKE_PATH = re.compile(r"^(?:/|~|\.{1,2}/|[A-Za-z]:[\\/]|\\\\|file:)", re.I)
_GLOB = re.compile(r"[*?\[]")
_WRITE_VERB = re.compile(r"(write|put|save|append|create|update|modify|edit|"
                         r"overwrite|replace|copy|move|upload|patch)", re.I)


def canonical_path(raw: str) -> str:
    """Fold a path argument to one comparable absolute form."""
    from morrison_governance.kernel.normalize import normalize_text
    p = normalize_text(str(raw)).strip().strip("\"'")
    if p.lower().startswith("file:"):
        p = re.sub(r"^file:(//[^/]*)?", "", p, flags=re.I)
    p = p.replace("\\", "/")
    p = re.sub(r"^[A-Za-z]:", "", p)
    if p.startswith("~"):
        rest = p[1:]                       # ~/x is the agent's home, ~user/x another's
        p = "/home/_" + rest if rest[:1] in ("", "/") else "/home/" + rest
    if not p.startswith("/"):
        p = "/" + p
    p = posixpath.normpath(p)
    p = re.sub(r"/+", "/", p)
    return p.lower()


def _matches(path: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(path, pat) for pat in patterns)


def credential_location(raw: str) -> bool:
    """Whether a path argument reaches a credential location, either directly
    or as a glob pattern the tool will expand."""
    path = canonical_path(raw)
    if _matches(path, (pat for pat, _ in _CREDENTIAL_LOCATIONS)):
        return True
    if _GLOB.search(path):
        return any(fnmatch.fnmatchcase(example, path) or
                   fnmatch.fnmatchcase(example, "*" + path)
                   for _, example in _CREDENTIAL_LOCATIONS)
    return False


def path_capabilities(tool: str, args: dict) -> set[str]:
    from morrison_governance.kernel.normalize import BudgetExhausted, iter_pairs
    caps: set[str] = set()
    writes = bool(_WRITE_VERB.search(str(tool)))
    try:
        pairs = list(iter_pairs(args or {}))
    except BudgetExhausted:
        return caps
    for key, value in pairs:
        if not isinstance(value, str) or not value.strip() or len(value) > 4096:
            continue
        k = str(key).strip().lower()
        if k not in PATH_KEYS and not (_LOOKS_LIKE_PATH.match(value.strip())
                                       and not re.search(r"\s", value.strip())):
            continue
        if credential_location(value):
            caps.add(CAP_CREDENTIAL_READ)
            if writes:
                caps.add(CAP_CREDENTIAL_CHANGE)
        if writes and _matches(canonical_path(value), _PERSISTENCE_LOCATIONS):
            caps.add(CAP_PERSISTENCE)
    return caps
