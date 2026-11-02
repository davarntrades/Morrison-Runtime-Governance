"""Deployer self-test for obvious complete-mediation bypass paths.

Morrison governs what calls it. Every claim it makes is conditional on T1:
every consequential executor is reachable only through the kernel
(docs/research/COMPLETE_MEDIATION_ANALYSIS.md). That is a property of the DEPLOYMENT, and
no library can prove it. This self-test can only find OBVIOUS violations, and
it must be run from where the agent runs: the same container, OS identity,
environment and network position. Run anywhere else, it tests the wrong thing.

    python -m morrison_governance.mediation_selftest
    python -m morrison_governance.mediation_selftest --network --json
    python -m morrison_governance.mediation_selftest \\
        --governance-path /etc/morrison --egress-probe example.com:443 \\
        --resource-probe https://db-gateway.internal/healthz-mutation-dry-run

Checks (M-numbers refer to docs/research/COMPLETE_MEDIATION_ANALYSIS.md):

  M1  credentials   secret-shaped environment variables and readable
                    credential files. Names and paths are reported, VALUES
                    are never read or printed.
  M4  egress        (--network) direct TCP to the cloud metadata service and
                    to --egress-probe targets, bypassing any configured proxy.
                    A successful connect means egress is not default-deny.
  M2/M3 resource    (--resource-probe URL) a request carrying NO execution
                    lease must be refused by the resource (401/403). Point it
                    only at an endpoint where acceptance is harmless.
  M6  config        --governance-path files (policy, manifest, continuity
                    store, keys) must not be writable by this identity.
  shell             interpreters and a shell on PATH, and whether this process
                    can spawn one. Informational unless --no-shell-expected.
  MCP               MCP client configurations found on disk, listing servers
                    that do not go through --mcp-gateway.
  tools             `audit_tools(registry)` (Python API): every tool callable
                    an agent framework will invoke must be a Morrison-governed
                    wrapper.

Exit status: 0 no FAIL and no WARN, 1 any FAIL, 2 WARN only.

What a pass means: none of these OBVIOUS bypasses was found from here. It does
not establish complete mediation. Paths this cannot see include credentials
baked into tools' own configuration, sockets inherited from a parent, other
processes in the same network namespace, and anything the executor itself
does after a valid lease.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlparse

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"

# Environment variable NAMES that conventionally hold credentials.
_SECRET_ENV = re.compile(
    r"(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|PASS|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|"
    r"CREDENTIALS?|AUTH|SESSION_?KEY|CLIENT_?SECRET|DSN)($|_)|"
    r"^(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GOOGLE_APPLICATION_CREDENTIALS|"
    r"AZURE_CLIENT_SECRET|DATABASE_URL|REDIS_URL|MONGO(DB)?_URI|GITHUB_TOKEN|"
    r"GH_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|KUBECONFIG|VAULT_TOKEN|NPM_TOKEN)$",
    re.I)
# Names that look secret-shaped but are configuration, not credentials.
_NOT_SECRET_ENV = re.compile(r"(_FILE|_PATH|_URL_PATH|_ENDPOINT|_REGION|_HOST|_PORT)$", re.I)

_CREDENTIAL_FILES = (
    "~/.aws/credentials", "~/.aws/config", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
    "~/.ssh/id_ecdsa", "~/.ssh/id_dsa", "~/.kube/config", "~/.docker/config.json",
    "~/.netrc", "~/.pgpass", "~/.my.cnf", "~/.git-credentials", "~/.npmrc",
    "~/.pypirc", "~/.vault-token", "~/.config/gcloud/credentials.db",
    "~/.config/gcloud/application_default_credentials.json",
    "~/.azure/accessTokens.json", "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/run/secrets", "/etc/shadow",
)
_METADATA_ENDPOINTS = (("169.254.169.254", 80), ("metadata.google.internal", 80),
                       ("100.100.100.200", 80))
_SHELLS = ("sh", "bash", "zsh", "dash", "python3", "python", "node", "perl", "ruby")
_MCP_CONFIGS = (
    ".mcp.json", "~/.mcp.json", "~/.claude.json", "~/.claude/settings.json",
    "~/.config/claude/claude_desktop_config.json",
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.cursor/mcp.json", "~/.codeium/windsurf/mcp_config.json",
    "~/.config/Code/User/settings.json",
)


@dataclass
class Finding:
    check: str
    status: str
    summary: str
    details: list = field(default_factory=list)
    condition: str = ""


# ── M1: credentials held by the agent ─────────────────────────────────────

def check_environment(env: Optional[Mapping[str, str]] = None) -> Finding:
    env = os.environ if env is None else env
    names = sorted(k for k, v in env.items()
                   if v and _SECRET_ENV.search(k) and not _NOT_SECRET_ENV.search(k))
    if names:
        return Finding("credentials.environment", FAIL,
                       f"{len(names)} secret-shaped environment variable(s) visible to "
                       f"the agent; an agent holding a credential needs no tool",
                       names, "M1")
    return Finding("credentials.environment", PASS,
                   "no secret-shaped environment variables visible", [], "M1")


def check_credential_files(paths: Iterable[str] = _CREDENTIAL_FILES,
                           home: Optional[str] = None) -> Finding:
    found = []
    for raw in paths:
        p = Path(raw.replace("~", home, 1) if home and raw.startswith("~")
                 else os.path.expanduser(raw))
        try:
            if p.is_dir():
                readable = os.access(p, os.R_OK | os.X_OK) and any(True for _ in p.iterdir())
            else:
                readable = p.is_file() and os.access(p, os.R_OK)
        except OSError:
            readable = False
        if readable:
            found.append(str(p))
    if found:
        return Finding("credentials.files", FAIL,
                       f"{len(found)} credential location(s) readable by this identity "
                       f"(contents not read)", found, "M1")
    return Finding("credentials.files", PASS,
                   "no known credential location readable", [], "M1")


# ── M4: network egress ────────────────────────────────────────────────────

def _connects(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_egress(targets: Iterable[tuple[str, int]], timeout: float = 2.0,
                 metadata: Iterable[tuple[str, int]] = _METADATA_ENDPOINTS) -> list[Finding]:
    out = []
    open_meta = [f"{h}:{p}" for h, p in metadata if _connects(h, p, timeout)]
    out.append(Finding(
        "egress.metadata", FAIL if open_meta else PASS,
        ("cloud metadata service reachable directly: it hands role credentials "
         "to any plain GET" if open_meta else "metadata service not reachable"),
        open_meta, "M1/M4"))
    open_direct = [f"{h}:{p}" for h, p in targets if _connects(h, p, timeout)]
    if targets:
        out.append(Finding(
            "egress.direct", FAIL if open_direct else PASS,
            ("direct outbound TCP succeeded without the proxy: egress is not "
             "default-deny" if open_direct else "direct outbound TCP refused"),
            open_direct, "M4"))
    return out


# ── M2/M3: the resource refuses a lease-less request ─────────────────────

def check_resource(url: str, timeout: float = 5.0) -> Finding:
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, method="POST", data=b"{}",
                                 headers={"Content-Type": "application/json",
                                          "X-Morrison-Selftest": "no-lease"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310
            code = resp.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    except (urllib.error.URLError, OSError) as exc:
        return Finding("resource.lease_required", WARN,
                       f"resource probe could not connect ({exc}); not tested",
                       [url], "M2/M3")
    if code in (401, 403):
        return Finding("resource.lease_required", PASS,
                       f"resource refused a request without a lease (HTTP {code})",
                       [url], "M2/M3")
    return Finding("resource.lease_required", FAIL,
                   f"resource answered HTTP {code} to a request carrying no lease: "
                   f"it does not require Morrison authorisation", [url], "M2/M3")


# ── M6: the agent cannot edit its governor ───────────────────────────────

def check_governance_paths(paths: Iterable[str]) -> Finding:
    writable = []
    for raw in paths:
        p = Path(raw).expanduser()
        targets = [p] + (list(p.rglob("*")) if p.is_dir() else [])
        writable += [str(t) for t in targets if t.exists() and os.access(t, os.W_OK)]
    if writable:
        return Finding("config.writable", FAIL,
                       f"{len(writable)} governance file(s) writable by the agent's identity",
                       writable[:50], "M6")
    return Finding("config.writable", PASS, "governance paths not writable", [], "M6")


# ── shell ─────────────────────────────────────────────────────────────────

def check_shell(expect_none: bool = False) -> Finding:
    available = [s for s in _SHELLS if shutil.which(s)]
    spawn = False
    if available:
        try:
            spawn = subprocess.run([shutil.which(available[0]), "-c", "exit 0"],
                                   capture_output=True, timeout=5,
                                   check=False).returncode == 0
        except (OSError, subprocess.SubprocessError):
            spawn = False
    if not available:
        return Finding("shell", PASS, "no shell or interpreter on PATH", [], "M4")
    status = FAIL if expect_none and spawn else WARN
    return Finding("shell", status,
                   ("this identity can spawn " + available[0] + "; any shell tool the agent "
                    "is given must be governed_run or a governed wrapper, and the sandbox "
                    "must lack destructive privileges") if spawn else
                   "interpreters on PATH but spawning failed",
                   available, "M4")


# ── MCP ───────────────────────────────────────────────────────────────────

def _mcp_servers(doc: Any) -> dict:
    if not isinstance(doc, dict):
        return {}
    servers = dict(doc.get("mcpServers") or doc.get("mcp_servers") or {})
    for value in doc.values():                 # nested per-project configs
        if isinstance(value, dict) and isinstance(value.get("mcpServers"), dict):
            servers.update(value["mcpServers"])
    return servers


def check_mcp(config_paths: Iterable[str] = _MCP_CONFIGS,
              gateway: str = "", cwd: Optional[str] = None) -> Finding:
    ungoverned, seen = [], []
    for raw in config_paths:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = Path(cwd or os.getcwd()) / p
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for name, spec in _mcp_servers(doc).items():
            seen.append(f"{p}:{name}")
            text = json.dumps(spec, sort_keys=True)
            if not gateway or gateway not in text:
                ungoverned.append(f"{p}:{name}")
    if not seen:
        return Finding("mcp", PASS, "no MCP client configuration found", [], "M2/M3")
    if ungoverned:
        return Finding("mcp", WARN,
                       f"{len(ungoverned)} MCP server(s) not routed through the Morrison "
                       f"gateway{' ' + repr(gateway) if gateway else ' (none declared)'}; "
                       f"wrap their call_tool with wrap_mcp_call_tool or route via the gateway",
                       ungoverned, "M2/M3")
    return Finding("mcp", PASS, "every MCP server goes through the gateway", seen, "M2/M3")


# ── tools (Python API) ────────────────────────────────────────────────────

def is_governed(tool: Any) -> bool:
    """Whether a callable/tool object is a Morrison-governed wrapper."""
    if getattr(tool, "__morrison_governed__", False):
        return True
    for attr in ("func", "coroutine", "_run", "run", "invoke", "__call__"):
        inner = getattr(tool, attr, None)
        if inner is not None and getattr(inner, "__morrison_governed__", False):
            return True
    return False


def audit_tools(registry: Mapping[str, Any]) -> Finding:
    """Every tool an agent can invoke must be governed. Pass the framework's
    registry ({name: tool}) as the agent will see it."""
    bare = sorted(name for name, tool in registry.items() if not is_governed(tool))
    if bare:
        return Finding("tools.registry", FAIL,
                       f"{len(bare)} tool(s) the agent can call are not Morrison-governed",
                       bare, "M2")
    return Finding("tools.registry", PASS, f"all {len(registry)} tools governed", [], "M2")


# ── runner ────────────────────────────────────────────────────────────────

def _target(text: str) -> tuple[str, int]:
    if "://" in text:
        u = urlparse(text)
        return u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
    host, _, port = text.rpartition(":")
    return (host, int(port)) if host else (text, 443)


def run(argv: Optional[list] = None) -> tuple[list[Finding], int]:
    p = argparse.ArgumentParser(prog="python -m morrison_governance.mediation_selftest",
                                description=__doc__.splitlines()[0])
    p.add_argument("--network", action="store_true",
                   help="probe the metadata service and --egress-probe targets")
    p.add_argument("--egress-probe", action="append", default=[],
                   help="host:port that must NOT be reachable directly")
    p.add_argument("--resource-probe", action="append", default=[],
                   help="URL that must refuse a lease-less request (harmless endpoint only)")
    p.add_argument("--governance-path", action="append", default=[])
    p.add_argument("--mcp-gateway", default="",
                   help="substring identifying the Morrison MCP gateway in server configs")
    p.add_argument("--mcp-config", action="append", default=[])
    p.add_argument("--no-shell-expected", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    findings = [check_environment(), check_credential_files(),
                check_shell(args.no_shell_expected),
                check_mcp(args.mcp_config or _MCP_CONFIGS, args.mcp_gateway)]
    if args.governance_path:
        findings.append(check_governance_paths(args.governance_path))
    if args.network or args.egress_probe:
        findings += check_egress([_target(t) for t in args.egress_probe])
    else:
        findings.append(Finding("egress", SKIP, "network probes not run (pass --network)"))
    for url in args.resource_probe:
        findings.append(check_resource(url))

    statuses = {f.status for f in findings}
    code = 1 if FAIL in statuses else 2 if WARN in statuses else 0
    if args.json:
        print(json.dumps({"exit": code, "findings": [asdict(f) for f in findings],
                          "scope": "obvious bypasses visible from this process only"},
                         indent=2))
    else:
        for f in findings:
            print(f"{f.status:4s}  {f.check:26s} {f.summary}")
            for d in f.details[:20]:
                print(f"        - {d}")
        print("\nA pass means no OBVIOUS bypass was visible from this process. It does "
              "not establish complete mediation (see docs/research/COMPLETE_MEDIATION_ANALYSIS.md).")
    return findings, code


def main(argv: Optional[list] = None) -> int:
    return run(argv)[1]


if __name__ == "__main__":
    sys.exit(main())
