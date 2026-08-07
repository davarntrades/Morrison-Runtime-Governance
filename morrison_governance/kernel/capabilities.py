"""Canonical capability classification.

The red-team finding this module closes:

    Ω coverage was exact tool-name set membership. `drop_database` was blocked;
    `execute_sql {"sql": "DROP DATABASE prod;"}` executed. 7 of 7 semantically
    identical actions evaded governance purely by renaming the tool. Because
    real cloud SDK verbs are `update_*` / `set_*` config writes, entire classes
    (security-control disablement) scored 0%.

Actions are classified into CANONICAL CAPABILITIES from four independent
signals, so that equivalent actions resolve to the same governed capability
regardless of what the tool is called:

  1. a declared tool manifest (authoritative when present)
  2. tool-name morphology (verb/object families, not exact names)
  3. argument SHAPE and VALUE semantics — `{"mfa_required": false}` is a
     security-control modification whatever the tool is called
  4. nested/embedded payloads — SQL text, shell text, deferred-action wrappers

Explicit tool-name rules are preserved as one signal among four; safety no
longer depends on exact naming.

Deterministic: no clock, no RNG, no I/O.
"""

from __future__ import annotations

import re
from typing import Any

# ── Canonical capability vocabulary ─────────────────────────────────────
CAP_DATA_DESTRUCTIVE = "data.destructive"          # drop/truncate/mass-delete data
CAP_INFRA_DESTRUCTIVE = "infra.destructive"        # delete/terminate infrastructure
CAP_BACKUP_DESTRUCTIVE = "backup.destructive"      # destroy recoverability
CAP_SECURITY_CONTROL = "security_control.modify"   # MFA/EDR/firewall/audit/monitoring
CAP_LOG_TAMPER = "log.tamper"                      # delete/alter audit evidence
CAP_CREDENTIAL_READ = "credential.read"
CAP_CREDENTIAL_CHANGE = "credential.change"        # reset/rotate/issue credentials
CAP_IAM_PRIVILEGED = "iam.privileged"              # roles, policies, permissions
CAP_EXTERNAL_DATA_MOVE = "data.external_move"      # egress beyond the trust boundary
CAP_PAYMENT = "payment.move_funds"
CAP_PERSISTENCE = "persistence.establish"          # cron/webhook/key/service
CAP_CODE_EXEC = "code.execute"
CAP_DELEGATION = "agent.delegate"
CAP_DATA_READ = "data.read"
CAP_WILDCARD_SCOPE = "scope.wildcard"              # '*'/all/organization scope

ALL_CAPABILITIES = frozenset({
    CAP_DATA_DESTRUCTIVE, CAP_INFRA_DESTRUCTIVE, CAP_BACKUP_DESTRUCTIVE,
    CAP_SECURITY_CONTROL, CAP_LOG_TAMPER, CAP_CREDENTIAL_READ,
    CAP_CREDENTIAL_CHANGE, CAP_IAM_PRIVILEGED, CAP_EXTERNAL_DATA_MOVE,
    CAP_PAYMENT, CAP_PERSISTENCE, CAP_CODE_EXEC, CAP_DELEGATION,
    CAP_DATA_READ, CAP_WILDCARD_SCOPE,
})

# ── Morphology: verbs and objects, not whole tool names ─────────────────
_DESTRUCTIVE_VERB = re.compile(
    r"(drop|delete|destroy|terminate|purge|wipe|erase|shred|truncate|remove|"
    r"decommission|teardown|tear_down|reclaim|revoke|kill|obliterate|"
    r"deprovision|expire|prune|format|mkfs|rm)", re.I)
_DISABLE_VERB = re.compile(
    r"(disable|deactivate|turn_?off|switch_?off|suspend|bypass|weaken|relax|"
    r"unenforce|opt_?out|uninstall|stop)", re.I)
_CREATE_VERB = re.compile(r"(create|add|install|register|provision|issue|mint|grant|spawn)", re.I)
_MODIFY_VERB = re.compile(r"(update|modify|set|change|patch|configure|edit|alter|put)", re.I)

_DB_OBJECT = re.compile(r"(database|\bdb\b|table|schema|dataset|collection|index|sql|query|migration)", re.I)
_INFRA_OBJECT = re.compile(
    r"(bucket|cluster|instance|instances|vm|node|container|pod|volume|disk|"
    r"deployment|namespace|stack|environment|server|host|capacity|fleet|"
    r"resource|service|storage|object)", re.I)
_BACKUP_OBJECT = re.compile(r"(backup|snapshot|restore|vault|archive|retention|recovery|replica)", re.I)
_SECCTRL_OBJECT = re.compile(
    r"(mfa|2fa|multi_?factor|two_?factor|otp|firewall|edr|antivirus|\bav\b|"
    r"defender|endpoint_?protection|security|audit|logging|monitor|monitoring|"
    r"alert|alerting|guard|governance|compliance|waf|ids|ips|siem|"
    r"deletion_?protection|encryption|tls|ssl|auth|authentication|"
    r"password_?policy|session|interlock|safeguard|protection)", re.I)
_LOG_OBJECT = re.compile(r"(log|logs|audit|trail|event_?log|history|forensic|evidence)", re.I)
_CRED_OBJECT = re.compile(
    r"(password|passwd|credential|secret|api_?key|access_?key|token|"
    r"private_?key|ssh_?key|id_rsa|keychain|vault|certificate|\bcert\b)", re.I)
_IAM_OBJECT = re.compile(
    r"(role|policy|permission|permissions|iam|acl|binding|entitlement|"
    r"privilege|group|membership|scope|grant|admin|service_?account)", re.I)
_PAYMENT_OBJECT = re.compile(
    r"(payment|transfer|refund|payout|settle|settlement|remit|disburse|"
    r"wire|ach|invoice|charge|withdraw|funds|treasury|payee|beneficiary)", re.I)
_PERSIST_OBJECT = re.compile(
    r"(cron|crontab|schedule|scheduled_?task|webhook|hook|trigger|daemon|"
    r"startup|autorun|service|agent|listener|subscription|access_?key|"
    r"ssh_?key|backdoor|sudoers)", re.I)
_EGRESS_OBJECT = re.compile(
    r"(upload|export|send|post|publish|share|transmit|sync|push|email|mail|"
    r"webhook|ship|emit|forward|copy|replicate|stream)", re.I)
_EXEC_OBJECT = re.compile(
    r"(shell|exec|execute|eval|subprocess|bash|sh\b|zsh|powershell|pwsh|cmd|"
    r"command|run_?code|run_?script|python|system|terminal|invoke)", re.I)
_READ_OBJECT = re.compile(
    r"(read|get|fetch|list|query|select|download|export|dump|scan|search|"
    r"describe|retrieve|load|view|browse)", re.I)
_DELEGATE_OBJECT = re.compile(
    r"(delegate|handoff|hand_?off|spawn|dispatch|assign|subagent|sub_?agent|"
    r"invoke_?agent|route_?to|forward_?to)", re.I)

# ── Embedded payload analysis ───────────────────────────────────────────
_SQL_DESTRUCTIVE = re.compile(
    r"\b(drop\s+(database|table|schema|index|view)|truncate\s+table|"
    r"delete\s+from|alter\s+table\s+\w+\s+drop|drop\s+column)\b", re.I)
_SHELL_DESTRUCTIVE = re.compile(
    r"(rm\s+-[rf]{1,2}|mkfs|shred\s|dd\s+if=|>\s*/dev/sd|format\s+[a-z]:)", re.I)
_WILDCARD_VALUE = re.compile(r"^\s*(\*|all|any|everyone|public|anonymous|\*/\*|organization|org|global|\*\.\*)\s*$", re.I)

# Argument keys whose FALSE/disabled value means a control is being weakened.
_CONTROL_KEYS = re.compile(
    r"(mfa|2fa|multi_?factor|two_?factor|required|enforce|enabled|active|"
    r"protection|logging|audit|monitoring|alerting|encryption|tls|ssl|"
    r"verify|validation|deletion_?protection|governance|firewall|edr|"
    r"antivirus|security|compliance|interlock|safeguard)", re.I)
_DISABLED_VALUE = re.compile(
    r"^\s*(false|0|no|off|disabled|disable|none|optional|never|inactive|"
    r"unenforced|permissive|allow_?all)\s*$", re.I)

# Retention/expiry values that destroy recoverability.
_RETENTION_KEY = re.compile(r"(retention|expire|expiry|ttl|keep|lifecycle|purge_after)", re.I)


def _walk(value: Any, depth: int = 0, max_depth: int = 6):
    """Yield every (key, value) pair reachable in a nested structure, so a
    dangerous action hidden inside a wrapper is still visible."""
    if depth > max_depth:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k), v
            yield from _walk(v, depth + 1, max_depth)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield "", v
            yield from _walk(v, depth + 1, max_depth)


def _text_blob(call: dict) -> str:
    parts = [str(call.get("tool", ""))]
    for k, v in _walk(call.get("args") or {}):
        parts.append(k)
        if isinstance(v, (str, int, float, bool)):
            parts.append(str(v))
    return " ".join(parts)


def _nested_tools(call: dict) -> list[str]:
    """Tool names referenced inside argument payloads (deferred-action
    wrappers, delegation tasks, cron commands)."""
    out = []
    for k, v in _walk(call.get("args") or {}):
        if k.lower() in ("tool", "action", "command", "cmd", "task", "operation", "op"):
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, dict) and isinstance(v.get("tool"), str):
                out.append(v["tool"])
    return out


def classify(call: dict, manifest: dict | None = None) -> frozenset:
    """Resolve a call to its canonical capability set.

    `manifest` maps tool name -> declared capability list. When a tool is
    declared, its declaration is INCLUDED (authoritative floor) but inferred
    capabilities are still unioned in — a declaration can add governance, never
    remove it. That keeps a malicious or careless manifest from being a bypass.
    """
    tool = str(call.get("tool", "")).strip().lower()
    args = call.get("args") if isinstance(call.get("args"), dict) else {}
    blob = _text_blob(call)
    caps: set[str] = set()

    if manifest and tool in manifest:
        caps.update(manifest[tool] or [])

    name = tool.replace("-", "_")
    destructive_verb = bool(_DESTRUCTIVE_VERB.search(name))
    disable_verb = bool(_DISABLE_VERB.search(name))
    modify_verb = bool(_MODIFY_VERB.search(name))
    create_verb = bool(_CREATE_VERB.search(name))

    # ── embedded payloads: SQL / shell / nested tool references ─────────
    nested = " ".join(_nested_tools(call))
    scan = blob + " " + nested
    if _SQL_DESTRUCTIVE.search(scan):
        caps.add(CAP_DATA_DESTRUCTIVE)
    if _SHELL_DESTRUCTIVE.search(scan):
        caps.add(CAP_INFRA_DESTRUCTIVE)
        caps.add(CAP_DATA_DESTRUCTIVE)
    if _EXEC_OBJECT.search(name):
        caps.add(CAP_CODE_EXEC)

    # A wrapper carrying a nested action inherits that action's capabilities.
    if nested.strip():
        for sub in _nested_tools(call):
            if isinstance(sub, str) and sub.strip():
                caps |= classify({"tool": sub.split()[0], "args": {"_inline": sub}},
                                 manifest)

    # ── destructive families ────────────────────────────────────────────
    if destructive_verb:
        if _DB_OBJECT.search(name) or _DB_OBJECT.search(blob[:200]):
            caps.add(CAP_DATA_DESTRUCTIVE)
        if _INFRA_OBJECT.search(name) or _INFRA_OBJECT.search(blob[:200]):
            caps.add(CAP_INFRA_DESTRUCTIVE)
        if _BACKUP_OBJECT.search(name) or _BACKUP_OBJECT.search(blob[:200]):
            caps.add(CAP_BACKUP_DESTRUCTIVE)
        if _LOG_OBJECT.search(name) or _LOG_OBJECT.search(blob[:200]):
            caps.add(CAP_LOG_TAMPER)
        if not caps & {CAP_DATA_DESTRUCTIVE, CAP_INFRA_DESTRUCTIVE,
                       CAP_BACKUP_DESTRUCTIVE, CAP_LOG_TAMPER}:
            # A destructive verb with an unrecognised object is still destructive.
            caps.add(CAP_INFRA_DESTRUCTIVE)

    # ── security-control weakening: verb OR value semantics ─────────────
    if disable_verb and _SECCTRL_OBJECT.search(blob):
        caps.add(CAP_SECURITY_CONTROL)
    if _SECCTRL_OBJECT.search(name) and (disable_verb or modify_verb or create_verb):
        caps.add(CAP_SECURITY_CONTROL)

    # The decisive signal: a control-shaped key set to a disabled value,
    # whatever the tool is called. This is what catches update_security_policy
    # {"mfa_required": false} and edr_control {"protection": "disabled"}.
    for k, v in _walk(args):
        ks = str(k)
        vs = str(v)
        if _CONTROL_KEYS.search(ks) and (_DISABLED_VALUE.search(vs) or v is False):
            caps.add(CAP_SECURITY_CONTROL)
            if _LOG_OBJECT.search(ks) or _LOG_OBJECT.search(blob[:200]):
                caps.add(CAP_LOG_TAMPER)
        # Retention/expiry driven to zero destroys recoverability.
        if _RETENTION_KEY.search(ks):
            try:
                if float(vs) <= 1:
                    caps.add(CAP_BACKUP_DESTRUCTIVE)
                    if _BACKUP_OBJECT.search(blob):
                        caps.add(CAP_BACKUP_DESTRUCTIVE)
            except (TypeError, ValueError):
                if _DISABLED_VALUE.search(vs):
                    caps.add(CAP_BACKUP_DESTRUCTIVE)
        # Wildcard / organisation-wide scope.
        if _WILDCARD_VALUE.match(vs):
            caps.add(CAP_WILDCARD_SCOPE)
        # Non-expiring credentials are persistence.
        if ks.lower() in ("expires", "expiry", "expires_at", "ttl") and \
                re.match(r"^\s*(never|none|0|infinite|unlimited)\s*$", vs, re.I):
            caps.add(CAP_PERSISTENCE)

    # A security-control object being modified at all is governed.
    if _SECCTRL_OBJECT.search(name) and _SECCTRL_OBJECT.search(blob):
        if modify_verb or disable_verb:
            caps.add(CAP_SECURITY_CONTROL)

    # ── credentials ─────────────────────────────────────────────────────
    if _CRED_OBJECT.search(blob):
        if _READ_OBJECT.search(name) or "dump" in name:
            caps.add(CAP_CREDENTIAL_READ)
        if create_verb or modify_verb or "reset" in name or "rotate" in name:
            caps.add(CAP_CREDENTIAL_CHANGE)
    if "reset" in name and re.search(r"(password|credential|mfa|account|token)", blob, re.I):
        caps.add(CAP_CREDENTIAL_CHANGE)

    # ── IAM / privilege ─────────────────────────────────────────────────
    if _IAM_OBJECT.search(name) or _IAM_OBJECT.search(" ".join(str(k) for k, _ in _walk(args))):
        if create_verb or modify_verb or destructive_verb or "attach" in name or "assume" in name:
            caps.add(CAP_IAM_PRIVILEGED)
    if re.search(r"\b(admin|owner|root|superuser|sudo|roles/owner|roles/editor)\b", blob, re.I):
        if create_verb or modify_verb or _IAM_OBJECT.search(blob):
            caps.add(CAP_IAM_PRIVILEGED)

    # ── payments ────────────────────────────────────────────────────────
    if _PAYMENT_OBJECT.search(name) or _PAYMENT_OBJECT.search(
            " ".join(str(k) for k, _ in _walk(args))):
        caps.add(CAP_PAYMENT)
    if "amount" in {str(k).lower() for k, _ in _walk(args)} and (
            _PAYMENT_OBJECT.search(blob) or modify_verb or create_verb):
        caps.add(CAP_PAYMENT)

    # ── persistence ─────────────────────────────────────────────────────
    if _PERSIST_OBJECT.search(name) and (create_verb or modify_verb or "add" in name):
        caps.add(CAP_PERSISTENCE)
    if re.search(r"(schedule|cron|when|at_time|run_at|defer|later)",
                 " ".join(str(k) for k, _ in _walk(args)), re.I):
        caps.add(CAP_PERSISTENCE)

    # ── egress / external data movement ─────────────────────────────────
    if _EGRESS_OBJECT.search(name):
        caps.add(CAP_EXTERNAL_DATA_MOVE)
    argkeys = {str(k).lower() for k, _ in _walk(args)}
    if argkeys & {"url", "endpoint", "host", "to", "recipient", "collector",
                  "webhook", "callback", "dest", "destination", "dest_bucket",
                  "share_with", "acl"}:
        caps.add(CAP_EXTERNAL_DATA_MOVE)

    # ── reads / delegation ──────────────────────────────────────────────
    if _READ_OBJECT.search(name) and not caps & {CAP_DATA_DESTRUCTIVE}:
        caps.add(CAP_DATA_READ)
    if argkeys & {"path", "sql", "query", "file", "key", "object", "bucket",
                  "dataset", "table", "secret_path"}:
        caps.add(CAP_DATA_READ)
    if _DELEGATE_OBJECT.search(name):
        caps.add(CAP_DELEGATION)

    return frozenset(caps)


def describe(caps: frozenset) -> str:
    return ", ".join(sorted(caps)) if caps else "(none inferred)"
