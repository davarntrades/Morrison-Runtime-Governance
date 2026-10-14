"""Checks around a live AgentDojo run: preflight, evidence verification,
credential redaction, and the run summary.

None of these functions prints, logs or writes the API key. The preflight
reports only whether a key is present and what the API answered.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path

ARM_FILE = re.compile(r"^live-.*-(none|morrison)-[a-z]+\.json$")
# Anthropic key shapes, plus the header that would carry one.
_KEY_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)(x-api-key[\"']?\s*[:=]\s*[\"']?)([^\s\"',}]{8,})"),
]
REDACTED = "[REDACTED]"
# Settings and inputs that must be identical across the two arms.
_MATCHED_FIELDS = ("suite", "benchmark_version", "provider", "model", "attack",
                   "attack_target_name", "llm_settings", "tool_loop_max_iters",
                   "pairs_requested_list", "injection_sha_by_pair")
_MATCHED_PROVENANCE = ("git_commit", "agentdojo_version", "python")


def preflight(model: str, output: Path | None, canary: bool = False,
              settings=None) -> int:
    """Authenticate and confirm model access without exposing the key.

    `GET /v1/models/{model}` is not billed. With `canary`, one minimal request
    is sent with the exact settings the benchmark uses, so a rejected
    parameter fails here rather than after the first arm has started.
    """
    import anthropic
    report: dict = {"model": model,
                    "key_present": bool(os.environ.get("ANTHROPIC_API_KEY"))}
    base = os.environ.get("ANTHROPIC_BASE_URL")
    report["base_url_overridden"] = bool(base)
    if not report["key_present"]:
        report.update(ok=False, error="ANTHROPIC_API_KEY is not set")
        return _finish(report, output)

    client = anthropic.Anthropic()
    try:
        info = client.models.retrieve(model)
        report.update(auth="ok", http_status=200, model_id=info.id,
                      display_name=getattr(info, "display_name", None))
    except anthropic.AuthenticationError:
        report.update(ok=False, http_status=401,
                      error="authentication failed: the key was rejected")
        return _finish(report, output)
    except anthropic.PermissionDeniedError:
        report.update(ok=False, http_status=403,
                      error="the key is not permitted to use this model")
        return _finish(report, output)
    except anthropic.NotFoundError:
        report.update(ok=False, http_status=404,
                      error=f"model {model!r} is not available to this key")
        return _finish(report, output)
    except anthropic.APIStatusError as exc:
        report.update(ok=False, http_status=exc.status_code,
                      error=f"API error {exc.status_code}")
        return _finish(report, output)
    except anthropic.APIConnectionError:
        report.update(ok=False, error="could not reach the Anthropic API")
        return _finish(report, output)

    if canary:
        report["canary"] = _canary(model, settings)
        if not report["canary"]["ok"]:
            report.update(ok=False, error="canary request failed")
            return _finish(report, output)
    report["ok"] = True
    return _finish(report, output)


def _canary(model: str, settings) -> dict:
    import anthropic
    from runtime_eval.agentdojo_bench.anthropic_adapter import (
        Budget, RequestSettings, _request)
    settings = settings or RequestSettings(model=model)
    budget = Budget(model, max_usd=1.0, max_requests=1)
    tools = [{"name": "get_balance", "description": "Get the account balance.",
              "input_schema": {"type": "object", "properties": {}}}]
    messages = [{"role": "user", "content": "What is my balance? Use the tool."}]
    try:
        asyncio.run(_request(anthropic.AsyncAnthropic(), settings, budget,
                             messages=messages, tools=tools,
                             system_prompt="You are a banking assistant."))
    except anthropic.APIStatusError as exc:
        # The API's error message names the rejected parameter; it never
        # contains the key.
        return {"ok": False, "http_status": exc.status_code,
                "error": str(getattr(exc, "message", exc))[:500],
                "settings": settings.as_dict()}
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:500],
                "settings": settings.as_dict()}
    rec = budget.requests[0]
    return {"ok": True, "settings": settings.as_dict(), **{
        k: rec[k] for k in ("served_model", "stop_reason", "block_types",
                            "input_tokens", "output_tokens", "est_cost_usd")}}


def _finish(report: dict, output: Path | None) -> int:
    report.setdefault("ok", False)
    print(json.dumps(report, indent=2, sort_keys=True))
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        (output / "preflight.json").write_text(
            json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def redact_tree(root: Path, secret: str = "") -> dict:
    """Replace any credential found under `root`, in place. Returns the files
    and counts redacted (never the values)."""
    found: dict[str, int] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            data = path.read_bytes()
            if secret and secret.encode() in data:
                path.write_bytes(data.replace(secret.encode(), REDACTED.encode()))
                found[str(path.relative_to(root))] = data.count(secret.encode())
            continue
        n = 0
        if secret and len(secret) >= 8 and secret in text:
            n += text.count(secret)
            text = text.replace(secret, REDACTED)
        text, k = _KEY_PATTERNS[0].subn(REDACTED, text)
        n += k
        text, k = _KEY_PATTERNS[1].subn(lambda m: m.group(1) + REDACTED, text)
        n += k
        if n:
            path.write_text(text, encoding="utf-8")
            found[str(path.relative_to(root))] = n
    return found


def load_arms(root: Path) -> dict[str, dict]:
    arms = {}
    for path in sorted(root.glob("live-*.json")):
        m = ARM_FILE.match(path.name)
        if m:
            arms[m.group(1)] = json.loads(path.read_text(encoding="utf-8"))
    return arms


def _episodes(arm: dict) -> list[dict]:
    return [*(arm.get("results") or []), *(arm.get("partial_episodes") or []),
            *(arm.get("injection_tasks_standalone") or [])]


def verify(root: Path, secret: str = "") -> int:
    """Redact credentials, re-verify every evidence chain from its content,
    and check the two arms ran under matched conditions."""
    from morrison_governance.kernel.attestation import recompute_chain
    root.mkdir(parents=True, exist_ok=True)  # a run that wrote nothing still gets a report
    report: dict = {"redactions": redact_tree(root, secret)}
    arms = load_arms(root)
    report["arms_found"] = sorted(arms)
    chains = {"checked": 0, "failed": []}
    for name, arm in arms.items():
        for ep in _episodes(arm):
            chain = ep.get("evidence_chain") or {}
            if not chain.get("jsonl"):
                continue
            chains["checked"] += 1
            result = recompute_chain(chain["jsonl"])
            ok = result.ok
            if not ok or chain.get("integrity_verified") is False:
                chains["failed"].append({
                    "arm": name, "user_task": ep.get("user_task"),
                    "injection_task": ep.get("injection_task"),
                    "problems": list(result.problems)[:5]})
    report["evidence_chains"] = chains

    mismatches = []
    if set(arms) == {"none", "morrison"}:
        a, b = arms["none"], arms["morrison"]
        for f in _MATCHED_FIELDS:
            if a.get(f) != b.get(f):
                mismatches.append(f)
        pa, pb = a.get("provenance", {}), b.get("provenance", {})
        mismatches += [f"provenance.{f}" for f in _MATCHED_PROVENANCE
                       if pa.get(f) != pb.get(f)]
    else:
        mismatches.append("both arms not present")
    report["matched_conditions"] = {"ok": not mismatches,
                                    "mismatched_fields": mismatches}
    report["arm_status"] = {k: v.get("status", "unknown") for k, v in arms.items()}
    report["ok"] = (not report["redactions"] and not chains["failed"]
                    and not mismatches
                    and all(v == "complete" for v in report["arm_status"].values()))
    (root / "verification.json").write_text(
        json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def summary_markdown(root: Path) -> str:
    """Paired, denominator-explicit summary for the Actions run page."""
    arms = load_arms(root)
    ver_path = root / "verification.json"
    ver = json.loads(ver_path.read_text()) if ver_path.exists() else {}
    verdict = ("COMPLETE" if ver.get("ok") else
               "INCOMPLETE OR UNVERIFIED: do not report as an experimental result")
    lines = [f"## AgentDojo live: {verdict}", ""]
    if not arms:
        return "\n".join(lines + ["No arm produced a result file."])
    lines += ["| | Baseline (record-only) | Morrison (enforced) |",
              "|---|---|---|"]

    def cell(arm: dict | None, key: str) -> str:
        if arm is None:
            return "not run"
        v = arm.get(key)
        return "—" if v is None else str(v)

    def api(arm: dict | None, key: str) -> str:
        if arm is None:
            return "not run"
        return str((arm.get("api_usage") or {}).get(key, "—"))

    rows = [("Status", "status"), ("Error", "error"),
            ("Attack succeeded (pairs)", "attack_success_count"),
            ("Utility under attack (pairs)", "utility_count"),
            ("Tool calls attempted", "calls_attempted"),
            ("Tool calls executed", "calls_executed"),
            ("Tool calls withheld", "calls_withheld"),
            ("BLOCK verdicts (baseline: recorded only)", "calls_blocked"),
            ("ESCALATE verdicts (baseline: recorded only)", "calls_escalated"),
            ("Pairs with environment changes", "pairs_with_resource_effects"),
            ("Pairs with evidence", "pairs_with_evidence")]
    a, b = arms.get("none"), arms.get("morrison")
    for label, key in rows:
        lines.append(f"| {label} | {cell(a, key)} | {cell(b, key)} |")
    for label, key in (("API requests", "requests"),
                       ("Input tokens", "input_tokens"),
                       ("Output tokens", "output_tokens"),
                       ("Est. cost (USD)", "est_cost_usd"),
                       ("Stop reasons", "stop_reasons"),
                       ("Served models", "served_models")):
        lines.append(f"| {label} | {api(a, key)} | {api(b, key)} |")
    mc = ver.get("matched_conditions", {})
    lines += ["",
              f"Matched conditions: {'yes' if mc.get('ok') else 'NO'} "
              f"{mc.get('mismatched_fields') or ''}",
              f"Evidence chains re-verified: "
              f"{ver.get('evidence_chains', {}).get('checked', 0)}, failed: "
              f"{len(ver.get('evidence_chains', {}).get('failed', []))}",
              f"Credential redactions: {len(ver.get('redactions', {}))} file(s)"]
    return "\n".join(lines)
