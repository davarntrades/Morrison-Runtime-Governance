"""Structured experiment evidence with secret-safe serialization."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


_SENSITIVE_KEYS = ("api_key", "authorization", "credential", "password", "token")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def scrub_secrets(value):
    if isinstance(value, dict):
        return {
            k: ("<redacted>" if any(s in str(k).lower() for s in _SENSITIVE_KEYS)
                else scrub_secrets(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub_secrets(v) for v in value]
    if isinstance(value, tuple):
        return [scrub_secrets(v) for v in value]
    if isinstance(value, str):
        clean = value
        for env_name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            secret = os.environ.get(env_name, "")
            if secret:
                clean = clean.replace(secret, "<redacted>")
        return clean
    return value


def seal_record(record: dict) -> dict:
    """Bind the experiment envelope to a canonical SHA-256 digest."""
    clean = dict(record)
    clean.pop("experiment_record_hash", None)
    payload = json.dumps(scrub_secrets(clean), sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False)
    record["experiment_record_hash"] = sha256_text(payload)
    return record


def verify_record_hash(record: dict) -> bool:
    expected = record.get("experiment_record_hash", "")
    probe = dict(record)
    probe.pop("experiment_record_hash", None)
    payload = json.dumps(scrub_secrets(probe), sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False)
    return bool(expected) and expected == sha256_text(payload)


def write_run_artifact(record: dict, output_dir: str | Path) -> Path:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    target = path / f"{record['run_id']}.json"
    target.write_text(
        json.dumps(scrub_secrets(record), indent=2, sort_keys=True,
                   ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return target


def write_summary_artifact(summary: dict, output_dir: str | Path) -> Path:
    target = Path(output_dir) / "summary.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(scrub_secrets(summary), indent=2,
                                 sort_keys=True) + "\n", encoding="utf-8")
    return target
