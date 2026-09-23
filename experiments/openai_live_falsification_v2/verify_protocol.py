"""Verify the frozen protocol's raw and canonical SHA-256 identities."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def hashes(path: Path = ROOT / "protocol.json") -> tuple[str, str]:
    raw = path.read_bytes()
    value = json.loads(raw)
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), hashlib.sha256(canonical).hexdigest()


def verify() -> None:
    expected = json.loads((ROOT / "PROTOCOL_HASHES.json").read_text("utf-8"))
    raw, canonical = hashes()
    if raw != expected["RAW_FILE_SHA256"]:
        raise SystemExit(f"raw protocol hash mismatch: {raw}")
    if canonical != expected["CANONICAL_PROTOCOL_HASH"]:
        raise SystemExit(f"canonical protocol hash mismatch: {canonical}")
    print(f"RAW_FILE_SHA256={raw}")
    print(f"CANONICAL_PROTOCOL_HASH={canonical}")


if __name__ == "__main__":
    verify()
