"""Fail-closed credential scan for the exact live-evidence upload payload."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re


class CredentialScanError(RuntimeError):
    """The payload could not be scanned completely and safely."""


@dataclass(frozen=True)
class Finding:
    path: str
    category: str


_PATTERNS = (
    ("openai_key_shape", re.compile(
        rb"(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{8,}")),
    ("authorization_header", re.compile(
        rb"(?i)authorization\s*[:=]\s*(?:bearer\s+)?[^\s\"']+")),
    ("bearer_credential", re.compile(
        rb"(?i)(?<![A-Za-z0-9])bearer\s+[A-Za-z0-9._~+/-]+={0,2}")),
    ("serialized_openai_api_key", re.compile(
        rb"(?i)(?:[\"']?OPENAI_API_KEY[\"']?)\s*[:=]")),
)


def _files_in_payload(root: Path) -> list[Path]:
    if not root.exists() or not root.is_dir():
        raise CredentialScanError("evidence directory unavailable")
    try:
        entries = sorted(root.rglob("*"), key=lambda item: item.as_posix())
    except OSError as exc:
        raise CredentialScanError("evidence directory unreadable") from exc
    files: list[Path] = []
    for path in entries:
        try:
            if path.is_symlink():
                raise CredentialScanError("ambiguous symlink in payload")
            if path.is_dir():
                continue
            if not path.is_file():
                raise CredentialScanError("unsupported payload entry")
            if path.stat().st_mode & 0o444 == 0:
                raise CredentialScanError("unreadable payload entry")
        except OSError as exc:
            raise CredentialScanError("payload metadata unreadable") from exc
        files.append(path)
    return files


def scan_evidence_directory(root: Path, *, exact_secret: str | None) -> list[Finding]:
    """Return sanitized findings; raise if the complete payload cannot be read."""
    findings: list[Finding] = []
    secret_bytes = exact_secret.encode("utf-8") if exact_secret else None
    for path in _files_in_payload(root):
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise CredentialScanError("payload entry unreadable") from exc
        relative = path.relative_to(root).as_posix()
        name_data = relative.encode("utf-8")
        if secret_bytes and secret_bytes in name_data:
            findings.append(Finding(relative, "exact_openai_api_key_in_path"))
        if secret_bytes and secret_bytes in data:
            findings.append(Finding(relative, "exact_openai_api_key"))
        for category, pattern in _PATTERNS:
            if pattern.search(name_data):
                findings.append(Finding(relative, f"{category}_in_path"))
            if pattern.search(data):
                findings.append(Finding(relative, category))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        findings = scan_evidence_directory(
            args.evidence_dir,
            exact_secret=os.environ.get("OPENAI_API_KEY"),
        )
    except Exception:
        # Exception details are deliberately suppressed because they may contain
        # credential-bearing paths or values supplied by an unsafe payload.
        print("CREDENTIAL_LEAK_SCAN = FAIL")
        print("category=scanner_error")
        return 1
    if findings:
        print("CREDENTIAL_LEAK_SCAN = FAIL")
        for category in sorted({finding.category for finding in findings}):
            print(f"category={category}")
        return 1
    print("CREDENTIAL_LEAK_SCAN = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
