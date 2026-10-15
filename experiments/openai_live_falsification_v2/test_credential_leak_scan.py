"""Deterministic tests for the fail-closed live-evidence credential scan."""

from pathlib import Path

import pytest

from .credential_leak_scan import (
    CredentialScanError, main, scan_evidence_directory,
)


FAKE_SECRET = "sk-proj-FAKE_TEST_SECRET_0123456789"


def write_payload(tmp_path: Path, content: str) -> Path:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "report.json").write_text(content, encoding="utf-8")
    return evidence


def categories(findings):
    return {finding.category for finding in findings}


def test_clean_evidence_passes_and_is_upload_eligible(tmp_path):
    evidence = write_payload(tmp_path, '{"outcome":"contained","spent":0.01}')
    assert scan_evidence_directory(evidence, exact_secret=FAKE_SECRET) == []


def test_exact_synthetic_secret_fails(tmp_path):
    evidence = write_payload(tmp_path, f'{{"accidental":"{FAKE_SECRET}"}}')
    assert "exact_openai_api_key" in categories(
        scan_evidence_directory(evidence, exact_secret=FAKE_SECRET))


def test_exact_secret_is_never_printed(tmp_path, monkeypatch, capsys):
    evidence = write_payload(tmp_path, f'{{"accidental":"{FAKE_SECRET}"}}')
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_SECRET)
    assert main(["--evidence-dir", str(evidence)]) == 1
    output = capsys.readouterr().out
    assert "CREDENTIAL_LEAK_SCAN = FAIL" in output
    assert FAKE_SECRET not in output


def test_secret_in_filename_is_detected_but_never_printed(
        tmp_path, monkeypatch, capsys):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / f"{FAKE_SECRET}.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_SECRET)
    assert main(["--evidence-dir", str(evidence)]) == 1
    output = capsys.readouterr().out
    assert "exact_openai_api_key_in_path" in output
    assert FAKE_SECRET not in output


def test_openai_like_key_fails(tmp_path):
    evidence = write_payload(
        tmp_path, '{"text":"sk-proj-SYNTHETIC0123456789abcdef"}')
    assert "openai_key_shape" in categories(
        scan_evidence_directory(evidence, exact_secret=None))


def test_authorization_bearer_header_fails(tmp_path):
    evidence = write_payload(
        tmp_path, "Authorization: Bearer synthetic-token-0123456789")
    found = categories(scan_evidence_directory(evidence, exact_secret=None))
    assert "authorization_header" in found
    assert "bearer_credential" in found


def test_serialized_openai_api_key_field_fails(tmp_path):
    evidence = write_payload(
        tmp_path, '{"OPENAI_API_KEY":"synthetic-placeholder"}')
    assert "serialized_openai_api_key" in categories(
        scan_evidence_directory(evidence, exact_secret=None))


def test_scanner_error_fails_closed(tmp_path, monkeypatch):
    evidence = write_payload(tmp_path, '{"safe":true}')

    def explode(_self):
        raise OSError("synthetic read failure")

    monkeypatch.setattr(Path, "read_bytes", explode)
    with pytest.raises(CredentialScanError):
        scan_evidence_directory(evidence, exact_secret=FAKE_SECRET)


def test_missing_evidence_directory_fails_closed(tmp_path):
    with pytest.raises(CredentialScanError):
        scan_evidence_directory(tmp_path / "missing", exact_secret=FAKE_SECRET)


def test_unreadable_payload_fails_closed(tmp_path):
    evidence = write_payload(tmp_path, '{"safe":true}')
    report = evidence / "report.json"
    report.chmod(0)
    try:
        with pytest.raises(CredentialScanError):
            scan_evidence_directory(evidence, exact_secret=FAKE_SECRET)
    finally:
        report.chmod(0o600)


def test_safe_counterexample_remains_upload_eligible(tmp_path):
    evidence = write_payload(
        tmp_path,
        '{"outcome":"FAILURE","AUTHORIZATION_FAILURE":true,'
        '"proposal":{"tool":"delete_protected_resource"}}',
    )
    assert scan_evidence_directory(evidence, exact_secret=FAKE_SECRET) == []
