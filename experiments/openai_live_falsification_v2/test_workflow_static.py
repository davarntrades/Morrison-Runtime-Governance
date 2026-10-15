"""Static safety assertions for the manually triggered live workflow."""

from pathlib import Path
import re


WORKFLOW = (Path(__file__).resolve().parents[2] / ".github" / "workflows"
            / "openai-live-falsification-v2.yml")


def text():
    return WORKFLOW.read_text("utf-8")


def test_workflow_dispatch_is_the_only_trigger():
    source = text()
    trigger_block = source.split("permissions:", 1)[0]
    assert re.search(r"^on:\n  workflow_dispatch:", trigger_block, re.M)
    for forbidden in ("push:", "pull_request:", "schedule:",
                      "repository_dispatch:"):
        assert forbidden not in trigger_block


def test_minimum_repository_permissions_and_no_persisted_credentials():
    source = text()
    assert "permissions:\n  contents: read" in source
    assert "persist-credentials: false" in source


def test_every_external_action_is_pinned_to_a_full_commit_sha():
    uses = re.findall(r"^\s*uses:\s*([^\s]+)", text(), re.M)
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in uses)


def test_openai_secret_is_only_on_three_minimum_credential_steps():
    source = text()
    secret_line = "OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}"
    assert source.count(secret_line) == 3
    job_env = source.split("    steps:", 1)[0]
    assert "OPENAI_API_KEY" not in job_env
    assert "hash" not in "\n".join(
        line.lower() for line in source.splitlines()
        if "openai_api_key" in line.lower())
    steps = re.split(r"(?m)(?=^      - name: )", source)
    secret_steps = [step for step in steps if secret_line in step]
    assert len(secret_steps) == 3
    assert any("Discover account-available OpenAI models" in step
               for step in secret_steps)
    assert any("Run cost-gated initial smoke" in step
               for step in secret_steps)
    assert any("Scan exact evidence payload for credential leakage" in step
               for step in secret_steps)


def test_protocol_integrity_runs_before_any_live_step():
    source = text()
    integrity = source.index("Verify frozen protocol and offline gates")
    discovery = source.index("Discover account-available OpenAI models")
    smoke = source.index("Run cost-gated initial smoke")
    assert integrity < discovery < smoke


def test_upload_requires_explicit_successful_credential_scan():
    source = text()
    scan = source.index("Scan exact evidence payload for credential leakage")
    upload = source.index("Upload non-secret evidence")
    assert scan < upload
    assert "id: credential-scan" in source
    assert "CREDENTIAL_LEAK_SCAN" not in source
    assert ("if: ${{ always() && steps.credential-scan.outputs.safe == "
            "'true' }}") in source


def test_no_artifact_upload_route_bypasses_scan_output():
    source = text()
    steps = re.split(r"(?m)(?=^      - name: )", source)
    upload_steps = [
        step for step in steps
        if re.search(r"uses: actions/upload-artifact@[0-9a-f]{40}", step)
    ]
    assert len(upload_steps) == 1
    assert "steps.credential-scan.outputs.safe == 'true'" in upload_steps[0]
    assert "if: ${{ always() }}" not in upload_steps[0]


def test_scanner_runs_even_after_experiment_failure_for_counterexamples():
    source = text()
    scan_step = source[source.index(
        "- name: Scan exact evidence payload"):source.index(
        "- name: Upload non-secret evidence")]
    assert "if: ${{ always() }}" in scan_step
    assert "safe=$scan_safe" in scan_step
    assert 'test "$scan_safe" = true' in scan_step
