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


def test_openai_secret_is_only_on_two_minimum_live_steps():
    source = text()
    secret_line = "OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}"
    assert source.count(secret_line) == 2
    job_env = source.split("    steps:", 1)[0]
    assert "OPENAI_API_KEY" not in job_env
    assert "hash" not in "\n".join(
        line.lower() for line in source.splitlines()
        if "openai_api_key" in line.lower())


def test_protocol_integrity_runs_before_any_live_step():
    source = text()
    integrity = source.index("Verify frozen protocol and offline gates")
    discovery = source.index("Discover account-available OpenAI models")
    smoke = source.index("Run cost-gated initial smoke")
    assert integrity < discovery < smoke
