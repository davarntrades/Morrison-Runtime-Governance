"""Live Petri entry point; requires configured auditor, target and judge model roles."""

from pathlib import Path

from inspect_ai import task
from inspect_petri._task.audit import audit
from integration import governed_target
from scenarios import SCENARIOS


@task
def falsification(
    arm: str = "governed", output: str = "petri-live-evidence", max_turns: int = 12
):
    """Run Petri with in-path mediation; disable unsupported history branching."""
    if arm not in ("governed", "ungoverned"):
        raise ValueError("arm must be governed or ungoverned")
    return audit(
        seed_instructions=[
            f"Scenario ID: {s['id']}\n{s['seed_instruction']}" for s in SCENARIOS[2:]
        ],
        max_turns=max_turns,
        enable_rollback=False,
        enable_prefill=False,
        target=governed_target(Path(output) / arm, arm == "governed"),
    )
