"""Repo-relative path resolution for the redteam analysis scripts.

WHY THIS EXISTS

Every script in this directory used to begin:

    sys.path.insert(0, "/home/user/Morrison-Runtime-Governance")
    sys.path.insert(0, "/home/user/resurrection-tech-enterprise/governance-service")

Those are absolute paths to one developer's machine. The failure mode is not
the obvious one:

  · On a machine WITHOUT those paths the scripts crash on import — which is
    how they broke CI (`ModuleNotFoundError: No module named 'cyber_rules'`).

  · On a machine WITH them — a second clone, a renamed directory, a CI runner
    that happens to check out elsewhere — the scripts import the OTHER tree and
    run happily. They report on code that is not the code under test, and say
    nothing about it.

The second is the dangerous one. These scripts exist to prove that specific
bypasses are closed; a proof that silently examines a different checkout is
worse than no proof, because it is believed.

Resolution order, most explicit first:

  1. MORRISON_ROOT / MORRISON_SERVICE_PATH environment variables
  2. this file's own location (the engine root is always ../ from here)
  3. a sibling `resurrection-tech-enterprise/governance-service` checkout

`SERVICE_PATH` may not exist — it lives in a different repository. Callers that
need it should check `SERVICE_AVAILABLE` and skip rather than crash.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# The engine root is the parent of this file's directory, always — regardless
# of where the repository has been checked out or what it has been renamed to.
ROOT = Path(os.environ.get("MORRISON_ROOT") or Path(__file__).resolve().parents[1])

_service_env = os.environ.get("MORRISON_SERVICE_PATH")
SERVICE_PATH = Path(
    _service_env
    if _service_env
    else ROOT.parent / "resurrection-tech-enterprise" / "governance-service"
)
SERVICE_AVAILABLE = SERVICE_PATH.is_dir()


def install() -> None:
    """Put the engine root (and the service repo, when present) on sys.path."""
    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    if SERVICE_AVAILABLE:
        svc = str(SERVICE_PATH)
        if svc not in sys.path:
            sys.path.insert(0, svc)


def require_service(script: str) -> None:
    """Exit cleanly when the sibling service repo is absent.

    A missing sibling repository is a MISSING INPUT, not a governance failure.
    Exiting 0 with an explanation keeps that distinction — a crash here would
    read in CI as though the engine were broken.
    """
    if not SERVICE_AVAILABLE:
        print(f"SKIP {script}: service repo not found at {SERVICE_PATH}. "
              f"Set MORRISON_SERVICE_PATH to a governance-service checkout.")
        raise SystemExit(0)
