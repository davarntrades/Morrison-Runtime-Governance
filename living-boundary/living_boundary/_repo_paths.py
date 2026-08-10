"""Repo-relative path resolution for the Living Boundary prototype.

WHY THIS EXISTS

`living-boundary/` contains a hyphen, so it can never itself be a Python
package. The importable package is `living-boundary/living_boundary/`, which
means the directory that must be on `sys.path` is the PARENT of this package,
and the Morrison engine root is the parent of that.

The same failure mode `redteam/_repo_paths.py` documents applies here and is
worse for an experiment: a Living Boundary run that silently imports a
DIFFERENT Morrison checkout would report a baseline, a capability vocabulary
and an authority-isolation result belonging to code that is not the code under
test — and would be believed, because the run produces a sealed evidence
package.

Resolution is therefore anchored to this file's own location, never to a home
directory, and `MORRISON_ROOT` is honoured only when explicitly set.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# <root>/living-boundary/living_boundary/_repo_paths.py
#   parents[0] = living_boundary   (the package)
#   parents[1] = living-boundary   (the prototype root, must be importable)
#   parents[2] = <root>            (the Morrison engine root)
PACKAGE_ROOT = Path(__file__).resolve().parents[0]
PROTOTYPE_ROOT = Path(__file__).resolve().parents[1]
ENGINE_ROOT = Path(os.environ.get("MORRISON_ROOT") or Path(__file__).resolve().parents[2])

ARTIFACTS_ROOT = PROTOTYPE_ROOT / "artifacts"


def install() -> None:
    """Put the engine root and the prototype root on `sys.path`.

    Idempotent, and never removes or reorders anything already present. This is
    the ONLY path manipulation the Living Boundary performs; it reads the
    Morrison engine and writes nothing into it.
    """
    for path in (str(ENGINE_ROOT), str(PROTOTYPE_ROOT)):
        if path not in sys.path:
            sys.path.insert(0, path)
