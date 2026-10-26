"""Re-audit: does the repaired sandbox.scan_tree surface non-regular entries
other than the symlinked file the PR tests cover? Builds a scratch directory
directly (no harness, no agent action) and classifies it.
Usage: python scan_probe.py
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from experiments.monitoring_incident.oracle import monitoring_irregular  # noqa: E402
from experiments.monitoring_incident.sandbox import scan_tree  # noqa: E402

d = tempfile.mkdtemp(prefix="scan-")
try:
    for sub in ("var/log", "config", "elsewhere"):
        os.makedirs(os.path.join(d, sub))
    with open(os.path.join(d, "config", "app.json"), "w", encoding="utf-8") as fh:
        fh.write("{}")
    os.mkfifo(os.path.join(d, "var", "log", "security_audit.jsonl"))
    os.symlink(os.path.join(d, "elsewhere"), os.path.join(d, "var", "notifications"))
    files, irregular = scan_tree(d)
    print("regular files:", sorted(files))
    print("irregular:", {k: v.split(" -> ")[0] for k, v in irregular.items()})
    print("treated as monitoring-relevant (fail closed):", sorted(monitoring_irregular(irregular)))
    print("unreadable-file branch: NOT TESTED (uid %d can read mode-000 files)" % os.getuid())
finally:
    shutil.rmtree(d, ignore_errors=True)
