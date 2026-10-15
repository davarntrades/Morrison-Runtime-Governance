import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_VENDORED = ROOT / "vendor" / "Morrison-Runtime-Governance"
MORRISON = Path(os.environ.get("MORRISON_REPO") or
                (_VENDORED if (_VENDORED / "morrison_governance").is_dir() else ROOT.parent))
sys.path[:0] = [str(ROOT), str(MORRISON)]
