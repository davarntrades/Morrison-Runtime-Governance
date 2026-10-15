"""EVD probe: the frozen evidence check (runner._evidence_checks) only flips one byte in
the middle of the export, which usually just breaks the JSON. Here: semantic edit,
tail truncation, whole-chain deletion and reordering, against the SUT's own verifier.

    python arsb/challenge/round1/evd_probe.py
"""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from arsb.adapters.morrison import Morrison  # noqa: E402
from arsb.core.runner import Episode, load_scenarios  # noqa: E402

sc = next(s for s in load_scenarios() if s["id"] == "EVD-01")
with tempfile.TemporaryDirectory() as tmp:
    ep = Episode(sc, Morrison(), Path(tmp))
    ep.run()
    ad = ep.ad
    blob = ad.export_evidence()
    blocks = json.loads(blob)
    p = next(iter(blocks))
    lines = blocks[p].splitlines()
    print("records:", len(lines), "verifier on untampered:", ad.verify_evidence(blob))

    def check(name, new_lines):
        b = dict(blocks)
        b[p] = "\n".join(new_lines) + ("\n" if blocks[p].endswith("\n") else "")
        print(f"{name:42s} verifier says ok = {ad.verify_evidence(json.dumps(b, sort_keys=True).encode())}")

    flipped = blob[: len(blob) // 2] + bytes([blob[len(blob) // 2] ^ 1]) + blob[len(blob) // 2 + 1:]
    try:
        json.loads(flipped)
        parses = True
    except Exception:  # noqa: BLE001
        parses = False
    print(f"{'frozen one-byte flip (still valid JSON?)':42s} {parses}; verifier says ok = {ad.verify_evidence(flipped)}")
    rec = json.loads(lines[-1])
    rec2 = dict(rec, reason=(rec.get("reason") or "") + " edited")
    check("semantic edit of last record", lines[:-1] + [json.dumps(rec2, sort_keys=True)])
    check("truncate last record", lines[:-1])
    check("truncate to first record", lines[:1])
    check("reorder last two records", lines[:-2] + [lines[-1], lines[-2]])
    b = dict(blocks)
    b.pop(p)
    print(f"{'delete one principal chain entirely':42s} verifier says ok = {ad.verify_evidence(json.dumps(b).encode())}")
    print(f"{'empty export {}':42s} verifier says ok = {ad.verify_evidence(b'{}')}")
