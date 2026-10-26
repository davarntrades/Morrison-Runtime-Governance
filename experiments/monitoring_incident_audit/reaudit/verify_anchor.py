"""Re-audit: check the PR's published raw evidence against its committed anchor.

Stdlib only; run with `python -I`. Treats the tarball as untrusted data: it is
extracted into a fresh empty directory and only parsed, never executed.
Usage: python -I verify_anchor.py RESULTS_DIR OUT_DIR
"""
import collections
import hashlib
import json
import sys
import tarfile
from pathlib import Path

results, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
tar = results / "raw_evidence.tar.gz"
want = (results / "raw_evidence.sha256").read_text().split()[0]
got = hashlib.sha256(tar.read_bytes()).hexdigest()
print("tarball sha256 matches raw_evidence.sha256:", got == want)
with tarfile.open(tar) as t:
    t.extractall(out, filter="data")
anchor = json.loads((results / "EVIDENCE_ANCHOR.json").read_text())


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=repr)


rows = {}
for r in anchor["rows"]:
    rows.setdefault(r["run_id"], []).append(r)
logs = sorted(out.glob("*/*/evidence.jsonl"))
sets = collections.Counter(p.parts[-3] for p in logs)
commits = collections.Counter()
ok = bad = missing = 0
for p in logs:
    recs = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    prev, chain = "0" * 64, True
    for i, r in enumerate(recs):
        h = hashlib.sha256(canon({k: v for k, v in r.items() if k != "record_hash"}).encode()).hexdigest()
        chain &= r["seq"] == i and r["prev_hash"] == prev and r["record_hash"] == h
        prev = r["record_hash"]
    g = recs[0]["payload"]["git"]
    commits[(g["commit"], g["governed_paths_dirty"])] += 1
    cands = rows.get(recs[0]["run_id"], [])
    if not cands:
        missing += 1
    elif chain and any(c.get("terminal_hash") == prev for c in cands):
        ok += 1
    else:
        bad += 1
print("logs per set:", dict(sets), "| anchor rows:", len(anchor["rows"]))
print("chain valid and terminal hash == anchor: %d | mismatch: %d | missing from anchor: %d" % (ok, bad, missing))
print("generating commit / dirty:", dict(commits))
