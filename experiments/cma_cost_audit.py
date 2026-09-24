"""Query authoritative session usage for each preserved CMA campaign session.

Session usage is platform-reported list cost in whole cents, not an invoice or
the account's net credit debit. Original archives remain untouched.
"""
import json
import os
import pathlib
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.abspath("../campaign/experiments"))
import cma_falsification as c

ROOT = pathlib.Path("../campaign/evidence")
ARCHIVES = {
    "campaign1": ROOT / "campaign1/raw-artifact.zip",
    "followup": ROOT / "followup/raw-artifact.zip",
    "pagination-depth": ROOT / "pagination-depth/raw-evidence.tar.zst",
    "pagination-updates": ROOT / "pagination-updates/raw-artifact.zip",
    "driver-race": ROOT / "driver-race/raw-artifact.zip",
    "multiturn": ROOT / "multiturn/raw-artifact.zip",
}


def files(path):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            for suffix in ("results.json", "api.jsonl"):
                hits = [n for n in names if n.endswith("experiments/evidence/" + suffix)]
                yield suffix, z.read(hits[0]).decode() if hits else ""
    else:
        for suffix in ("results.json", "api.jsonl"):
            name = "depth/experiments/evidence/" + suffix
            out = subprocess.run(["tar", "--zstd", "-xOf", str(path), name], capture_output=True, check=True)
            yield suffix, out.stdout.decode()


def main():
    records = []
    for run, path in ARCHIVES.items():
        contents = dict(files(path))
        results = json.loads(contents["results.json"])
        family = {r["session"]: r["family"] for r in results if r.get("session")}
        trials = {r["session"]: r.get("trial") for r in results if r.get("session")}
        created = {}
        for line in contents["api.jsonl"].splitlines():
            row = json.loads(line)
            if row.get("method") == "POST" and row.get("path") == "/sessions":
                sid = (row.get("response") or {}).get("id")
                if isinstance(sid, str) and sid.startswith("sesn_"):
                    created[sid] = (row.get("request") or {}).get("title")
        for sid, title in sorted(created.items()):
            code, response, rid = c.api("GET", f"/sessions/{sid}")
            usage = response.get("usage") if code == 200 else None
            model = (response.get("agent") or {}).get("model") if code == 200 else None
            records.append({"source_archive": str(path), "run": run, "family": family.get(sid),
                "trial": trials.get(sid), "session": sid, "title": title, "request_id": rid,
                "http_status": code, "model": model, "status": response.get("status"),
                "usage": usage, "list_cost_cents": (usage or {}).get("list_cost", {}).get("amount")})
            print(f"{run} {family.get(sid) or title}: {code}", flush=True)
    (c.ROOT / "cost-audit.json").write_text(json.dumps(records, indent=2))
    print("sessions", len(records), "successful", sum(r["http_status"] == 200 for r in records), flush=True)


if __name__ == "__main__":
    main()
