"""Fetch terminal session usage for new Fable arms and pre-campaign baselines.

This is read-only and preserves the original experiment evidence unchanged.
"""
import json
import os
import pathlib
import sys
import zipfile

sys.path.insert(0, os.path.abspath("../campaign/experiments"))
import cma_falsification as c

ARCHIVES = {
    "fable-extension": pathlib.Path("../campaign/evidence/fable-extension/raw-artifact.zip"),
    "fable-indirection": pathlib.Path("../campaign/evidence/fable-indirection/raw-artifact.zip"),
    "fable-max-domain": pathlib.Path("../campaign/evidence/fable-max-domain/raw-artifact.zip"),
}
BASELINES = {
    "campaign-original-driver": {"ORIGINAL_GOVERNED_PATH": ["sesn_01RdNXbmQZbxYcmZcLPPb3r4"]},
    "phase0-original": {
        "L1": ["sesn_01PV3J6H4qSQWnS7xyWoQvHb"],
        "L4": ["sesn_01FjrGHyVAj9APiMJoW6BGuc"],
        "L5_L6": ["sesn_01URMYGQsAdAqNRJ3x8rWeXa"],
        "L7": ["sesn_01RFvUEXfp3Tbqzmv5eKD9cJ"],
    },
}


def main():
    targets = []
    for run, path in ARCHIVES.items():
        with zipfile.ZipFile(path) as archive:
            name = next(n for n in archive.namelist() if n.endswith("experiments/evidence/results.json"))
            for result in json.loads(archive.read(name)):
                if result.get("session"):
                    targets.append((run, result["family"], result.get("trial"), result["session"]))
    for run, families in BASELINES.items():
        for family, ids in families.items():
            targets.extend((run, family, None, sid) for sid in ids)
    records = []
    for run, family, trial, sid in targets:
        code, response, rid = c.api("GET", f"/sessions/{sid}")
        usage = response.get("usage") if code == 200 else None
        record = {"run": run, "family": family, "trial": trial, "session": sid,
            "http_status": code, "request_id": rid, "status": response.get("status"),
            "model": (response.get("agent") or {}).get("model"), "usage": usage,
            "list_cost_cents": (usage or {}).get("list_cost", {}).get("amount")}
        records.append(record)
        print(f"{run}/{family}/{trial} {code}", flush=True)
    (c.ROOT / "final-usage.json").write_text(json.dumps(records, indent=2))
    print("sessions", len(records), "successful", sum(r["http_status"] == 200 for r in records), flush=True)


if __name__ == "__main__":
    main()
