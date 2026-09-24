"""Read-only terminal cost and model audit of two completed live extensions."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath("../campaign/experiments"))
import cma_falsification as c


def main():
    targets = json.loads(Path("../campaign/experiments/cma_extension_sessions.json").read_text())
    out = []
    for row in targets:
        code, response, request_id = c.api("GET", f"/sessions/{row['session']}")
        usage = response.get("usage") if code == 200 else None
        out.append({**row, "http_status": code, "request_id": request_id,
            "status": response.get("status"), "model": (response.get("agent") or {}).get("model"),
            "usage": usage, "list_cost_cents": (usage or {}).get("list_cost", {}).get("amount")})
        print(row["family"], row["trial"], code, flush=True)
    (c.ROOT / "extension-usage.json").write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
