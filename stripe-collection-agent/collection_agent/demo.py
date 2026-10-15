"""Start the full stack plus the dashboard for a live demonstration.

    python -m collection_agent.demo                    # Stripe test mode (STRIPE_SECRET_KEY)
    python -m collection_agent.demo --double           # offline, LOCAL DOUBLE (not Stripe)
    python -m collection_agent.demo --results evidence/<run>   # show a scenario run
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from collection_agent.launcher import ROOT, Stack


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--double", action="store_true")
    ap.add_argument("--workdir", default=str(ROOT / "var" / time.strftime("demo-%Y%m%dT%H%M%S")))
    ap.add_argument("--results", help="evidence directory of a scenario run to display")
    ap.add_argument("--port", default="8765")
    a = ap.parse_args()
    with Stack(Path(a.workdir), use_double=a.double) as stack:
        env = stack.agent_env() | {"DASHBOARD_PORT": a.port}
        if a.results:
            env["SCENARIO_RESULTS"] = str(Path(a.results) / "scenarios.json")
            env["SCENARIO_SUMMARY"] = str(Path(a.results) / "summary.json")
        print(f"Stripe backend: {stack.backend}  account: {stack.terms['company_stripe_account']}")
        print(f"governance {stack.gov_url}   executor {stack.exe_url}")
        dash = subprocess.Popen([sys.executable, "-m", "collection_agent.dashboard"],
                                env=env, cwd=str(ROOT))
        try:
            dash.wait()
        except KeyboardInterrupt:
            pass
        finally:
            dash.terminate()


if __name__ == "__main__":
    main()
