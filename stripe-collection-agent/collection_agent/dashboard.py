"""Demonstration dashboard. Runs in the AGENT host process (keyless).

It hosts the collection agent and shows each run end to end. It has the same
reach as the agent: governance (propose) and the executor (execute with a
lease, read invoice status). It cannot authorize, sign, approve or reach Stripe.

    python -m collection_agent.dashboard      (started by collection_agent.demo)
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from collection_agent.agent import CollectionAgent
from collection_agent.web import call, make_server

HERE = Path(__file__).resolve().parent


def main() -> None:
    agent = CollectionAgent(os.environ["GOVERNANCE_URL"], os.environ["EXECUTOR_URL"])
    runs: list[dict] = []
    lock = threading.Lock()
    scenarios_file = os.environ.get("SCENARIO_RESULTS", "")
    summary_file = os.environ.get("SCENARIO_SUMMARY", "")

    def run(body, q, h):
        request = (body.get("request") or "").strip()
        if not request:
            return 400, {"error": "request required"}
        override = body.get("override") or {}
        proposal = agent.interpret(request)
        if override:
            # Demonstration of a compromised / prompt-injected agent: the
            # proposal is altered AFTER interpretation. Governance sees only
            # the altered proposal, exactly as it would in an attack.
            proposal = {**proposal, **override,
                        "_interpreter": proposal.get("_interpreter", "") + "+override"}
        trace = agent.run(request, proposal)
        lease = trace.pop("lease", None)
        trace["lease_preview"] = (lease[:24] + "…") if lease else None
        trace["override"] = override
        with lock:
            runs.insert(0, trace)
            del runs[20:]
        return 200, trace

    def status(body, q, h):
        return 200, agent.invoice_status(q["_rest"])

    def evidence(body, q, h):
        g = call("GET", f"{agent.gov}/evidence")[1]
        e = call("GET", f"{agent.exe}/evidence")[1]
        return 200, {"governance": {"integrity": g.get("integrity"),
                                    "tail": (g.get("records") or [])[-8:]},
                     "executor": {"verified": e.get("verified"),
                                  "records": len(e.get("records") or []),
                                  "tail": (e.get("records") or [])[-4:]}}

    def scenarios(body, q, h):
        out = {}
        for key, f in (("results", scenarios_file), ("summary", summary_file)):
            if f and Path(f).exists():
                out[key] = json.loads(Path(f).read_text(encoding="utf-8"))
        return 200, out

    def health(body, q, h):
        status, exe = call("GET", f"{agent.exe}/health")
        backend = exe.get("backend", "unreachable") if status == 200 else "unreachable"
        return 200, {"backend": backend, "account": exe.get("account"),
                     "is_real_stripe": backend == "stripe-test-mode",
                     "interpreter": ("claude:" + os.environ.get("COLLECTION_AGENT_MODEL", "claude-opus-5-5"))
                     if os.environ.get("ANTHROPIC_API_KEY") else "rule-based (no LLM key)"}

    def customers(body, q, h):
        return 200, agent.customers()

    static = {"/": lambda: ("text/html; charset=utf-8",
                            (HERE / "static" / "index.html").read_bytes())}
    srv = make_server({("POST", "/api/run"): run, ("GET", "/api/invoice/*"): status,
                       ("GET", "/api/evidence"): evidence,
                       ("GET", "/api/scenarios"): scenarios,
                       ("GET", "/api/customers"): customers,
                       ("GET", "/api/health"): health,
                       ("GET", "/api/runs"): lambda b, q, h: (200, runs)},
                      host=os.environ.get("DASHBOARD_HOST", "127.0.0.1"),
                      port=int(os.environ.get("DASHBOARD_PORT", "8765")), static=static)
    print(f"dashboard http://{srv.server_address[0]}:{srv.server_address[1]}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
