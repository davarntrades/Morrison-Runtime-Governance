"""Agent-side steps, run in a KEYLESS child process by the scenario harness.

Everything the agent does in the adversarial scenarios (honest runs and
misbehaviour alike: replaying a lease, mutating an authorised request,
calling the executor with no lease, racing proposals) happens here, in a
process whose environment holds no Stripe key, no operator token and no
service token. The harness (operator/auditor) only verifies effects.

    python -m collection_agent.agent_steps <step>   < input.json   > output.json
"""

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from collection_agent.agent import CollectionAgent


def main() -> None:
    step = sys.argv[1]
    data = json.load(sys.stdin)
    agent = CollectionAgent(os.environ["GOVERNANCE_URL"], os.environ["EXECUTOR_URL"])
    if step == "env":
        out = {"secrets_present": [k for k in (
            "STRIPE_SECRET_KEY", "OPERATOR_TOKEN", "GOVERNANCE_SERVICE_TOKEN",
            "STRIPE_API_KEY", "STRIPE_WEBHOOK_SECRET") if os.environ.get(k)]}
        try:
            from collection_agent.stripe_gateway import StripeGateway
            StripeGateway()
            out["direct_stripe"] = "constructed (UNEXPECTED)"
        except Exception as e:                                # noqa: BLE001
            out["direct_stripe"] = f"refused: {type(e).__name__}: {e}"
    elif step == "run":
        out = agent.run(data["request"], data.get("proposal"))
    elif step == "interpret":
        out = agent.interpret(data["request"])
    elif step == "propose":
        out = agent.submit(data["operation"])
    elif step == "execute":
        status, body = agent.execute(data.get("lease"), data["operation"])
        out = {"http_status": status, **body}
    elif step == "status":
        out = agent.invoice_status(data["invoice_id"])
    elif step == "concurrent":
        ops = data["operations"]
        with ThreadPoolExecutor(len(ops)) as pool:
            decisions = list(pool.map(agent.submit, ops))
        granted = [(o, d) for o, d in zip(ops, decisions) if d.get("lease")]
        with ThreadPoolExecutor(max(1, len(granted))) as pool:
            execs = list(pool.map(lambda od: agent.execute(od[1]["lease"], od[0]),
                                  granted))
        out = {"decisions": [{k: v for k, v in d.items() if k != "lease"}
                             for d in decisions],
               "executions": [{"http_status": s, **b} for s, b in execs]}
    else:
        raise SystemExit(f"unknown step {step}")
    json.dump(out, sys.stdout, default=str)


if __name__ == "__main__":
    main()
