"""Governance service (trusted process): Morrison decides here.

Holds the GovernanceKernel, the commercial terms, the Ed25519 lease signing
key and the finance approval key. Holds NO Stripe key. Observed collection
state is read from the executor over an authenticated service channel; if it
cannot be read, the envelope rules receive no trusted state and fail closed.

Agent-facing:     GET /customers, GET /terms, POST /propose, GET /evidence
Operator-only:    POST /operator/approve, POST /operator/agreement
                  (bearer OPERATOR_TOKEN, which the agent process never has)

    python -m collection_agent.governance_service
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from collection_agent.governance import CollectionGovernor
from collection_agent.signer import LeaseSigner
from collection_agent.web import bearer_ok, call, make_server


def build(terms_file: str, state_dir: str, executor_url_file: str,
          service_token: str) -> tuple[CollectionGovernor, LeaseSigner]:
    terms = json.loads(Path(terms_file).read_text(encoding="utf-8"))

    def observed() -> dict:
        url = Path(executor_url_file).read_text(encoding="utf-8").strip()
        status, body = call("GET", f"{url}/collection-state", token=service_token,
                            timeout=60)
        if status != 200:
            raise RuntimeError(f"executor collection-state HTTP {status}: {body}")
        return body

    signer = LeaseSigner()
    gov = CollectionGovernor(terms, Path(state_dir), signer, observed)
    return gov, signer


def routes(gov: CollectionGovernor, operator_token: str) -> dict:
    def customers(b, q, h):
        return 200, {ref: c.get("name") for ref, c in gov.terms["customers"].items()}

    def terms(b, q, h):
        t = gov.public_terms(q.get("customer", ""))
        return (200, t) if t else (404, {"error": "unknown customer"})

    def propose(b, q, h):
        out = gov.propose(b.get("call") or {})
        return 200, out.as_dict()

    def evidence(b, q, h):
        return 200, gov.evidence()

    def approve(b, q, h):
        if not bearer_ok(h, operator_token):
            return 401, {"error": "operator token required"}
        return 200, gov.approve(b["call"])

    def agreement(b, q, h):
        if not bearer_ok(h, operator_token):
            return 401, {"error": "operator token required"}
        return 200, gov.update_agreement(b["customer"], b["changes"])

    def position(b, q, h):
        if not bearer_ok(h, operator_token):
            return 401, {"error": "operator token required"}
        return 200, {"envelope": gov.envelope_snapshot(),
                     "trajectory": gov.kernel.executed_history}

    return {("GET", "/customers"): customers, ("GET", "/terms"): terms,
            ("POST", "/propose"): propose, ("GET", "/evidence"): evidence,
            ("POST", "/operator/approve"): approve,
            ("POST", "/operator/agreement"): agreement,
            ("GET", "/operator/position"): position,
            ("GET", "/health"): lambda b, q, h: (200, {"ok": True})}


def main() -> None:
    state = Path(os.environ["GOVERNANCE_STATE_DIR"])
    state.mkdir(parents=True, exist_ok=True)
    gov, signer = build(os.environ["TERMS_FILE"], str(state),
                        os.environ["EXECUTOR_URL_FILE"],
                        os.environ["GOVERNANCE_SERVICE_TOKEN"])
    # The executor gets the PUBLIC key only.
    Path(os.environ["MORRISON_LEASE_PUBKEY_FILE"]).write_text(signer.public_key.hex(),
                                                            encoding="utf-8")
    srv = make_server(routes(gov, os.environ["OPERATOR_TOKEN"]),
                      port=int(os.environ.get("GOVERNANCE_PORT", "0")))
    (state / "governance.port").write_text(str(srv.server_address[1]), encoding="utf-8")
    srv.serve_forever()


if __name__ == "__main__":
    main()
