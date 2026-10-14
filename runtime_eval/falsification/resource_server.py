"""The protected ledger as a separate service behind an execution-lease check
(repair for E8; also the resource-side half of the E12 and E10 repairs).

    python -m runtime_eval.falsification.resource_server --base DIR --public HEX

Run it as its own OS user. It owns DIR/resource (the ledger database) and
DIR/leases (the lease registry), both mode 0700, and listens on
DIR/sock/resource.sock, which anyone may connect to. A mutation is committed
only when the request carries a Morrison execution lease that

  * verifies against the governor's Ed25519 public key,
  * is bound to exactly this request (canonical action hash),
  * is registered and not yet redeemed (single use, atomic), and
  * was issued to a principal of the tenant that owns the debited account.

The effect row records the lease's principal and decision id, so every effect
names the decision that authorised it, independently of the kernel's own
evidence. Synthetic funds only.

Protocol: one JSON object per line in, one JSON object per line out.
  {"op": "apply", "lease": TOKEN, "request": {...}}
  {"op": "snapshot"}
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socketserver
import sys
from pathlib import Path

from morrison_governance.kernel import ExecutionLease, LeaseVerifier, SQLiteLeaseStore
from morrison_governance.kernel.canonical import canonicalize
from runtime_eval.falsification.resource import Ledger, ResourceRefused

ACCOUNTS = {"OPS": ("acme", 100_000), "SHARED": ("acme", 100_000),
            "BETA-OPS": ("beta", 100_000)}


class Service:
    def __init__(self, base: Path, public: bytes, accounts: dict) -> None:
        for sub in ("resource", "leases"):
            (base / sub).mkdir(mode=0o700, exist_ok=True)
            os.chmod(base / sub, 0o700)
        self._token = secrets.token_hex(16)          # never leaves this process
        self.ledger = Ledger(base / "resource" / "ledger.db", self._token, accounts)
        os.chmod(base / "resource" / "ledger.db", 0o600)
        self.leases = SQLiteLeaseStore(base / "leases" / "leases.db")
        os.chmod(base / "leases" / "leases.db", 0o600)
        self.verifier = LeaseVerifier(public, self.leases)
        self.tenants = {k: v[0] for k, v in accounts.items()}

    def apply(self, token: str, request: dict) -> dict:
        # R1: everything that can refuse runs BEFORE the lease is spent, so a
        # refused request cannot burn a lease the governor will still use.
        # The request must already be in the canonical form the lease hash
        # binds: several spellings hash alike (tool case and padding, args
        # outside "args", 10.0 vs 10), and the ledger must interpret exactly
        # the bytes that were authorised, not a different reading of them.
        if not isinstance(request, dict) or canonicalize(request) != request:
            return {"ok": False, "refused_by": "shape",
                    "reason": "request is not in canonical form"}
        try:
            claimed = ExecutionLease.decode(token)   # unauthenticated: may only refuse
        except Exception:                            # noqa: BLE001
            claimed = None
        src = (request.get("args") or {}).get("from")
        if claimed is not None and request.get("tool") == "transfer":
            owner = self.tenants.get(src)
            if owner is None or owner != claimed.tenant:
                return {"ok": False, "refused_by": "ownership",
                        "reason": f"lease tenant {claimed.tenant!r} does not own {src!r}"}
        ok, reason = self.verifier.verify(token, request)
        if not ok:
            return {"ok": False, "refused_by": "lease", "reason": reason}
        lease = ExecutionLease.decode(token)
        owner = self.tenants.get(src) if request.get("tool") == "transfer" else lease.tenant
        if owner is None or owner != lease.tenant:
            return {"ok": False, "refused_by": "ownership",
                    "reason": f"lease tenant {lease.tenant!r} does not own {src!r}"}
        try:
            eff = self.ledger.apply(self._token, request, lease.principal, lease.decision_id)
        except ResourceRefused as exc:
            return {"ok": False, "refused_by": "resource", "reason": str(exc)}
        return {"ok": True, "effect": eff, "lease_id": lease.lease_id,
                "decision_id": lease.decision_id, "principal": lease.principal}

    def handle(self, msg: dict) -> dict:
        op = msg.get("op")
        if op == "apply":
            return self.apply(msg.get("lease") or "", msg.get("request") or {})
        if op == "snapshot":
            return {"ok": True, "snapshot": self.ledger.snapshot()}
        return {"ok": False, "reason": f"unknown op {op!r}"}


def serve(base: Path, public: bytes) -> None:
    service = Service(base, public, ACCOUNTS)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            for line in self.rfile:
                try:
                    reply = service.handle(json.loads(line))
                except Exception as exc:              # noqa: BLE001 - refuse
                    reply = {"ok": False, "reason": f"bad request: {type(exc).__name__}"}
                self.wfile.write((json.dumps(reply) + "\n").encode())

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    path = base / "sock" / "resource.sock"
    if path.exists():
        path.unlink()
    with Server(str(path), Handler) as srv:
        os.chmod(path, 0o666)
        print("ready", flush=True)
        srv.serve_forever()


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base", type=Path, required=True)
    p.add_argument("--public", required=True)
    a = p.parse_args(argv)
    serve(a.base, bytes.fromhex(a.public))
    return 0


if __name__ == "__main__":
    sys.exit(main())
