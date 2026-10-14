"""A three-identity deployment of the ledger, for E8 and its re-falsification.

    governor  (this process)   holds the kernel and the Ed25519 lease seed,
                               in memory only; mints one lease per PERMIT
    resource  (uid 10001)      resource_server.py; owns the ledger file and the
                               lease registry (mode 0700); commits only on a
                               valid, unspent, request-bound lease
    agent     (uid 10002)      adversary.py; can reach the resource socket and
                               knows every path, holds no credential

Creating the identities needs root. Without it `available()` is False and the
experiments that need it record that they did not run.
"""

from __future__ import annotations

import dataclasses
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from morrison_governance._ed25519_test_signer import public_key, sign
from morrison_governance.kernel import SQLiteLeaseStore

REPO = Path(__file__).resolve().parents[2]
RESOURCE_UID = 10001
AGENT_UID = 10002


def available() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _as(uid: int):
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return drop


class Client:
    def __init__(self, path: Path) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(str(path))
        self.f = self.sock.makefile("rwb")

    def call(self, msg: dict) -> dict:
        self.f.write((json.dumps(msg) + "\n").encode())
        self.f.flush()
        return json.loads(self.f.readline())

    def close(self) -> None:
        self.f.close()
        self.sock.close()


class IsolatedDeployment:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="morrison-iso-")
        self.base = Path(self._tmp.name)
        os.chmod(self.base, 0o755)
        for sub, mode in (("resource", 0o700), ("leases", 0o700), ("sock", 0o755)):
            d = self.base / sub
            d.mkdir()
            os.chown(d, RESOURCE_UID, RESOURCE_UID)
            os.chmod(d, mode)
        self._seed = secrets.token_bytes(32)          # governor memory only
        self.public = public_key(self._seed)
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(REPO),
               "HOME": "/nonexistent"}
        self.server = subprocess.Popen(
            [sys.executable, "-m", "runtime_eval.falsification.resource_server",
             "--base", str(self.base), "--public", self.public.hex()],
            cwd=str(REPO), env=env, preexec_fn=_as(RESOURCE_UID),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.server.stdout.readline().strip()
        if line != "ready":
            raise RuntimeError(f"resource server failed: {line} {self.server.stderr.read()[-500:]}")
        self.socket_path = self.base / "sock" / "resource.sock"
        self.lease_store = SQLiteLeaseStore(self.base / "leases" / "leases.db")
        self.client = Client(self.socket_path)

    # ── governor side ───────────────────────────────────────
    def signer(self, message: bytes) -> bytes:
        return sign(self._seed, message)

    def arm(self, kernel):
        """Give a kernel this deployment's lease signer and registry."""
        kernel.ctx = dataclasses.replace(kernel.ctx, lease_signer=self.signer,
                                         lease_store=self.lease_store)
        return kernel

    def submit(self, kernel, call: dict) -> dict:
        """authorize -> mint lease -> resource. Returns a record."""
        d = kernel.authorize(call)
        rec = {"call": call, "principal": kernel.ctx.principal.id, "verdict": d.verdict,
               "layer": d.layer, "rule": d.rule, "reason": d.reason[:200],
               "decision_id": d.decision_id, "executed": False}
        if d.permitted:
            lease = kernel.mint_lease(d).encode()
            rec["lease"] = lease
            reply = self.client.call({"op": "apply", "lease": lease, "request": d.action})
            rec["resource"] = reply
            rec["executed"] = bool(reply.get("ok"))
        return rec

    def snapshot(self) -> dict:
        return self.client.call({"op": "snapshot"})["snapshot"]

    # ── agent side ──────────────────────────────────────────
    def run_agent(self, payload: dict) -> dict:
        """Run adversary.py as the agent identity with `payload` on stdin."""
        payload = {**payload, "base": str(self.base), "socket": str(self.socket_path),
                   "db": str(self.base / "resource" / "ledger.db"),
                   "lease_db": str(self.base / "leases" / "leases.db"),
                   "governor_pid": os.getpid(), "resource_pid": self.server.pid}
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(REPO),
               "HOME": "/nonexistent"}
        out = subprocess.run(
            [sys.executable, "-m", "runtime_eval.falsification.adversary"],
            input=json.dumps(payload), cwd=str(REPO), env=env, preexec_fn=_as(AGENT_UID),
            capture_output=True, text=True, timeout=120)
        if out.returncode != 0:
            return {"error": out.stderr[-2000:]}
        return json.loads(out.stdout)

    def close(self) -> None:
        try:
            self.client.close()
        finally:
            self.server.terminate()
            self.server.wait(timeout=10)
            self._tmp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
