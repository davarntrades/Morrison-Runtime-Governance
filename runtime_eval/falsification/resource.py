"""The protected resource for the falsification experiments.

A synthetic ledger in SQLite: accounts with balances, a transfer log, and a
role table. It is the thing whose state the safety properties are about, so
every result is read back from this database, never from a tool response or
a governance verdict.

Mutation requires a resource token. The token is generated per experiment and
handed only to the component allowed to commit (the governed gateway, or the
ungoverned executor in a baseline arm). Agents never receive it. This models
the credential boundary a real deployment would place in front of a payment
or IAM API. Experiment E8 tests what this boundary does and does not cover.

Synthetic funds and identities only. Nothing here reaches a real system.
"""

from __future__ import annotations

import hmac
import json
import sqlite3
import time
import uuid
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, tenant TEXT NOT NULL,
                                     balance INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS effects (effect_id TEXT PRIMARY KEY, seq INTEGER,
                                    kind TEXT, src TEXT, dst TEXT, amount INTEGER,
                                    principal TEXT, role TEXT, decision_id TEXT,
                                    committed_at REAL);
CREATE TABLE IF NOT EXISTS roles (principal TEXT, role TEXT,
                                  PRIMARY KEY (principal, role));
"""


class ResourceRefused(Exception):
    """The resource itself refused the mutation (bad token, overdraft...)."""


class Ledger:
    """Token-gated synthetic ledger. Each mutation is one SQLite transaction
    (BEGIN IMMEDIATE), so concurrent writers serialise at the commit boundary
    and a transfer is all-or-nothing."""

    def __init__(self, path: Path, token: str, accounts: dict,
                 roles: tuple = ()) -> None:
        self.path = Path(path)
        self._token = token
        if self.path.exists():
            self.path.unlink()
        with self._conn() as c:
            c.executescript(SCHEMA)
            for acct, (tenant, bal) in accounts.items():
                c.execute("INSERT INTO accounts VALUES (?,?,?)", (acct, tenant, bal))
            for principal, role in roles:
                c.execute("INSERT INTO roles VALUES (?,?)", (principal, role))

    @classmethod
    def attach(cls, path: Path, token: str) -> "Ledger":
        """Open an existing ledger (another process's view of the same file)."""
        obj = cls.__new__(cls)
        obj.path, obj._token = Path(path), token
        return obj

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30, isolation_level=None)

    def _check(self, token: str) -> None:
        if not hmac.compare_digest(str(token), self._token):
            raise ResourceRefused("resource token invalid: mutation refused")

    # ── mutations ───────────────────────────────────────────
    def apply(self, token: str, action: dict, principal: str,
              decision_id: str = "") -> dict:
        """Commit one action. Returns the effect record."""
        self._check(token)
        tool, args = action["tool"], action.get("args") or {}
        effect_id = uuid.uuid4().hex
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                seq = c.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
                if tool == "transfer":
                    amt = args["amount"]
                    # A transfer moves a positive amount from `from` to `to`.
                    # A negative amount debited `to` instead (V-E12): the
                    # payee, whose owner nobody checks.
                    if (isinstance(amt, bool) or not isinstance(amt, (int, float))
                            or amt != amt or amt <= 0 or int(amt) != amt):
                        raise ResourceRefused(f"amount must be a positive whole number, got {amt!r}")
                    amt = int(amt)
                    row = c.execute("SELECT balance FROM accounts WHERE id=?",
                                    (args["from"],)).fetchone()
                    if row is None:
                        raise ResourceRefused(f"no account {args['from']}")
                    if row[0] < amt:
                        raise ResourceRefused("insufficient funds")
                    if c.execute("SELECT 1 FROM accounts WHERE id=?",
                                 (args["to"],)).fetchone() is None:
                        c.execute("INSERT INTO accounts VALUES (?,?,0)",
                                  (args["to"], "external"))
                    c.execute("UPDATE accounts SET balance=balance-? WHERE id=?",
                              (amt, args["from"]))
                    c.execute("UPDATE accounts SET balance=balance+? WHERE id=?",
                              (amt, args["to"]))
                    c.execute("INSERT INTO effects VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (effect_id, seq, "transfer", args["from"], args["to"],
                               amt, principal, None, decision_id, time.time()))
                elif tool == "grant_role":
                    c.execute("INSERT OR IGNORE INTO roles VALUES (?,?)",
                              (args["subject"], args["entitlement"]))
                    c.execute("INSERT INTO effects VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (effect_id, seq, "grant_role", None, None, None,
                               args["subject"], args["entitlement"], decision_id,
                               time.time()))
                else:
                    raise ResourceRefused(f"unknown operation {tool}")
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        return {"effect_id": effect_id, "seq": seq}

    # ── reads (no token needed) ─────────────────────────────
    def snapshot(self) -> dict:
        with self._conn() as c:
            accts = {r[0]: r[2] for r in c.execute(
                "SELECT id, tenant, balance FROM accounts ORDER BY id")}
            roles = sorted([list(r) for r in c.execute(
                "SELECT principal, role FROM roles ORDER BY principal, role")])
            effects = [dict(zip(("effect_id", "seq", "kind", "src", "dst", "amount",
                                 "principal", "role", "decision_id"), r))
                       for r in c.execute(
                "SELECT effect_id, seq, kind, src, dst, amount, principal, role, "
                "decision_id FROM effects ORDER BY seq")]
        return {"balances": accts, "roles": roles, "effects": effects}

    def outflow(self, src: str, to: str | None = None) -> int:
        with self._conn() as c:
            q = "SELECT COALESCE(SUM(amount),0) FROM effects WHERE kind='transfer' AND src=?"
            params: tuple = (src,)
            if to is not None:
                q += " AND dst=?"
                params = (src, to)
            return int(c.execute(q, params).fetchone()[0])


def snapshot_digest(snap: dict) -> str:
    import hashlib
    return hashlib.sha256(json.dumps(snap, sort_keys=True).encode()).hexdigest()
