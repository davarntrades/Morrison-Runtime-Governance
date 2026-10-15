"""The resource fixture: the only source of ground truth (SPEC §4).

A synthetic multi-tenant bank with documents, an outbox, roles and a password. All
state lives in one SQLite file per episode, so concurrent writers (threads, or
processes attaching to the same file) serialise at the database. Every mutation
is one IMMEDIATE transaction and appends an effect row naming the principal and
the decision reference the caller supplied.

Operation semantics are strict and realistic: a transfer moves a positive whole
amount from an existing account with sufficient funds; unknown accounts in `to`
are external payees created on first credit. Synthetic data only.

Resource-side enforcement (SPEC §3.5): a fixture may be given a `guard`, a
callable supplied by the system under test. If set, EVERY mutation, governed or
direct, must pass it; the fixture itself never interprets the token.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

SCHEMA = """
CREATE TABLE accounts (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, balance INTEGER NOT NULL);
CREATE TABLE effects  (seq INTEGER PRIMARY KEY AUTOINCREMENT, effect_id TEXT, kind TEXT, args TEXT,
                       principal TEXT, decision_ref TEXT, ts REAL);
CREATE TABLE roles    (subject TEXT, entitlement TEXT, PRIMARY KEY (subject, entitlement));
CREATE TABLE docs     (id TEXT PRIMARY KEY, trusted INTEGER, content TEXT, fields TEXT);
CREATE TABLE outbox   (seq INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT, body TEXT);
CREATE TABLE settings (k TEXT PRIMARY KEY, v TEXT);
"""

OPERATIONS = ("transfer", "grant_role", "send_email", "set_password", "read_doc")
MUTATING = ("transfer", "grant_role", "send_email", "set_password")


class Refused(Exception):
    """The resource itself refused the operation (bad arguments, funds, guard)."""


class Fixture:
    def __init__(self, path: Path, initial: dict, guard: Optional[Callable] = None) -> None:
        self.path = Path(path)
        self.guard = guard
        self._local = threading.local()
        if self.path.exists():
            self.path.unlink()
        with self._conn() as c:
            c.executescript(SCHEMA)
            for acct, spec in (initial.get("accounts") or {}).items():
                c.execute("INSERT INTO accounts VALUES (?,?,?)", (acct, spec["tenant"], int(spec["balance"])))
            for subj, ent in initial.get("roles") or []:
                c.execute("INSERT INTO roles VALUES (?,?)", (subj, ent))
            for d in initial.get("docs") or []:
                c.execute("INSERT INTO docs VALUES (?,?,?,?)", (d["id"], int(bool(d["trusted"])), d["content"],
                                                                 json.dumps(d.get("fields") or {}, sort_keys=True)))
            c.execute("INSERT INTO settings VALUES ('password', ?)", (initial.get("password", "initial"),))

    @classmethod
    def attach(cls, path: Path) -> "Fixture":
        obj = cls.__new__(cls)
        obj.path, obj.guard, obj._local = Path(path), None, threading.local()
        return obj

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=60, isolation_level=None)

    # ── reads (no effect) ────────────────────────────────────
    def read_doc(self, doc_id: str) -> dict:
        with self._conn() as c:
            row = c.execute("SELECT trusted, content, fields FROM docs WHERE id=?", (doc_id,)).fetchone()
        if row is None:
            raise Refused(f"no document {doc_id!r}")
        return {"id": doc_id, "trusted": bool(row[0]), "content": row[1], "fields": json.loads(row[2])}

    # ── the single mutation entry point ─────────────────────
    def apply(self, op: dict, principal: str, decision_ref: str = "", token: Any = None) -> dict:
        kind, args = op.get("op"), dict(op.get("args") or {})
        if kind == "read_doc":
            return {"read": self.read_doc(args.get("id", ""))}
        if kind not in MUTATING:
            raise Refused(f"unknown operation {kind!r}")
        if self.guard is not None:
            ok, why = self.guard(op, token)
            if not ok:
                raise Refused(f"resource guard: {why}")
        effect_id = uuid.uuid4().hex
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                if kind == "transfer":
                    src, dst, amt = args.get("from"), args.get("to"), args.get("amount")
                    if (isinstance(amt, bool) or not isinstance(amt, (int, float)) or amt != amt
                            or amt <= 0 or int(amt) != amt):
                        raise Refused(f"amount must be a positive whole number, got {amt!r}")
                    if not isinstance(src, str) or not isinstance(dst, str) or src == dst:
                        raise Refused("transfer needs distinct string accounts")
                    row = c.execute("SELECT balance FROM accounts WHERE id=?", (src,)).fetchone()
                    if row is None:
                        raise Refused(f"no account {src!r}")
                    if row[0] < amt:
                        raise Refused("insufficient funds")
                    if c.execute("SELECT 1 FROM accounts WHERE id=?", (dst,)).fetchone() is None:
                        c.execute("INSERT INTO accounts VALUES (?, 'external', 0)", (dst,))
                    c.execute("UPDATE accounts SET balance=balance-? WHERE id=?", (int(amt), src))
                    c.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (int(amt), dst))
                elif kind == "grant_role":
                    c.execute("INSERT OR IGNORE INTO roles VALUES (?,?)", (args["subject"], args["entitlement"]))
                elif kind == "send_email":
                    c.execute("INSERT INTO outbox (recipient, body) VALUES (?,?)", (args["to"], args.get("body", "")))
                elif kind == "set_password":
                    c.execute("UPDATE settings SET v=? WHERE k='password'", (str(args["password"]),))
                c.execute("INSERT INTO effects (effect_id, kind, args, principal, decision_ref, ts) "
                          "VALUES (?,?,?,?,?,?)",
                          (effect_id, kind, json.dumps(args, sort_keys=True), principal,
                           str(decision_ref or ""), time.time()))
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        return {"effect_id": effect_id}

    # ── ground truth ─────────────────────────────────────────
    def snapshot(self) -> dict:
        with self._conn() as c:
            accounts = {r[0]: {"tenant": r[1], "balance": r[2]}
                        for r in c.execute("SELECT id, tenant, balance FROM accounts ORDER BY id")}
            effects = [{"seq": r[0], "effect_id": r[1], "kind": r[2], "args": json.loads(r[3]),
                        "principal": r[4], "decision_ref": r[5]}
                       for r in c.execute("SELECT seq, effect_id, kind, args, principal, decision_ref, ts "
                                          "FROM effects ORDER BY seq")]
            roles = sorted([list(r) for r in c.execute("SELECT subject, entitlement FROM roles")])
            outbox = [{"to": r[0], "body": r[1]} for r in c.execute("SELECT recipient, body FROM outbox ORDER BY seq")]
            pw = c.execute("SELECT v FROM settings WHERE k='password'").fetchone()[0]
        return {"accounts": accounts, "effects": effects, "roles": roles, "outbox": outbox, "password": pw}
