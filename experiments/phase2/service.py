"""Separate, durable synthetic resource boundary for the frozen Phase 2 protocol."""
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from morrison_governance.kernel import ExecutionLease, LeaseVerifier
from morrison_governance.kernel.canonical import action_hash

DB = Path(os.environ["PHASE2_DB"])
KEY = base64.b64decode(os.environ["PHASE2_LEASE_KEY_B64"])
IDENTITIES = json.loads(os.environ["PHASE2_IDENTITIES_JSON"])
ABLATION = os.environ.get("PHASE2_ABLATION_TOKEN", "")


def connect():
    db = sqlite3.connect(DB, timeout=30, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=30000")
    return db


def initialize():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS state(tenant TEXT, path TEXT, value TEXT, version INTEGER, PRIMARY KEY(tenant,path));
        CREATE TABLE IF NOT EXISTS redemptions(lease_id TEXT PRIMARY KEY, commit_id INTEGER);
        CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY AUTOINCREMENT, utc REAL, principal TEXT, tenant TEXT,
          claimed_session TEXT, raw_request TEXT, action_json TEXT, lease_id TEXT, verifier_ok INTEGER,
          verifier_reason TEXT, outcome TEXT, before_json TEXT, after_json TEXT, commit_id INTEGER);
        CREATE TABLE IF NOT EXISTS commits(id INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id INTEGER, prev_hash TEXT,
          receipt_hash TEXT, utc REAL, principal TEXT, tenant TEXT, session TEXT, path TEXT,
          before_json TEXT, after_json TEXT, lease_id TEXT, decision_id TEXT, action_hash TEXT);
        """)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, code, payload):
        raw = json.dumps(payload, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"ok": True, "pid": os.getpid()})
        if self.path != "/snapshot":
            return self.reply(404, {"error": "unknown route"})
        with connect() as db:
            rows = lambda table: [dict(zip([x[0] for x in cur.description], row)) for cur in [db.execute(f"SELECT * FROM {table} ORDER BY 1")] for row in cur]
            self.reply(200, {"state": rows("state"), "redemptions": rows("redemptions"),
                             "attempts": rows("attempts"), "commits": rows("commits")})

    def do_POST(self):
        if self.path not in ("/mutate", "/ablation"):
            return self.reply(404, {"error": "unknown mutation route"})
        length = int(self.headers.get("Content-Length", 0))
        if length > 1048576:
            return self.reply(413, {"error": "request too large"})
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError):
            return self.reply(400, {"error": "malformed JSON"})
        token = self.headers.get("X-Identity", "")
        actor = next((v for k, v in IDENTITIES.items() if hmac.compare_digest(k, token)), None)
        if not actor:
            return self.reply(401, {"error": "identity credential invalid"})
        principal, tenant = actor["principal"], actor["tenant"]
        if self.path == "/ablation" and (not ABLATION or not hmac.compare_digest(self.headers.get("X-Ablation", ""), ABLATION)):
            return self.reply(403, {"error": "test-only ablation credential required"})
        action, authority = data.get("action"), data.get("lease", "")
        claimed_session = data.get("session", "")
        phase = data.get("failure_phase", "")
        lease_id = decision_id = ""
        try:
            lease = ExecutionLease.decode(authority)
            lease_id, decision_id = lease.lease_id, lease.decision_id
        except Exception:
            pass
        db = connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            before = None
            if isinstance(action, dict):
                args = action.get("args", {})
                path = args.get("path") if isinstance(args, dict) else None
                if isinstance(path, str):
                    row = db.execute("SELECT value,version FROM state WHERE tenant=? AND path=?", (tenant, path)).fetchone()
                    before = {"value": row[0], "version": row[1]} if row else {"value": None, "version": 0}
            if self.path == "/ablation":
                ok, reason = True, "EXCLUDED_TEST_ONLY_ABLATION"
            else:
                # The actual production verifier. Its _consume callback is a durable,
                # atomic redemption within the same SQLite transaction as the commit.
                def consume(ident):
                    try:
                        db.execute("INSERT INTO redemptions(lease_id,commit_id) VALUES(?,NULL)", (ident,))
                        return True
                    except sqlite3.IntegrityError:
                        return False
                verifier = LeaseVerifier(key=KEY, _consume=consume)
                ok, reason = verifier.verify(authority, action)
            allowed_shape = isinstance(action, dict) and action.get("tool") == "write_file" and isinstance(action.get("args"), dict) and isinstance(action["args"].get("path"), str) and isinstance(action["args"].get("content"), str) and action["args"]["path"].startswith("/synthetic/")
            if not allowed_shape:
                ok, reason = False, "synthetic service action shape invalid"
            outcome = "ACCEPT" if ok else "REJECT"
            cur = db.execute("INSERT INTO attempts(utc,principal,tenant,claimed_session,raw_request,action_json,lease_id,verifier_ok,verifier_reason,outcome,before_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), principal, tenant, claimed_session, raw.decode(errors="replace"), json.dumps(action, sort_keys=True), lease_id, int(ok), reason, outcome, json.dumps(before)))
            attempt_id = cur.lastrowid
            if not ok:
                db.commit()
                return self.reply(403, {"accepted": False, "attempt_id": attempt_id, "reason": reason})
            if phase == "before_commit":
                db.rollback()
                os._exit(70)
            path, content = action["args"]["path"], action["args"]["content"]
            version = before["version"] + 1
            after = {"value": content, "version": version}
            db.execute("INSERT INTO state(tenant,path,value,version) VALUES(?,?,?,?) ON CONFLICT(tenant,path) DO UPDATE SET value=excluded.value,version=excluded.version", (tenant, path, content, version))
            previous = db.execute("SELECT receipt_hash FROM commits ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = previous[0] if previous else "0" * 64
            fields = {"attempt_id": attempt_id, "utc": time.time(), "principal": principal,
                "tenant": tenant, "session": claimed_session, "path": path, "before": before,
                "after": after, "lease_id": lease_id, "decision_id": decision_id,
                "action_hash": action_hash(action), "prev_hash": prev_hash}
            receipt_hash = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            cur = db.execute("INSERT INTO commits(attempt_id,prev_hash,receipt_hash,utc,principal,tenant,session,path,before_json,after_json,lease_id,decision_id,action_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (attempt_id,prev_hash,receipt_hash,fields["utc"],principal,tenant,claimed_session,path,json.dumps(before),json.dumps(after),lease_id,decision_id,fields["action_hash"]))
            commit_id = cur.lastrowid
            db.execute("UPDATE attempts SET after_json=?,commit_id=? WHERE id=?", (json.dumps(after),commit_id,attempt_id))
            if self.path != "/ablation":
                db.execute("UPDATE redemptions SET commit_id=? WHERE lease_id=?", (commit_id,lease_id))
            db.commit()
            if phase == "after_commit":
                os._exit(71)
            return self.reply(200, {"accepted": True, "attempt_id": attempt_id, "commit_id": commit_id,
                                    "receipt_hash": receipt_hash, "before": before, "after": after})
        finally:
            db.close()


if __name__ == "__main__":
    initialize()
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PHASE2_PORT", "18761"))), Handler).serve_forever()
