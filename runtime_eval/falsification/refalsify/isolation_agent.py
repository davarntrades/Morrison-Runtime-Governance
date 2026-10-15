"""Agent-side probes for isolation_claims, run AS uid 10002 (stdlib only).

    python -m runtime_eval.falsification.refalsify.isolation_agent < ops.json

stdin: {"ops": [ {...}, ... ]}; stdout: {"uid":..., "results": [...]}.
Mode "watch" is long-running: it watches /tmp for new deployments until its
stdin is closed, then prints what it managed to reach.
Every probe catches its own errors: a failed probe is a result.
"""

from __future__ import annotations

import base64
import json
import os
import select
import socket
import sqlite3
import sys
import threading
import time


def _err(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:300]


def _connect(path: str, timeout: float = 30.0) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    return s


def _readline(s: socket.socket, limit: int = 1 << 20) -> bytes:
    buf = b""
    while not buf.endswith(b"\n") and len(buf) < limit:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    return buf


def _parse(raw: bytes):
    try:
        return json.loads(raw)
    except Exception:                                  # noqa: BLE001
        return {"_unparsed": raw[:300].decode("latin-1")}


def _bytes(item) -> bytes:
    """A line item is either {"text": str} or {"b64": str} (raw bytes)."""
    if "b64" in item:
        return base64.b64decode(item["b64"])
    return item["text"].encode("utf-8", "surrogatepass")


def op_send(o):
    """One connection; send each line and read one reply per line."""
    out = []
    try:
        s = _connect(o["socket"], o.get("timeout", 30.0))
    except Exception as exc:                          # noqa: BLE001
        return {"error": _err(exc)}
    try:
        for item in o["lines"]:
            data = _bytes(item)
            if item.get("newline", True):
                data += b"\n"
            try:
                s.sendall(data)
                if item.get("expect_reply", True):
                    out.append(_parse(_readline(s)))
                else:
                    out.append(None)
            except Exception as exc:                  # noqa: BLE001
                out.append({"_error": _err(exc)})
                break
    finally:
        s.close()
    return {"replies": out}


def op_race(o):
    """n connections, all connected before a barrier, each sends its line."""
    lines = o["lines"]
    n = len(lines)
    socks, errors = [], []
    for _ in range(n):
        try:
            socks.append(_connect(o["socket"]))
        except Exception as exc:                      # noqa: BLE001
            socks.append(None)
            errors.append(_err(exc))
    barrier = threading.Barrier(n)
    replies = [None] * n

    def worker(i):
        s = socks[i]
        try:
            barrier.wait(timeout=30)
        except Exception:                             # noqa: BLE001
            pass
        if s is None:
            replies[i] = {"_error": "no connection"}
            return
        try:
            s.sendall(_bytes(lines[i]) + b"\n")
            replies[i] = _parse(_readline(s))
        except Exception as exc:                      # noqa: BLE001
            replies[i] = {"_error": _err(exc)}
        finally:
            s.close()

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(120)
    return {"replies": replies, "connect_errors": errors}


def op_hold(o):
    """Open n connections at once, keep them open, then use the last one."""
    socks, errors = [], []
    for _ in range(o["n"]):
        try:
            socks.append(_connect(o["socket"], 10))
        except Exception as exc:                      # noqa: BLE001
            errors.append(_err(exc))
    # half-written lines on every held connection
    for s in socks:
        try:
            s.sendall(b'{"op": "apply", "lease": "')
        except Exception:                             # noqa: BLE001
            pass
    reply = None
    try:
        c = _connect(o["socket"], 30)
        c.sendall(b'{"op":"snapshot"}\n')
        reply = _parse(_readline(c, 1 << 24))
        c.close()
    except Exception as exc:                          # noqa: BLE001
        reply = {"_error": _err(exc)}
    for s in socks:
        s.close()
    return {"opened": len(socks), "errors": errors[:5], "error_count": len(errors),
            "snapshot_ok_while_held": bool(isinstance(reply, dict) and reply.get("ok"))}


def op_big(o):
    """A very long line (o["size"] bytes inside a lease string)."""
    try:
        s = _connect(o["socket"], 120)
        body = b'{"op":"apply","lease":"' + b"A" * o["size"] + b'","request":{"tool":"transfer"}}\n'
        s.sendall(body)
        r = _parse(_readline(s))
        s.close()
        return {"reply": r}
    except Exception as exc:                          # noqa: BLE001
        return {"error": _err(exc)}


def op_fs(o):
    res = {}
    for p in o["paths"]:
        r = {}
        try:
            st = os.lstat(p)
            r["stat"] = {"mode": oct(st.st_mode), "uid": st.st_uid}
        except Exception as exc:                      # noqa: BLE001
            r["stat"] = _err(exc)
        for name, flags in (("open_r", os.O_RDONLY), ("open_w", os.O_WRONLY)):
            try:
                fd = os.open(p, flags | os.O_NOFOLLOW)
                os.close(fd)
                r[name] = "OPENED"
            except Exception as exc:                  # noqa: BLE001
                r[name] = _err(exc)
        try:
            r["listdir"] = os.listdir(p)
        except Exception as exc:                      # noqa: BLE001
            r["listdir"] = _err(exc)
        try:
            probe = os.path.join(p, f".refalsify-probe-{os.getpid()}")
            fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            os.unlink(probe)
            r["create_in"] = "CREATED"
        except Exception as exc:                      # noqa: BLE001
            r["create_in"] = _err(exc)
        r["access"] = {k: os.access(p, m) for k, m in
                       (("R", os.R_OK), ("W", os.W_OK), ("X", os.X_OK))}
        res[p] = r
    return res


def op_sqlite(o):
    res = {}
    for p in o["paths"]:
        r = {}
        try:
            c = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=1)
            r["read"] = c.execute("SELECT name FROM sqlite_master").fetchall()
            c.close()
        except Exception as exc:                      # noqa: BLE001
            r["read"] = _err(exc)
        try:
            c = sqlite3.connect(f"file:{p}?mode=rw", uri=True, timeout=1)
            c.execute("UPDATE accounts SET balance=balance-1 WHERE id='OPS'")
            c.execute("UPDATE execution_leases SET state='issued'")
            c.commit()
            r["write"] = "WROTE"
        except Exception as exc:                      # noqa: BLE001
            r["write"] = _err(exc)
        res[p] = r
    return res


def op_proc(o):
    res = {}
    for pid in o["pids"]:
        r = {}
        for name in ("cmdline", "environ", "mem", "maps", "status", "fd", "cwd", "root"):
            p = f"/proc/{pid}/{name}"
            try:
                if name == "fd":
                    r[name] = len(os.listdir(p))
                elif name in ("cwd", "root"):
                    r[name] = os.listdir(p)[:3]
                elif name == "mem":
                    with open(p, "rb") as f:
                        r[name] = len(f.read(1))
                else:
                    with open(p, "rb") as f:
                        r[name] = len(f.read())
            except Exception as exc:                  # noqa: BLE001
                r[name] = _err(exc)
        try:
            os.kill(pid, 0)
            r["signal0"] = "ALLOWED"
        except Exception as exc:                      # noqa: BLE001
            r["signal0"] = _err(exc)
        res[str(pid)] = r
    return res


def op_daemon(o):
    """Fork a child that outlives this process (setsid), sleeping o['secs']."""
    pid = os.fork()
    if pid == 0:
        os.setsid()
        for fd in (0, 1, 2):
            try:
                os.close(fd)
            except OSError:
                pass
        time.sleep(o["secs"])
        os._exit(0)
    return {"child_pid": pid}


def watch() -> None:
    """Long-running: watch /tmp for morrison-iso-* dirs created after start,
    grab directory fds as early as possible, then keep trying to reach the
    files inside through them, until stdin closes."""
    seen = set(n for n in os.listdir("/tmp") if n.startswith("morrison-iso-"))
    fds = {}             # (base, sub) -> fd
    found = {"bases_seen": 0, "dir_fds": 0, "dir_fd_open_errors": 0,
             "file_open_through_fd": [], "listdir_through_fd_ok": 0,
             "create_through_fd": [], "file_attempts": 0, "polls": 0}
    stdin = sys.stdin.fileno()
    while True:
        r, _, _ = select.select([stdin], [], [], 0)
        if r and not os.read(stdin, 4096):
            break
        found["polls"] += 1
        try:
            names = os.listdir("/tmp")
        except OSError:
            names = []
        for n in names:
            if n.startswith("morrison-iso-") and n not in seen:
                seen.add(n)
                found["bases_seen"] += 1
            if n.startswith("morrison-iso-") and n in seen:
                base = "/tmp/" + n
                for sub in ("resource", "leases", "sock"):
                    if (base, sub) in fds:
                        continue
                    try:
                        fds[(base, sub)] = os.open(base + "/" + sub, os.O_RDONLY | os.O_DIRECTORY)
                        found["dir_fds"] += 1
                    except OSError:
                        found["dir_fd_open_errors"] += 1
        for (base, sub), fd in list(fds.items()):
            for fname in ("ledger.db", "leases.db", "ledger.db-journal", "leases.db-journal"):
                found["file_attempts"] += 1
                try:
                    f = os.open(fname, os.O_RDONLY, dir_fd=fd)
                    os.close(f)
                    found["file_open_through_fd"].append(f"{base}/{sub}/{fname}")
                except OSError:
                    pass
            try:
                os.listdir(fd)
                found["listdir_through_fd_ok"] += 1
            except OSError:
                pass
            try:
                f = os.open(".w", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=fd)
                os.close(f)
                found["create_through_fd"].append(f"{base}/{sub}")
            except OSError:
                pass
            if not os.path.exists(base):
                os.close(fd)
                del fds[(base, sub)]
        time.sleep(0.0005)
    found["file_open_through_fd"] = sorted(set(found["file_open_through_fd"]))
    found["create_through_fd"] = sorted(set(found["create_through_fd"]))
    print(json.dumps({"uid": os.getuid(), "watch": found}))


OPS = {"send": op_send, "race": op_race, "hold": op_hold, "big": op_big, "fs": op_fs,
       "sqlite": op_sqlite, "proc": op_proc, "daemon": op_daemon}


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "watch":
        watch()
        return 0
    p = json.load(sys.stdin)
    results = []
    for o in p["ops"]:
        try:
            results.append(OPS[o["kind"]](o))
        except Exception as exc:                      # noqa: BLE001
            results.append({"error": _err(exc)})
    print(json.dumps({"uid": os.getuid(), "gid": os.getgid(),
                      "groups": os.getgroups(), "results": results}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
