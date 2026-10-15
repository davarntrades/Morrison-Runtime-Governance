"""Minimal JSON-over-HTTP plumbing (stdlib only) for the three processes."""

from __future__ import annotations

import hmac
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse

Route = Callable[[dict, dict, dict], tuple]


class Request(dict):
    pass


def make_server(routes: dict, host: str = "127.0.0.1", port: int = 0,
                static: Optional[dict] = None) -> ThreadingHTTPServer:
    """routes: {("GET", "/path"): fn(body, query, headers) -> (status, obj)}.
    A path ending in '/*' matches any suffix; the suffix is query['_rest']."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):                   # quiet
            pass

        def _dispatch(self, method: str):
            parsed = urlparse(self.path)
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            fn = routes.get((method, parsed.path))
            if fn is None:
                for (m, p), f in routes.items():
                    if m == method and p.endswith("/*") and \
                            parsed.path.startswith(p[:-1]):
                        fn, query["_rest"] = f, parsed.path[len(p) - 1:]
                        break
            if fn is None and method == "GET" and static and parsed.path in static:
                ctype, data = static[parsed.path]()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if fn is None:
                return self._send(404, {"error": "not found"})
            body = {}
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                try:
                    body = json.loads(self.rfile.read(length))
                except ValueError:
                    return self._send(400, {"error": "invalid JSON"})
            try:
                status, obj = fn(body, query, dict(self.headers))
            except Exception as e:                   # noqa: BLE001
                status, obj = 500, {"error": f"{type(e).__name__}: {e}"}
            self._send(status, obj)

        def _send(self, status: int, obj) -> None:
            data = json.dumps(obj, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


def serve_forever_in_thread(srv: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t


def bearer_ok(headers: dict, token: str) -> bool:
    got = ""
    for k, v in headers.items():
        if k.lower() == "authorization":
            got = v
    return bool(token) and hmac.compare_digest(got, f"Bearer {token}")


def call(method: str, url: str, body: Optional[dict] = None,
         token: str = "", timeout: float = 60.0) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": str(e)}
