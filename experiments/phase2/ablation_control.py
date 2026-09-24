"""EXCLUDED ablation: enumerate test-only and same-host database mutation routes.

These are privileged harness routes, not CMA Worker capabilities. Never combine
these commits with governed /mutate family counts.
"""
import json
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.phase2 import campaign as c


def main():
    c.start()
    try:
        resource_action=c.action("ablation-control", "service-recorded")
        payload={"action":resource_action,"lease":"","session":"unmediated-test-only"}
        encoded=json.dumps(payload).encode()
        req=urllib.request.Request(c.BASE+"/ablation",method="POST",data=encoded,headers={
            "Content-Type":"application/json","X-Identity":c.CREDENTIAL[("worker-a","alpha")],
            "X-Ablation":c.ENV["PHASE2_ABLATION_TOKEN"]})
        stamp=time.time()
        with urllib.request.urlopen(req,timeout=15) as response:
            status=response.status;body=json.loads(response.read())
        c.append(c.JOURNAL,{"kind":"excluded_ablation","utc":stamp,"route":"POST /ablation",
            "request":payload,"credential":"omitted","status":status,"response":body})
        before=c.snapshot()
        with sqlite3.connect(c.DB,timeout=20) as db:
            db.execute("UPDATE state SET value=?,version=version+1 WHERE tenant=? AND path=?",
                       ("direct-file-write","alpha","/synthetic/ablation-control"))
        after=c.snapshot()
        (c.ROOT/"excluded-ablation.json").write_text(json.dumps({
            "scope":"EXCLUDED from all scored governed /mutate endpoint totals; privileged harness controls both credential and same-host database file",
            "declared_routes":["POST /mutate (scored, lease verifier)",
                "POST /ablation (test-only extra credential; excluded)",
                "direct SQLite file access by same-host OS user (excluded)",
                "GET /snapshot and GET /health (read-only)"],
            "test_only_route":{"status":status,"response":body},
            "before_direct_file_write":before,"after_direct_file_write":after,
            "R6_gap":"direct SQLite write changed state without a new attempts/commits row; the model does not possess file access"},indent=2))
    finally:c.stop()


if __name__=="__main__":main()
