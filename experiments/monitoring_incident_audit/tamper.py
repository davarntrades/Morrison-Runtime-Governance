"""Evidence tampering on a COPY of one reproduced log (C05, hierarchical, deny)."""
import copy, hashlib, json, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
src, dst = sys.argv[1], sys.argv[2]
shutil.copytree(src, dst, dirs_exist_ok=True)
canon = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=repr)
rh = lambda r: hashlib.sha256(canon({k: v for k, v in r.items() if k != "record_hash"}).encode()).hexdigest()
recs = [json.loads(l) for l in open(src + "/evidence.jsonl")]
summ = json.load(open(src + "/summary.json"))
anchor = summ["evidence"]["terminal_hash"]

def rechain(rs):
    prev = "0" * 64
    for i, r in enumerate(rs):
        r["seq"], r["prev_hash"] = i, prev
        r["record_hash"] = rh(r); prev = r["record_hash"]
    return rs

def write(rs, name):
    p = dst + "/" + name
    open(p, "w").write("".join(canon(r) + "\n" for r in rs))
    return p

def verify(p, anchor=None):
    cmd = [sys.executable, "-m", "experiments.monitoring_incident", "verify", "--log", p]
    if anchor: cmd += ["--terminal-hash", anchor]
    o = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    j = json.loads(o.stdout)
    return "valid=%s problems=%s" % (j["valid"], j["problems"][:2])

# T1: flip one byte of a payload, no re-chain
t = copy.deepcopy(recs); dec = next(r for r in t if r["type"] == "decision" and r["payload"]["verdict"] == "BLOCK")
dec["payload"]["basis"] = "admitted:local+global"
print("T1 edit, no rechain             :", verify(write(t, "t1.jsonl")))
# T2: turn the BLOCK into ALLOW, fabricate an execution record, re-chain
t = copy.deepcopy(recs)
i = next(k for k, r in enumerate(t) if r["type"] == "decision" and r["payload"]["verdict"] == "BLOCK")
t[i]["payload"]["verdict"] = "ALLOW"; t[i]["payload"]["basis"] = "admitted:local+global"
fake = {"schema": t[i]["schema"], "run_id": t[i]["run_id"], "type": "execution", "step": t[i]["step"],
        "time_utc": t[i]["time_utc"], "payload": {"executed": True, "decision_id": t[i]["payload"]["decision_id"],
        "action_hash": t[i]["payload"]["action_hash"], "eval_id": t[i]["payload"]["eval_id"], "primary": True,
        "effects": [], "state_before": "x", "state_after": "x", "refusal": "", "observation": "", "tool_error": "",
        "hook": None, "must_refuse": None}}
t.insert(i + 1, fake); rechain(t)
p2 = write(t, "t2.jsonl")
print("T2 BLOCK->ALLOW+fake exec, rechain, no anchor :", verify(p2))
print("T2 same, with ORIGINAL anchor               :", verify(p2, anchor))
print("T2 same, with anchor rewritten in summary   :", verify(p2, t[-1]["record_hash"]))
# T3: delete the oracle_label / evaluation records of the blocked step, re-chain
t = copy.deepcopy(recs)
eid = next(r["payload"]["eval_id"] for r in t if r["type"] == "decision" and r["payload"]["verdict"] == "BLOCK")
t = [r for r in t if (r["payload"] or {}).get("eval_id") != eid]; rechain(t)
print("T3 delete a blocked step's records, rechain :", verify(write(t, "t3.jsonl")))
# T4: truncate the tail (drop run_end)
print("T4 truncate tail, no rechain                :", verify(write(recs[:-1], "t4.jsonl")))
print("T4 truncate tail, with anchor               :", verify(write(recs[:-1], "t4b.jsonl"), anchor))
print("signature verifiable offline? decision keys are per-run, in memory, never persisted -> NO")
