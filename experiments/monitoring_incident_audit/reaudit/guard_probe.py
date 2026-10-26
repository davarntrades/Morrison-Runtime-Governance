"""Final verification: adversarial tests of SessionExecutionGuard (PR #42 e370b3f).

Disposable sandboxes only; PR classes unmodified. A test-only Sandbox SUBCLASS
widens the check-to-effect window where stated (slower snapshot); nothing in
experiments/monitoring_incident/ is edited.
Usage: python guard_probe.py [OUT_JSON]
"""
import json
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from experiments.monitoring_incident import cases as C  # noqa: E402
from experiments.monitoring_incident import scenarios as S  # noqa: E402
from experiments.monitoring_incident.authority import (  # noqa: E402
    Authorizer, DecisionKey, Executor, OverlappingExecutionError, SessionExecutionGuard,
    get_condition)
from experiments.monitoring_incident.harness import Episode, RunConfig  # noqa: E402
from experiments.monitoring_incident.oracle import Oracle  # noqa: E402
from experiments.monitoring_incident.proposers import ScriptedProposer  # noqa: E402
from experiments.monitoring_incident.sandbox import Sandbox, fs_hash  # noqa: E402
from experiments.monitoring_incident.tiers import GlobalAdmissibility  # noqa: E402

RESULTS = []
A_STEP = C.w(".env", C.ENV_SELECT_FREEZE)
B_STEP = C.w("config/notifications.json", C.NOTIF_WITH_MUTE_PROFILE)
BENIGN = C.w("config/notifications.json", C.NOTIF_DIGEST)


def rec(test, outcome, detail=""):
    RESULTS.append({"test": test, "outcome": outcome, "detail": detail})
    print("%-62s %-30s %s" % (test, outcome, detail))


class SlowSandbox(Sandbox):
    delay = 0.0

    def scan(self):
        out = super().scan()
        if self.delay:
            time.sleep(self.delay)
        return out


def world(cond="global_only", guard=True):
    work = tempfile.mkdtemp(prefix="mi-guard-")
    sb = SlowSandbox("alert_suppression", work)
    sc, c, key = S.get("alert_suppression"), get_condition(cond), DecisionKey()
    g = SessionExecutionGuard() if guard else None
    auth = Authorizer(c, "mi-g", key, None, GlobalAdmissibility(sc, sb.baseline) if c.global_ else None)
    return work, sb, auth, Executor(sb, key, "mi-g", guard=g), g


def decide(auth, sb, ex, action):
    return auth.decide(action, fs_hash(sb.snapshot()), list(ex.executed))[0]


def intact(sb, work):
    files, irr = sb.scan()
    return Oracle(S.get("alert_suppression"), sb.baseline, work).evaluate(
        files, include_task=False, irregular=irr)["monitoring_intact"]


# 1. Direct executor call, no open transaction ------------------------------------
work, sb, auth, ex, g = world()
d = decide(auth, sb, ex, BENIGN)
r = ex.execute(d, BENIGN)
rec("1 direct execute(), guard present, no transaction", "refused" if not r.executed else "EXECUTED",
    r.refusal)
with g.transaction("t"):
    r = ex.execute(d, BENIGN)
rec("1b same decision inside a transaction", "executed" if r.executed else "refused", r.refusal)
shutil.rmtree(work, ignore_errors=True)

# 2. Nested transaction, same thread; recovery afterwards --------------------------
work, sb, auth, ex, g = world()
try:
    with g.transaction("outer"):
        with g.transaction("inner"):
            pass
    rec("2 nested transaction (same thread)", "NOT rejected")
except OverlappingExecutionError:
    rec("2 nested transaction (same thread)", "rejected", "active after unwind=%s" % g.active())
try:
    with g.transaction("boom"):
        raise ValueError("simulated failure mid-step")
except ValueError:
    pass
with g.transaction("after-error"):
    ok = g.active()
rec("2b error inside transaction, then new transaction", "recovered" if ok and not g.active() else "STUCK")
shutil.rmtree(work, ignore_errors=True)

# 3. Authorization outside any transaction ----------------------------------------
work, sb, auth, ex, g = world()
dA, dB = decide(auth, sb, ex, A_STEP), decide(auth, sb, ex, B_STEP)
with g.transaction("a"):
    ra = ex.execute(dA, A_STEP)
with g.transaction("b"):
    rb = ex.execute(dB, B_STEP)
rec("3 decide() outside a transaction (both minted vs same state)",
    "decide not guarded; B %s" % ("refused" if not rb.executed else "EXECUTED"),
    rb.refusal or "")
shutil.rmtree(work, ignore_errors=True)


# 4. Two threads each opening their own transaction (the contract) -----------------
def two_txn_threads(delay):
    work, sb, auth, ex, g = world()
    dA, dB = decide(auth, sb, ex, A_STEP), decide(auth, sb, ex, B_STEP)
    sb.delay = delay
    res, barrier = {}, threading.Barrier(2)

    def run(name, d, a):
        barrier.wait()
        try:
            with g.transaction(name):
                res[name] = ex.execute(d, a).executed
        except OverlappingExecutionError:
            res[name] = "rejected"
    ts = [threading.Thread(target=run, args=("A", dA, A_STEP)),
          threading.Thread(target=run, args=("B", dB, B_STEP))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    out = (res["A"], res["B"], intact(sb, work))
    shutil.rmtree(work, ignore_errors=True)
    return out


tally = {}
for _ in range(20):
    k = two_txn_threads(0.05)
    tally[str(k)] = tally.get(str(k), 0) + 1
rec("4 two threads, each with own transaction (20 trials, 50ms)", "(A, B, monitoring_intact)", tally)


# 5. Ownership: thread A holds a transaction; thread B calls execute() with none ---
def ownership(delay):
    work, sb, auth, ex, g = world()
    dA, dB = decide(auth, sb, ex, A_STEP), decide(auth, sb, ex, B_STEP)
    sb.delay = delay
    res, opened = {}, threading.Event()

    def holder():
        with g.transaction("A"):
            opened.set()
            res["A"] = ex.execute(dA, A_STEP).executed

    def intruder():
        opened.wait()
        res["B"] = ex.execute(dB, B_STEP).executed      # no transaction of its own
    ts = [threading.Thread(target=holder), threading.Thread(target=intruder)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    out = (res["A"], res["B"], intact(sb, work), len(g.rejections))
    shutil.rmtree(work, ignore_errors=True)
    return out


tally = {}
for _ in range(20):
    k = ownership(0.05)
    tally[str(k)] = tally.get(str(k), 0) + 1
rec("5 B calls execute() inside A's open transaction (20 trials)",
    "(A, B, monitoring_intact, rejections)", tally)

# 6. Executor built without a guard (the class default) ----------------------------
work, sb, auth, ex, g = world(guard=False)
d = decide(auth, sb, ex, BENIGN)
r = ex.execute(d, BENIGN)
rec("6 Executor(guard=None) direct call", "EXECUTED (unguarded)" if r.executed else "refused",
    "guard is opt-in; only the harness passes one")
shutil.rmtree(work, ignore_errors=True)


# 7. The actual runner: two threads driving one Episode's _guarded_step -------------
def runner_overlap(delay):
    out_dir = tempfile.mkdtemp(prefix="mi-guard-ep-")
    ep = Episode(RunConfig(scenario="alert_suppression", condition="global_only",
                           output_dir=Path(out_dir), case_id="guard-probe"),
                 ScriptedProposer("guard-probe", []))
    ep.run_dir.mkdir(parents=True)
    ep._setup()
    ep.sandbox.__class__ = SlowSandbox
    ep.sandbox.delay = delay
    obs, barrier = {}, threading.Barrier(2)

    def run(name, call):
        barrier.wait()
        obs[name] = ep._guarded_step(call)
    ts = [threading.Thread(target=run, args=("A", dict(A_STEP))),
          threading.Thread(target=run, args=("B", dict(B_STEP)))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    rejected = sum(1 for v in obs.values() if v.startswith("REJECTED"))
    recs = [r["type"] for r in ep.log.records]
    res = (rejected, recs.count("concurrency_rejected"), len(ep.executor.executed))
    ep.sandbox.cleanup()
    shutil.rmtree(ep.base, ignore_errors=True)
    shutil.rmtree(out_dir, ignore_errors=True)
    return res


tally = {}
for _ in range(10):
    k = runner_overlap(0.05)
    tally[str(k)] = tally.get(str(k), 0) + 1
rec("7 two threads into Episode._guarded_step (10 trials)",
    "(rejected, concurrency_rejected recs, executed)", tally)

if len(sys.argv) > 1:
    json.dump(RESULTS, open(sys.argv[1], "w", encoding="utf-8"), indent=1)
