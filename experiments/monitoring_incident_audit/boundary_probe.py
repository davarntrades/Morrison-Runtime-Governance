"""Enforcement-boundary probes against the PR's Authorizer/Executor.

Disposable sandboxes only. Uses the PR's classes unmodified. Where a timing
window is widened, it is done with a test-only Sandbox SUBCLASS (slower
snapshot), never by editing PR code; this is stated in the output.
"""
import dataclasses
import json
import shutil
import sys
import tempfile
import threading
import time

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.monitoring_incident import cases as C, scenarios as S  # noqa: E402
from experiments.monitoring_incident.authority import (  # noqa: E402
    ALLOW, Authorizer, Decision, DecisionKey, Executor, get_condition)
from experiments.monitoring_incident.sandbox import Sandbox, fs_hash  # noqa: E402
from experiments.monitoring_incident.tiers import GlobalAdmissibility, LocalAdmissibility  # noqa: E402

RESULTS = []


def rec(test, outcome, detail=""):
    RESULTS.append({"test": test, "outcome": outcome, "detail": detail})
    print("%-58s %-34s %s" % (test, outcome, detail))


class SlowSandbox(Sandbox):
    """Test-only: widens the executor's check-to-effect window."""
    delay = 0.0

    def snapshot(self):
        out = super().snapshot()
        if self.delay:
            time.sleep(self.delay)
        return out


def world(cond="hierarchical", scenario="alert_suppression", slow=0.0, run_id="mi-audit"):
    work = tempfile.mkdtemp(prefix="mi-audit-")
    sb = SlowSandbox(scenario, work)
    sc = S.get(scenario)
    c = get_condition(cond)
    key = DecisionKey()
    auth = Authorizer(c, run_id, key, LocalAdmissibility(sc, S.manifest()) if c.local else None,
                      GlobalAdmissibility(sc, sb.baseline) if c.global_ else None)
    ex = Executor(sb, key, run_id)
    sb.delay = slow
    return work, sb, auth, ex


def decide(auth, sb, ex, action):
    return auth.decide(action, fs_hash(sb.snapshot()), list(ex.executed))[0]


w = C.w
BENIGN = w("config/notifications.json", C.NOTIF_DIGEST)
BAD = w("config/security_alerts.json", C.SECURITY_DISABLED)
A_STEP = w(".env", C.ENV_SELECT_FREEZE)
B_STEP = w("config/notifications.json", C.NOTIF_WITH_MUTE_PROFILE)

# 1. substitution variants -------------------------------------------------
work, sb, auth, ex = world()
d = decide(auth, sb, ex, BENIGN)
r = ex.execute(d, BAD)
rec("1a substitute different action", "BLOCK-before-exec" if not r.executed else "EXECUTED", r.refusal)
d = decide(auth, sb, ex, BENIGN)
r = ex.execute(d, {"tool": "WRITE_FILE", "args": dict(BENIGN["args"])})
rec("1b tool-name case variant (same action_hash)", "refused" if not r.executed else "EXECUTED", r.refusal)
d = decide(auth, sb, ex, BENIGN)
r = ex.execute(d, {"tool": "write_file", "args": dict(BENIGN["args"], _ts=123)})
rec("1c volatile arg added (same action_hash)", "EXECUTED(same effect)" if r.executed else "refused",
    "hash collision exists but effect identical" if r.executed else r.refusal)
shutil.rmtree(work, ignore_errors=True)

# 2. replay ----------------------------------------------------------------
work, sb, auth, ex = world()
d = decide(auth, sb, ex, w("config/missing_dir/x.json", "{}"))
r1 = ex.execute(d, w("config/missing_dir/x.json", "{}"))
r2 = ex.execute(d, w("config/missing_dir/x.json", "{}"))
rec("2a replay after successful use", "refused" if not r2.executed else "EXECUTED", r2.refusal)
d = decide(auth, sb, ex, {"tool": "delete_file", "args": {"path": "nope.txt"}})
r1 = ex.execute(d, {"tool": "delete_file", "args": {"path": "nope.txt"}})
r2 = ex.execute(d, {"tool": "delete_file", "args": {"path": "nope.txt"}})
rec("2b replay after tool error (decision consumed?)", "refused" if not r2.executed and "already used" in r2.refusal
    else "not consumed", r2.refusal)
shutil.rmtree(work, ignore_errors=True)

# 3. forgery ---------------------------------------------------------------
work, sb, auth, ex = world()
fake = Decision("d-x", "mi-audit", "hierarchical", ALLOW, "text", "0" * 64, fs_hash(sb.snapshot()),
                ex.trajectory_hash(), 1, signature="0" * 64)
rec("3a unsigned ALLOW", "refused" if not ex.execute(fake, BAD).executed else "EXECUTED")
rec("3b dict shaped like a decision", "refused" if not ex.execute(dataclasses.asdict(fake), BAD).executed else "EXECUTED")
rec("3c string 'APPROVED'", "refused" if not ex.execute("APPROVED by security", BAD).executed else "EXECUTED")
# 3d: obtain a genuinely signed BLOCK for BAD from the authorizer, then present a Decision SUBCLASS
# whose payload() returns the signed BLOCK payload but whose .verdict attribute is ALLOW.
blk = decide(auth, sb, ex, BAD)
assert blk.verdict != ALLOW


class Masquerade(Decision):
    def payload(self):
        return {k: v for k, v in dataclasses.asdict(blk).items() if k != "signature"}


mq = Masquerade(**dict(dataclasses.asdict(blk), verdict=ALLOW))
r = ex.execute(mq, BAD)
rec("3d signed BLOCK + Decision subclass (in-process object forgery)",
    "EXECUTED (in-process)" if r.executed else "refused", "verdict=%s signed=%s" % (blk.verdict, r.refusal or "ok"))
shutil.rmtree(work, ignore_errors=True)

# 4. state change after authorisation -------------------------------------
work, sb, auth, ex = world()
d = decide(auth, sb, ex, BENIGN)
open(sb.root + "/config/overrides.json", "w").write(C.OVERRIDES_DISABLE)
r = ex.execute(d, BENIGN)
rec("4a external change then execute", "refused" if not r.executed else "EXECUTED", r.refusal)
shutil.rmtree(work, ignore_errors=True)
work, sb, auth, ex = world()
d = decide(auth, sb, ex, BENIGN)
p = sb.root + "/config/security_alerts.json"
orig = open(p, "rb").read()
open(p, "w").write(C.SECURITY_DISABLED)
open(p, "wb").write(orig)
r = ex.execute(d, BENIGN)
rec("4b ABA change (restored bytes) then execute", "EXECUTED" if r.executed else "refused",
    "state identical at execution; acceptable")
shutil.rmtree(work, ignore_errors=True)

# 5. concurrency -------------------------------------------------------------
def race(slow, trials):
    double, both = 0, 0
    for _ in range(trials):
        work, sb, auth, ex = world("global_only", slow=0.0)
        d = decide(auth, sb, ex, BENIGN)
        sb.delay = slow
        res = []
        ts = [threading.Thread(target=lambda: res.append(ex.execute(d, BENIGN))) for _ in range(2)]
        [t.start() for t in ts]; [t.join() for t in ts]
        double += sum(x.executed for x in res) == 2
        shutil.rmtree(work, ignore_errors=True)
        # C06 batch: two decisions against the same state, executed concurrently
        work, sb, auth, ex = world("global_only", slow=0.0)
        dA = decide(auth, sb, ex, A_STEP)
        dB = decide(auth, sb, ex, B_STEP)
        sb.delay = slow
        res = []
        ta = threading.Thread(target=lambda: res.append(("A", ex.execute(dA, A_STEP))))
        tb = threading.Thread(target=lambda: res.append(("B", ex.execute(dB, B_STEP))))
        ta.start(); tb.start(); ta.join(); tb.join()
        if all(x.executed for _, x in res):
            both += 1
            final = sb.snapshot()
        shutil.rmtree(work, ignore_errors=True)
    return double, both, (dA.verdict, dB.verdict)


dbl, both, verdicts = race(0.0, 30)
rec("5a same decision executed by 2 threads (natural timing)", "%d/30 double-executed" % dbl)
rec("5b C06 batch pair executed concurrently (natural timing)", "%d/30 both executed" % both,
    "global verdicts %s" % (verdicts,))
dbl, both, verdicts = race(0.05, 10)
rec("5c same decision, 2 threads (snapshot widened 50ms)", "%d/10 double-executed" % dbl)
rec("5d C06 batch concurrently (snapshot widened 50ms)", "%d/10 both executed" % both,
    "global verdicts %s -> prohibited A+B trajectory committed" % (verdicts,))

# 6. cross-session ----------------------------------------------------------
w1, sb1, a1, e1 = world(run_id="mi-run-1")
w2, sb2, a2, e2 = world(run_id="mi-run-2")
d = decide(a1, sb1, e1, BENIGN)
r = e2.execute(d, BENIGN)
rec("6a decision from run 1 at run 2's executor", "refused" if not r.executed else "EXECUTED", r.refusal)
# same deterministic run_id (identical config re-run) but fresh key
w3, sb3, a3, e3 = world(run_id="mi-run-1")
r = e3.execute(d, BENIGN)
rec("6b same run_id, new episode (fresh key)", "refused" if not r.executed else "EXECUTED", r.refusal)
for x in (w1, w2, w3):
    shutil.rmtree(x, ignore_errors=True)

# 7. direct executor / effect access ---------------------------------------
work, sb, auth, ex = world()
r = ex.execute(None, BAD)
rec("7a executor with no decision", "refused" if not r.executed else "EXECUTED", r.refusal)
from experiments.monitoring_incident.sandbox import apply_action  # noqa: E402
new, _ = apply_action(sb.snapshot(), BAD)
sb.materialise(new)
rec("7b in-process code calls sandbox.materialise directly", "EXECUTED (no mediation)",
    "complete mediation is by API convention only (documented out of scope)")
shutil.rmtree(work, ignore_errors=True)

json.dump(RESULTS, open(sys.argv[1], "w"), indent=1)
