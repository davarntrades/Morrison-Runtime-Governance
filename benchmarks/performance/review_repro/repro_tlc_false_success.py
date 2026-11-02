"""Reproduce: run_tlc accepts errored TLC processes (pre-repair)."""
import json, shutil, sys
from pathlib import Path
from morrison_governance.global_verification.tla_export import run_tlc
src, jar, work = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
out = {}
def fresh(name):
    d = work / name
    if d.exists(): shutil.rmtree(d)
    shutil.copytree(src, d); return d
# 1. governed_safety.cfg names an invariant that does not exist -> TLC error
d = fresh("bad-invariant")
(d / "governed_safety.cfg").write_text((d / "governed_safety.cfg").read_text().replace("INVARIANT Safe", "INVARIANT NoSuchOperator"))
r = run_tlc(d, jar); out["bad_invariant"] = {"agree": r["agree"], "governed_safety": {k: r["tlc"]["governed_safety"][k] for k in ("exit_code","violated","distinct_states")}, "check": r["checks"]["governed_unsafe_reachable"]}
# 2. java binary that exits nonzero with no output (checker crash)
d = fresh("crash")
fake = work / "fakejava.sh"; fake.write_text("#!/bin/sh\necho 'Exception in thread main java.lang.OutOfMemoryError' >&2\nexit 1\n"); fake.chmod(0o755)
r = run_tlc(d, jar, java=str(fake)); out["crash"] = {"agree": r["agree"], "checks": r["checks"]}
# 3. syntax error in the spec
d = fresh("parse-error")
p = d / "EnterprisePipeline.tla"; p.write_text(p.read_text().replace("Safe == ~Unsafe", "Safe == ~Unsafe /\\"))
r = run_tlc(d, jar); out["parse_error"] = {"agree": r["agree"], "checks": r["checks"]}
print(json.dumps(out, indent=1))
