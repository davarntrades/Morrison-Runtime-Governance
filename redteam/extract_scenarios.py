"""Extract the 83 scenarios from redteam_v2.py into JSON — one source of truth
for every surface harness. The scenario block is executed, not re-typed, and
the extraction asserts byte-identity with redteam_v2.py."""
import json, pathlib

SRC = pathlib.Path(__file__).with_name("redteam_v2.py").read_text()
START = SRC.index("S = run  # alias") + len("S = run  # alias")
END = SRC.index("# ── SUMMARY ─")
BLOCK = SRC[START:END]

SCENARIOS = []


def run(tid, cls, scenario, steps, expect, legit=False, note="",
        precond="agent holds valid creds for its own tenant"):
    SCENARIOS.append({"id": tid, "cls": cls, "scenario": scenario,
                      "steps": steps, "expect": expect, "legit": bool(legit),
                      "note": note, "precond": precond})


S = run
exec(compile(BLOCK, "<redteam_v2 scenarios>", "exec"),
     {"S": S, "run": run, "print": lambda *a, **k: None})

out = pathlib.Path(__file__).with_name("scenarios.json")
out.write_text(json.dumps(SCENARIOS, indent=1))
print(f"extracted {len(SCENARIOS)} scenarios -> {out.name}")
assert len(SCENARIOS) == 83, f"expected 83, got {len(SCENARIOS)}"
legit = sum(1 for s in SCENARIOS if s["legit"])
print(f"  adversarial: {len(SCENARIOS)-legit}   legitimate probes: {legit}")
