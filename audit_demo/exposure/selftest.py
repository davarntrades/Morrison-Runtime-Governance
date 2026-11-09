"""Self-tests of the audit: try to make the verifier accept a wrong result.

    python -m audit_demo.exposure.selftest --assessment DIR --reports DIR --json PATH

Each mutation tampers with the evidence or the report text in one specific way
and states which check must catch it. A mutation that is NOT caught is a weakness
in the audit itself; it is reported as ESCAPED, never hidden.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

from audit_demo.exposure import verify as V


def _find(ev, sid):
    return next(r for r in ev["scenarios"] if r["id"] == sid)


def mutations(ev, cites_t, text_t):
    """Yield (id, description, expected_catcher, callable returning problems)."""
    def m1():
        e = copy.deepcopy(ev)
        _find(e, "L3")["arms"]["customer"]["outcome"] = "HELD"
        return V.check_outcomes(e)
    yield "M1", "Relabel a failed customer result (L3) as held", "outcomes", m1

    def m2():
        e = copy.deepcopy(ev)
        r = _find(e, "G2")["arms"]["customer"]
        r["outcome"] = "HELD"
        r["final_state"]["payouts_today"] = 21_000
        last = r["steps"][-1]
        last["state_after"] = copy.deepcopy(last["state_before"])
        last["state_changed"] = []
        return V.check_outcomes(e) + V.check_execution(e, []) + V.check_final_state(e) + V.check_digest(e)
    yield "M2", "Consistent forgery: G2 outcome, final state and last step all edited to 'held'", \
        "final-state / step consistency", m2

    def m3():
        c = copy.deepcopy(cites_t)
        c["numbers"][0]["value"] = str(int(c["numbers"][0]["value"]) + 1)
        return V.check_numbers(c, V.values(ev))
    yield "M3", "Change a printed figure in the technical report", "numbers", m3

    def m4():
        c = copy.deepcopy(cites_t)
        c["evidence_ids"].append("EV-L99-CU-1")
        return V.check_ids(c, ev, text_t)
    yield "M4", "Cite an evidence ID that does not exist", "evidence IDs", m4

    def m5():
        e = copy.deepcopy(ev)
        s = next(s for s in _find(e, "L2")["arms"]["morrison"]["steps"] if s["verdict"] == "BLOCK")
        s["executed"] = True
        return V.check_enforcement(e)
    yield "M5", "Mark a refused Morrison action as executed", "enforcement", m5

    def m6():
        e = copy.deepcopy(ev)
        _find(e, "L14")["arms"]["customer"]["outcome"] = "HELD"
        return V.check_outcomes(e)
    yield "M6", "Turn the inconclusive result (L14) into 'held'", "outcomes", m6

    def m7():
        e = copy.deepcopy(ev)
        _find(e, "L13")["arms"]["customer"]["outcome"] = "FAILED"
        return V.check_outcomes(e)
    yield "M7", "Hide that a control misreported (L13 FAILED_MISREPORTED to FAILED)", "outcomes", m7

    def m8():
        end = text_t.find("Comparison: an explicitly configured")
        reg_start = text_t.rfind("Residual exposure register", 0, end)
        t = text_t[:reg_start] + text_t[reg_start:].replace("G5", "G?", 1)
        return V.check_coverage(ev, t)
    yield "M8", "Drop a failed scenario (G5) from the residual register", "coverage", m8

    def m9():
        t = text_t.replace("Hold payments to payees", "Deploy Morrison and hold payments to payees", 1)
        return V.check_independence(t, "technical")
    yield "M9", "Recommend the auditor's own product in the register", "independence", m9

    def m10():
        return V.check_presentation([text_t + " This system is production-ready."])
    yield "M10", "Add a production-readiness claim", "presentation", m10

    def m11():
        e = copy.deepcopy(ev)
        _find(e, "G6")["arms"]["customer"]["steps"][0]["verdict_note"] = "x"
        _find(e, "G6")["arms"]["customer"]["final_state"]["records_exported_today"] = 4_000
        _find(e, "G6")["arms"]["customer"]["outcome"] = "HELD"
        return V.check_digest(e)
    yield "M11", "Edit evidence without recomputing the assessment digest", "digest", m11


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m audit_demo.exposure.selftest")
    p.add_argument("--assessment", type=Path, required=True)
    p.add_argument("--reports", type=Path, required=True)
    p.add_argument("--json", type=Path)
    a = p.parse_args(argv)
    ev = json.loads((a.assessment / "evidence.json").read_text())
    tech = next(a.reports.glob("*Technical*.pdf"))
    cites_t = json.loads(tech.with_suffix(".citations.json").read_text())
    text_t = "\n".join(V.pdf_pages(tech))
    baseline = {"outcomes": V.check_outcomes(ev), "execution": V.check_execution(ev, []),
                "final_state": V.check_final_state(ev), "digest": V.check_digest(ev)}
    baseline_problems = {x for v in baseline.values() for x in v}
    baseline_problems |= set(V.check_numbers(cites_t, V.values(ev))) | set(V.check_ids(cites_t, ev, text_t))
    baseline_problems |= set(V.check_coverage(ev, text_t)) | set(V.check_independence(text_t, "technical"))
    baseline_problems |= set(V.check_presentation([text_t]))
    rows = []
    for mid, desc, catcher, fn in mutations(ev, cites_t, text_t):
        try:
            problems = fn()
        except Exception as exc:             # a crash is not a detection
            problems, err = [], f"{type(exc).__name__}: {exc}"
        else:
            err = ""
        # Caught only if the mutation introduced a problem the clean evidence does not have.
        new = [x for x in problems if x not in baseline_problems]
        caught = bool(new)
        problems = new
        rows.append({"id": mid, "mutation": desc, "expected_catcher": catcher,
                     "result": "CAUGHT" if caught else "ESCAPED",
                     "evidence": "; ".join(problems)[:300] or err})
        print(f"{'CAUGHT ' if caught else 'ESCAPED'} {mid} {desc}")
    before = hashlib.sha256((a.assessment / "evidence.json").read_bytes()).hexdigest()
    out = {"baseline_clean": all(not v for v in baseline.values()), "mutations": rows,
           "caught": sum(r["result"] == "CAUGHT" for r in rows), "total": len(rows),
           "evidence_unchanged_by_selftest": before == hashlib.sha256(
               (a.assessment / "evidence.json").read_bytes()).hexdigest()}
    print(f"{out['caught']} of {out['total']} mutations caught; baseline clean: {out['baseline_clean']}")
    if a.json:
        a.json.write_text(json.dumps(out, indent=2))
    return 0 if out["caught"] == out["total"] and out["baseline_clean"] else 1


if __name__ == "__main__":
    sys.exit(main())
