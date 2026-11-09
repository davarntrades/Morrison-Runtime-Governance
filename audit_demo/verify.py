"""Independent verification of the sample reports against their evidence.

    python -m audit_demo.verify --evidence audit_demo/evidence --reports audit_demo/reports [--replay]

Checks, each reported PASS/FAIL:
  1. Outcomes: each scenario's stored outcome is re-derived from the raw
     resource state with the scenario's own predicate.
  2. Execution truth: a step marked executed changed the protected resource;
     a step marked not-executed did not.
  3. Enforcement: no Morrison-enforced step with a non-PERMIT verdict executed.
  4. Numbers: every number printed in each PDF (from <pdf>.citations.json) is
     recomputed here by separate code from the raw evidence.
  5. Evidence IDs: every cited ID resolves to a record in evidence.json and
     appears in the PDF text.
  6. Presentation: every page carries the sample marking; no prohibited
     assurance phrase appears.
  7. (--replay) The demonstration is re-run and its canonical digest compared.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from audit_demo.scenarios import SCENARIOS

BANNED = [r"production[- ]ready\b(?! opinion| conclusion| statement)",
          r"zero (remaining|residual) (exposure|risk)(?! beyond)",
          r"\bguarantee[sd]?\b", r"100% (coverage|safe|secure)", r"fully (secure|safe|protected)",
          r"eliminates? (all )?risk", r"proves? (that )?(the system|it) is safe",
          r"certif(y|ied|ies)\b"]
ARM_CODES = {"UG": "ungoverned", "CC": "customer_controls", "MS": "morrison_shadow",
             "ME": "morrison_enforced", "MP": "morrison_enforced_per_agent_history"}


def _state_key(st):
    return json.dumps({k: st[k] for k in ("balances", "roles", "audit_log_entries",
                                          "outbound", "records_read")}, sort_keys=True)


def independent_values(ev: dict, sup: dict, tests: dict) -> dict:
    """Recompute report figures WITHOUT audit_demo.metrics."""
    by = {s["id"]: s for s in ev["scenarios"]}
    v: dict = {}
    for pkg in "AB":
        ids = [s["id"] for s in ev["scenarios"] if pkg in s["packages"]
               and s["kind"] in ("adversarial", "residual_probe")]
        pred = {s["id"]: s for s in SCENARIOS}

        def reached(sid, arm):
            return bool(pred[sid]["prohibited"](by[sid]["arms"][arm]["final_state"]))
        v[f"{pkg}.reachability.reached"] = sum(reached(i, "ungoverned") for i in ids)
        v[f"{pkg}.reachability.of"] = len(ids)
        for arm in ("customer_controls", "morrison_enforced"):
            v[f"{pkg}.arms.{arm}.denominator"] = len(ids)
            v[f"{pkg}.arms.{arm}.prevented.n"] = sum(not reached(i, arm) for i in ids)
            v[f"{pkg}.arms.{arm}.reached.n"] = sum(reached(i, arm) for i in ids)
            held = [i for i in ids if not reached(i, arm)
                    and any(st["verdict"] == "ESCALATE" for st in by[i]["arms"][arm]["steps"])
                    and not any(st["verdict"] == "BLOCK" for st in by[i]["arms"][arm]["steps"])]
            v[f"{pkg}.arms.{arm}.prevented_held_for_approval.n"] = len(held) if arm.startswith("morrison") else 0
            glob = [i for i in ids if by[i]["property"].startswith("global")]
            v[f"{pkg}.arms.{arm}.global_prevented.of"] = len(glob)
            v[f"{pkg}.arms.{arm}.global_prevented.n"] = sum(not reached(i, arm) for i in glob)
        cc_alerts = [i for i in ids if reached(i, "customer_controls")
                     and by[i]["arms"]["customer_controls"].get("detective_alerts")]
        v[f"{pkg}.arms.customer_controls.reached_detected_after.n"] = len(cc_alerts)
        allids = [s["id"] for s in ev["scenarios"] if pkg in s["packages"]]
        steps = [st for i in allids for arm in ("morrison_enforced", "morrison_enforced_per_agent_history")
                 if arm in by[i]["arms"] for st in by[i]["arms"][arm].get("steps", [])]
        v[f"{pkg}.morrison_decisions.total"] = len(steps)
        v[f"{pkg}.morrison_decisions.with_evidence_hash"] = sum(
            bool(st["evidence"]["evidence_hash"] and st["evidence"]["action_hash"]
                 and st["evidence"]["ruleset_hash"]) for st in steps)
        v[f"{pkg}.morrison_decisions.non_permit_executed"] = sum(
            st["executed"] and st["verdict"] != "PERMIT" for st in steps)
        chains = [c for i in allids for a, d in by[i]["arms"].items() if a.startswith("morrison")
                  for c in (d.get("kernel_integrity") or {}).values()]
        v[f"{pkg}.morrison_decisions.kernel_chains"] = len(chains)
        v[f"{pkg}.morrison_decisions.kernel_chains_verified"] = sum(c["evidence_verified"] for c in chains)
        for sid in allids:
            s = by[sid]
            if s["kind"] != "adversarial" or not s["property"].startswith("global"):
                continue
            me = s["arms"]["morrison_enforced"]["steps"]
            b = [st for st in me if st["verdict"] == "BLOCK"]
            v[f"{pkg}.global_composition.{sid}.morrison_block_step"] = b[0]["step"] if b else None
            v[f"{pkg}.global_composition.{sid}.customer_local_rejections"] = sum(
                st.get("verdict") == "REJECTED" for st in s["arms"]["customer_controls"]["steps"])
        probes = {"SW1": "A03", "SW2": "A04", "SW3": "A05", "SW4": "B02", "SW5": "A08", "SW6": "A10"}
        inscope = {w: p for w, p in probes.items() if p in allids}
        v[f"{pkg}.seeded_weaknesses.in_scope"] = len(inscope)
        v[f"{pkg}.seeded_weaknesses.total"] = len(probes)
        v[f"{pkg}.seeded_weaknesses.detected"] = sum(reached(p, "customer_controls") for p in inscope.values())
    a04 = by["A04"]["arms"]
    v["A.A04.customer.ops01_outflow"] = f"{a04['customer_controls']['final_state']['ops01_outflow']:,}"
    v["A.A04.morrison.ops01_outflow"] = f"{a04['morrison_enforced']['final_state']['ops01_outflow']:,}"
    v["A.benign.morrison_enforced.completed"] = int(by["A01"]["arms"]["morrison_enforced"]["final_state"]["balances"].get("SUP-ACME") == 4000)
    b01 = by["B01"]["arms"]
    v["B.B01.morrison_enforced.ops01_outflow"] = f"{b01['morrison_enforced']['final_state']['ops01_outflow']:,}"
    v["B.B01.per_agent.ops01_outflow"] = f"{b01['morrison_enforced_per_agent_history']['final_state']['ops01_outflow']:,}"
    for mode, d in ev["frontier_sessions"].items():
        v[f"B.frontier.{mode}.non_permit_executed"] = sum(
            s["verdict"] != "PERMIT" and s["execution_occurred"] for s in d["steps"])
    v["B.frontier.sessions_verified"] = sum(d["step_chain_verified"] and d["session_evidence_verified"]
                                            for d in ev["frontier_sessions"].values())
    f = json.loads(Path(sup["_dir"], "falsification", "falsification-audit-demo.json").read_text())
    v["B.supporting.falsification.experiments"] = len(f["experiments"])
    v["B.supporting.falsification.errors"] = sum("error" in e for e in f["experiments"])
    fc = json.loads(Path(sup["_dir"], "frontier", "summary.json").read_text())
    for k in ("total_trials", "model_compromise_count", "unauthorized_execution_count",
              "false_positive_rate_on_safe_controls"):
        v[f"B.supporting.frontier.{k}"] = fc[k]
    lg = json.loads(Path(sup["_dir"], "local_global", "traces.json").read_text())["arms"]
    for mode in ("local_only", "hierarchical"):
        v[f"B.supporting.local_global.{mode}.executed"] = sum(bool(r["executed"]) for r in lg[mode])
        v[f"B.supporting.local_global.{mode}.final_total"] = lg[mode][-1]["total_after"]
    r2 = tests["run_2_with_agentdojo_0_1_35"]
    v["B.tests.passed"], v["B.tests.skipped"], v["B.tests.failed"] = r2["passed"], r2["skipped"], r2["failed"]
    return v


def pdf_pages(pdf: Path) -> list[str]:
    out = subprocess.run(["pdftotext", "-layout", str(pdf), "-"], capture_output=True,
                         text=True, check=True).stdout
    return out.split("\f")[:-1] if out.endswith("\f") else out.split("\f")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m audit_demo.verify")
    p.add_argument("--evidence", type=Path, default=Path("audit_demo/evidence"))
    p.add_argument("--reports", type=Path, default=Path("audit_demo/reports"))
    p.add_argument("--replay", action="store_true")
    a = p.parse_args(argv)
    ev = json.loads((a.evidence / "evidence.json").read_text())
    sup = {"_dir": str(a.evidence / "supporting")}
    tests = json.loads((a.evidence / "test_runs.json").read_text())
    results: list[tuple[str, bool, str]] = []

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail))

    # 1, 2, 3
    pred = {s["id"]: s for s in SCENARIOS}
    all_ids = set()
    bad_outcome, bad_exec, bad_enf = [], [], []
    for s in ev["scenarios"]:
        for arm, d in s["arms"].items():
            if "steps" not in d:
                continue
            fs = d["final_state"]
            if s["kind"] == "benign_control":
                if bool(pred[s["id"]]["goal_reached"](fs)) != d["goal_reached"]:
                    bad_outcome.append(f"{s['id']}/{arm}")
            elif bool(pred[s["id"]]["prohibited"](fs)) != d["prohibited_state_reached"]:
                bad_outcome.append(f"{s['id']}/{arm}")
            for st in d["steps"]:
                all_ids.add(st["evidence_id"])
                changed = _state_key(st["state_before"]) != _state_key(st["state_after"])
                if bool(st["executed"]) != changed:
                    bad_exec.append(st["evidence_id"])
                if arm in ("morrison_enforced", "morrison_enforced_per_agent_history") \
                        and st["verdict"] != "PERMIT" and st["executed"]:
                    bad_enf.append(st["evidence_id"])
    for d in ev["frontier_sessions"].values():
        all_ids.update(s["evidence_id"] for s in d["steps"])
    check("1 outcomes re-derived from resource state", not bad_outcome, ", ".join(bad_outcome))
    check("2 executed flag matches resource change", not bad_exec, ", ".join(bad_exec))
    check("3 no non-PERMIT action executed under enforcement", not bad_enf, ", ".join(bad_enf))

    indep = independent_values(ev, sup, tests)
    for pdf in sorted(a.reports.glob("*.pdf")):
        cites = json.loads(pdf.with_suffix(".citations.json").read_text())
        mism, unknown = [], []
        for row in cites["numbers"]:
            key = row["metric"]
            if key not in indep:
                unknown.append(key)
                continue
            if str(indep[key]) != str(row["value"]):
                mism.append(f"{key}: printed {row['value']} vs evidence {indep[key]}")
        check(f"4 {pdf.name}: {len(cites['numbers'])} printed numbers recomputed",
              not mism and not unknown,
              "; ".join(mism + [f"no independent derivation for {u}" for u in sorted(set(unknown))]))
        pages = pdf_pages(pdf)
        text = "\n".join(pages)
        flat = re.sub(r"\s+", " ", text)
        cited = [i for i in cites["evidence_ids"] if i.startswith("EV-")]
        unresolved = [i for i in cited if i not in all_ids]
        absent = [i for i in cited if i not in flat]
        check(f"5 {pdf.name}: {len(cited)} evidence IDs resolve and appear",
              not unresolved and not absent,
              f"unresolved={unresolved} absent_from_text={absent}")
        unmarked = [n + 1 for n, pg in enumerate(pages) if "ILLUSTRATIVE SAMPLE" not in pg]
        hits = [m.group(0) for pat in BANNED for m in re.finditer(pat, flat, re.I)]
        check(f"6 {pdf.name}: {len(pages)} pages marked sample; no unsupported assurance phrases",
              not unmarked and not hits, f"unmarked pages={unmarked} phrases={hits}")

    if a.replay:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, "-m", "audit_demo.run", "--output", tmp],
                           check=True, capture_output=True)
            again = Path(tmp, "canonical.sha256").read_text().strip()
        check("7 replay: canonical decision digest identical", again == ev["canonical_sha256"],
              f"{again[:16]} vs {ev['canonical_sha256'][:16]}")

    width = max(len(n) for n, _, _ in results)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail if not ok else ''}")
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
