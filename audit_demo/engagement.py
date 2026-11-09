"""Run one illustrative engagement end to end and assemble what the client receives.

    python -m audit_demo.engagement --package A --output audit_demo/deliverables
    python -m audit_demo.engagement --package B --output audit_demo/deliverables

Produces <output>/SCE-01_Package-<X>/ and a .zip of it:

  index.html                 open this first: scope, findings, evidence and report together
  README.md                  what is in the pack and how to check it
  01_scope/                  what was assessed, what was not
  02_assessment/             the executed run (evidence.json, canonical replay digest,
                             and for Package B the supporting experiments)
  03_enforcement_evidence/   one record per evidence ID cited in the report, plus a register
  04_report/                 the report PDF and its per-number citations
  05_verification/           independent verification results, including replay
  engagement_log.json        each step, its command, exit code and duration
  MANIFEST.sha256            checksum of every file in the pack

ILLUSTRATIVE SAMPLE: the client is the simulated environment SCE-01.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from audit_demo import environment as E
from audit_demo.metrics import package_metrics
from audit_demo.report_pdf import REPORT_FILES
from audit_demo.scenarios import scenarios_for

PACKAGES = {
    "A": {"name": "48-Hour Bounded Exposure Audit", "fee": "$5,000 (proposed, not market-validated)",
          "report": REPORT_FILES["A"]},
    "B": {"name": "Enterprise Runtime Governance Audit",
          "fee": "£40,000–£70,000 (proposed, not market-validated)",
          "report": REPORT_FILES["B"]},
}
ARMS = {"ungoverned": "No control", "customer_controls": "Customer controls",
        "morrison_shadow": "Morrison shadow", "morrison_enforced": "Morrison enforced",
        "morrison_enforced_per_agent_history": "Morrison, per-agent history"}
MARKER = ".engagement-pack"
REPO_ROOT = Path(__file__).resolve().parent.parent


# ── pipeline ──────────────────────────────────────────────────────────────
def _step(log: list, name: str, args: list[str]) -> None:
    t0 = time.perf_counter()
    proc = subprocess.run([sys.executable, *args], capture_output=True, text=True,
                          cwd=REPO_ROOT, check=False)
    log.append({"step": name, "command": "python " + " ".join(args),
                "exit_code": proc.returncode,
                "duration_s": round(time.perf_counter() - t0, 2),
                "output_tail": proc.stdout.strip().splitlines()[-3:]})
    print(f"  {name:<28} exit {proc.returncode}  {log[-1]['duration_s']:>6}s")
    if proc.returncode != 0:
        raise SystemExit(f"step '{name}' failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")


def _fresh(pack: Path) -> None:
    """Replace a previous pack only if this tool created it."""
    if pack.exists():
        if not (pack / MARKER).exists():
            raise SystemExit(f"{pack} exists and was not created by this tool; refusing to overwrite")
        shutil.rmtree(pack)
    pack.mkdir(parents=True)
    (pack / MARKER).write_text("created by audit_demo.engagement\n")


# ── 01 scope ──────────────────────────────────────────────────────────────
EXCLUSIONS = {
    "common": [
        "Any real customer system, model, credential, network or payment rail (scripted proposer).",
        "Tools, agents, accounts and policies not listed in this scope.",
        "Production integration: latency under load, availability, crash recovery.",
        "Control Room (operator console) display and parity: NOT TESTED.",
        "Financial-loss estimation.",
    ],
    "A": ["Cross-agent interaction, role management, approval-service integrity and broader "
          "falsification (Package B)."],
    "B": [],
}


def write_scope(pack: Path, pkg: str) -> dict:
    scen = scenarios_for(pkg)
    scope = {
        "label": "ILLUSTRATIVE SAMPLE — NOT A CUSTOMER AUDIT",
        "package": pkg, **PACKAGES[pkg],
        "client": E.ENVIRONMENT_LABEL,
        "agent": E.AGENT,
        "tools_declared": {k: {"capabilities": v[0], "description": v[1]} for k, v in E.TOOLS.items()},
        "tools_discovered_undeclared": E.UNDECLARED_REACHABLE_TOOLS,
        "policies_under_test": E.POLICIES,
        "customer_controls_under_test": E.CUSTOMER_CONTROLS,
        "seeded_weaknesses_note": ("The simulated customer controls contain weaknesses planted on "
                                   "purpose (SW1–SW6) so that detection can be demonstrated."),
        "seeded_weaknesses": E.SEEDED_WEAKNESSES,
        "scenarios": [{"id": s["id"], "title": s["title"], "policy": s["policy"],
                       "property": s["property"], "kind": s["kind"]} for s in scen],
        "arms": ["ungoverned", "customer_controls", "morrison_shadow", "morrison_enforced"]
        + (["morrison_enforced_per_agent_history (B01 only)"] if pkg == "B" else []),
        "proposer": "scripted; represents a compromised or mistaken agent; no model calls",
        "exclusions": EXCLUSIONS["common"] + EXCLUSIONS[pkg],
    }
    d = pack / "01_scope"
    d.mkdir()
    (d / "scope.json").write_text(json.dumps(scope, indent=2, ensure_ascii=False))
    lines = [f"# Scope: {scope['name']} (Package {pkg})", "",
             f"> {scope['label']}. Client: {scope['client']}", "",
             f"**Proposed fee:** {scope['fee']}", "",
             f"**Agent:** {E.AGENT['id']}: {E.AGENT['description']}", "",
             "## Policies under test", ""]
    lines += [f"- **{p['id']}** ({p['kind']}): {p['text']}" for p in E.POLICIES]
    lines += ["", "## Scenarios executed", "", "| ID | Policy | Property | Kind | Attempt |",
              "|:--|:--|:--|:--|:--|"]
    lines += [f"| {s['id']} | {s['policy']} | {s['property']} | {s['kind']} | {s['title']} |"
              for s in scope["scenarios"]]
    lines += ["", "## Exclusions", ""] + [f"- {x}" for x in scope["exclusions"]]
    (d / "scope.md").write_text("\n".join(lines) + "\n")
    return scope


# ── 03 enforcement evidence ───────────────────────────────────────────────
def _records(ev: dict):
    for sc in ev["scenarios"]:
        for arm, d in sc["arms"].items():
            for st in d.get("steps", []):
                yield st["evidence_id"], {
                    "evidence_id": st["evidence_id"],
                    "scenario": {k: sc[k] for k in ("id", "title", "policy", "property", "kind")},
                    "prohibited_state": sc.get("prohibited_state") or sc.get("goal_state"),
                    "arm": arm, "arm_outcome": d.get("outcome"), **{
                        k: st.get(k) for k in ("step", "principal", "call", "verdict", "layer", "rule",
                                               "reason", "control", "capabilities", "requirement",
                                               "approval", "shadow_decision", "executed",
                                               "evidence", "resource_error")},
                    "state_before": st["state_before"], "state_after": st["state_after"]}
    for mode, d in ev.get("frontier_sessions", {}).items():
        for st in d["steps"]:
            yield st["evidence_id"], {"evidence_id": st["evidence_id"], "source": "Frontier Lab",
                                      "session_id": d["session_id"], "mode": mode,
                                      "session_evidence_hash": d["session_evidence_hash"],
                                      "session_sealed": d["session_evidence_verified"],
                                      "step_chain_verified": d["step_chain_verified"], **st}


def write_evidence(pack: Path, ev: dict) -> dict:
    d = pack / "03_enforcement_evidence"
    (d / "records").mkdir(parents=True)
    recs = dict(_records(ev))
    for eid, rec in recs.items():
        (d / "records" / f"{eid}.json").write_text(json.dumps(rec, indent=2, sort_keys=True, default=str, ensure_ascii=False))
    cols = ["evidence_id", "scenario", "policy", "property", "arm", "step", "principal", "tool",
            "verdict", "layer", "rule", "executed", "action_hash", "ruleset_hash", "decision_id",
            "evidence_hash"]
    with (d / "evidence_register.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for eid, r in recs.items():
            e = r.get("evidence") or {}
            sc = r.get("scenario") or {}
            w.writerow([eid, sc.get("id", "Frontier Lab"), sc.get("policy", ""), sc.get("property", ""),
                        r.get("arm", r.get("mode")), r.get("step", ""), r.get("principal", ""),
                        (r.get("call") or {}).get("tool", r.get("tool")), r.get("verdict"),
                        r.get("layer", ""), r.get("rule", ""), r.get("executed", r.get("execution_occurred")),
                        e.get("action_hash", ""), e.get("ruleset_hash", ""), e.get("decision_id", ""),
                        e.get("evidence_hash", "")])
    return recs


# ── index.html ────────────────────────────────────────────────────────────
CSS = """
:root{--ink:#212121;--body:#333333;--muted:#737373;--soft:#8A929C;--rule:#E2E2E2;--srule:#B8B8B8;
--pale:#F3F3F3;--gold:#9A6A12;--green:#2E7D52;--red:#B3261E;--redfill:#F7EFEF;--redline:#E0B9B6}
*{box-sizing:border-box}html,body{margin:0;background:#fff;color:var(--body)}
body{font-family:"DejaVu Serif",Georgia,serif;font-size:15px;line-height:1.55}
.wrap{max-width:980px;margin:0 auto;padding:28px 16px 80px}
.sans,h1,h2,h3,th,.eyebrow,.brand,.pill,.tile b{font-family:"DejaVu Sans",Verdana,sans-serif}
header{display:flex;justify-content:space-between;align-items:baseline;border-bottom:1px solid var(--srule);padding-bottom:10px}
.brand{font-weight:700;color:var(--ink);font-size:17px}.eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--muted)}
.sample{margin:18px 0;background:var(--redfill);border:1px solid var(--redline);border-left:4px solid var(--red);padding:12px 16px;font-size:14px}
.sample .eyebrow{color:var(--red)}
section{border-top:1px solid var(--srule);margin-top:34px;padding-top:12px}
h1{font-size:28px;color:var(--ink);margin:6px 0 4px}h2{font-size:19px;color:var(--ink);margin:4px 0 12px}
.lede{color:var(--muted)}
.panel{background:var(--pale);border-left:4px solid var(--ink);padding:16px 18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px}
.tile{background:var(--pale);border:1px solid var(--rule);padding:12px 14px}
.tile b{display:block;font-size:24px;color:var(--ink)}.tile span{font-family:"DejaVu Sans",sans-serif;font-size:12px;color:var(--muted)}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--ink);border-bottom:1.5px solid var(--ink);padding:6px 8px}
td{border-bottom:1px solid var(--rule);padding:7px 8px;vertical-align:top}
.ok{color:var(--green);font-weight:700}.bad{color:var(--red);font-weight:700}.hold{color:var(--gold);font-weight:700}.na{color:var(--muted)}
a{color:var(--ink);overflow-wrap:anywhere}code,.mono{font-family:"DejaVu Sans Mono",Menlo,monospace;font-size:12.5px}
.files li{margin:4px 0}
details.rec{border-bottom:1px solid var(--rule);padding:6px 0}
details.rec summary{cursor:pointer;overflow-wrap:anywhere;font-family:"DejaVu Sans",sans-serif;font-size:13px}
details.rec:target,details.rec:target summary{background:#FFF8E6}
pre{background:var(--pale);padding:10px;overflow-x:auto;font-size:12px;line-height:1.4}
footer{margin-top:40px;border-top:1px solid var(--srule);padding-top:8px;display:flex;justify-content:space-between;color:var(--muted);font-family:"DejaVu Sans",sans-serif;font-size:12px;flex-wrap:wrap;gap:8px}
.mark{color:var(--gold);font-family:"DejaVu Sans",sans-serif;font-weight:700;font-size:30px;text-align:center;margin-top:30px}
"""

OUTCOME_CLASS = {"PREVENTED": ("Prevented", "ok"), "PREVENTED_HELD_FOR_APPROVAL": ("Held for approval", "hold"),
                 "REACHED": ("Reached", "bad"), "REACHED_DETECTED_AFTER_EXECUTION": ("Reached; flagged after", "bad"),
                 "REACHED_FLAGGED_BEFORE_EXECUTION": ("Reached; flagged before (shadow)", "hold"),
                 "REACHED_NOT_FLAGGED": ("Reached; not flagged", "bad"), "WORK_COMPLETED": ("Work completed", "ok"),
                 "WORK_HELD_FOR_APPROVAL": ("Held for approval", "hold"),
                 "WORK_NOT_COMPLETED": ("Work not completed", "bad"), "NOT_TESTED": ("Not tested", "na")}


def _e(x) -> str:
    return html.escape(str(x))


def _oc(o):
    t, c = OUTCOME_CLASS.get(o, (o, "na"))
    return f'<span class="{c}">{_e(t)}</span>'


def write_index(pack: Path, pkg: str, ev: dict, scope: dict, recs: dict, cites: dict,
                verification: dict, manifest_note: str) -> None:
    val = {r["metric"]: r["value"] for r in cites["numbers"]}       # identical to the PDF
    m = package_metrics(ev, pkg)
    D = m["arms"]["morrison_enforced"]["denominator"]
    P = f"{pkg}."
    tiles = [
        (f"{val[P + 'reachability.reached']} / {val[P + 'reachability.of']}",
         "prohibited outcomes reachable with no control"),
        (f"{val[P + 'arms.customer_controls.prevented.n']} / {D}", "prevented by the organisation's controls"),
        (f"{val[P + 'arms.morrison_enforced.prevented.n']} / {D}",
         f"prevented with Morrison enforcing ({val[P + 'arms.morrison_enforced.prevented_held_for_approval.n']} held for approval)"),
        (f"{m['arms']['morrison_enforced']['reached']['n']}", "still reached with Morrison enforcing"),
    ]
    rows = []
    for sid in m["scenario_ids"]:
        sc = next(s for s in ev["scenarios"] if s["id"] == sid)
        a = sc["arms"]
        dec = [st["evidence_id"] for st in a["morrison_enforced"].get("steps", []) if st["verdict"] != "PERMIT"]
        dec = dec or [st["evidence_id"] for st in a["morrison_enforced"].get("steps", [])][-1:]
        cc = [st["evidence_id"] for st in a["customer_controls"].get("steps", [])][-1:]
        links = " ".join(f'<a href="#{i}" class="mono">{i}</a>' for i in cc + dec)
        rows.append(f"<tr><td class='mono'>{sid}</td><td>{_e(sc['title'])}</td><td>{sc['policy']}</td>"
                    f"<td>{_e(sc['property'])}</td><td>{_oc(a['ungoverned'].get('outcome'))}</td>"
                    f"<td>{_oc(a['customer_controls'].get('outcome', a['customer_controls'].get('status')))}</td>"
                    f"<td>{_oc(a['morrison_enforced'].get('outcome'))}</td><td>{links}</td></tr>")
    recs_html = []
    for eid, r in recs.items():
        head = (f"{eid} — {_e((r.get('call') or {}).get('tool', r.get('tool')))} — "
                f"{_e(ARMS.get(r.get('arm'), r.get('mode', '')))} — verdict {_e(r.get('verdict'))}, "
                f"executed {_e(r.get('executed', r.get('execution_occurred')))}")
        recs_html.append(f'<details class="rec" id="{eid}"><summary>{head}</summary>'
                         f'<p class="sans" style="font-size:12px">File: <a href="03_enforcement_evidence/records/{eid}.json">'
                         f'records/{eid}.json</a></p><pre>{_e(json.dumps(r, indent=2, sort_keys=True, default=str, ensure_ascii=False))}</pre></details>')
    checks = "".join(f"<tr><td>{'<span class=ok>PASS</span>' if c['passed'] else '<span class=bad>FAIL</span>'}</td>"
                     f"<td>{_e(c['check'])}</td><td>{_e(c['detail'])}</td></tr>" for c in verification["checks"])
    files = [("01_scope/scope.md", "What was assessed, what was not, and the policies under test"),
             ("02_assessment/evidence.json", "The executed run: every step, every arm, resource state before and after"),
             ("03_enforcement_evidence/evidence_register.csv", f"One row per decision ({len(recs)} records), with action and rule-set hashes"),
             (f"04_report/{scope['report']}", "The report PDF"),
             (f"04_report/{Path(scope['report']).with_suffix('.citations.json').name}", "Every number in the report, its metric and evidence IDs"),
             ("05_verification/verification.json", "Independent verification results, including replay"),
             ("engagement_log.json", "Each pipeline step, its exit code and duration"),
             ("MANIFEST.sha256", "Checksums for every file in this pack")]
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SCE-01 Package {pkg} pack</title><style>{CSS}</style></head><body><div class="wrap">
<header><span class="brand">Resurrection Tech™</span><span class="eyebrow">Runtime Governance</span></header>
<div class="sample"><div class="eyebrow">Illustrative sample — not a customer audit</div>
The client is SCE-01, a simulated building society with a scripted agent. No real organisation, model or payment was involved.</div>
<div class="eyebrow">Engagement pack · Package {pkg}</div>
<h1>{_e(scope['name'])}</h1>
<p class="lede">What the organisation receives: the scope, the executed assessment, the enforcement evidence for every decision, the report, and an independent check that the three agree.</p>

<section><div class="eyebrow">Result</div><h2>What was found</h2>
<div class="tiles">{''.join(f'<div class="tile"><b>{_e(b)}</b><span>{_e(t)}</span></div>' for b, t in tiles)}</div>
<p class="lede" style="font-size:13px">Denominator: the {D} adversarial scenarios executed in this engagement. Figures are read from the report's own citation file, so they match the PDF exactly.</p>
<p>Report: <a href="04_report/{scope['report']}">{_e(scope['report'])}</a> · Verification: <span class="{'ok' if verification['passed'] == verification['total'] else 'bad'}">{verification['passed']} of {verification['total']} checks passed</span></p></section>

<section><div class="eyebrow">Findings to evidence</div><h2>Each scenario, its outcome, and the decisions behind it</h2>
<p class="lede" style="font-size:13px">Evidence links jump to the customer-control step and the Morrison decision that settled each scenario. Outcomes are read from the protected resources, not from verdicts.</p>
<div class="scroll"><table><tr><th>ID</th><th>Attempt</th><th>Policy</th><th>Type</th><th>No control</th><th>Customer controls</th><th>Morrison enforced</th><th>Evidence</th></tr>
{''.join(rows)}</table></div></section>

<section><div class="eyebrow">Contents</div><h2>What is in this pack</h2><ul class="files">
{''.join(f'<li><a href="{f}">{_e(f)}</a>: {_e(d)}</li>' for f, d in files)}</ul>
<p class="lede" style="font-size:13px">{_e(manifest_note)}</p></section>

<section><div class="eyebrow">Verification</div><h2>Independent checks of the report against its evidence</h2>
<div class="scroll"><table><tr><th>Result</th><th>Check</th><th>Detail</th></tr>{checks}</table></div>
<p class="lede" style="font-size:13px">Replay: decisions, rules and resource states reproduce byte for byte (canonical digest <code>{verification['canonical_sha256'][:24]}…</code>). Decision IDs, timestamps and evidence hashes are unique per run by design.</p></section>

<section><div class="eyebrow">Enforcement evidence</div><h2>All {len(recs)} decision records</h2>
{''.join(recs_html)}</section>

<div class="mark">ℛ(t)</div>
<footer><span>Resurrection Tech™</span><span>{_e(scope['name'])} · illustrative sample</span><span>Patent GB2600765.8</span></footer>
</div></body></html>"""
    (pack / "index.html").write_text(page)


# ── README, manifest, zip ─────────────────────────────────────────────────
def write_readme(pack: Path, pkg: str, scope: dict, verification: dict, log: list) -> None:
    total = round(sum(s["duration_s"] for s in log), 1)
    (pack / "README.md").write_text(f"""# Engagement pack: {scope['name']} (Package {pkg})

> **ILLUSTRATIVE SAMPLE — NOT A CUSTOMER AUDIT.** The client is SCE-01, a simulated
> building society with a scripted agent.

Open `index.html` first. It puts the result, each finding, the decision records behind
it, and the verification together on one page, and links to everything else.

| Folder | Contents |
|:--|:--|
| `01_scope/` | What was assessed and what was excluded |
| `02_assessment/` | The executed run (`evidence.json`) and its replay digest |
| `03_enforcement_evidence/` | One JSON record per evidence ID, and `evidence_register.csv` |
| `04_report/` | `{scope['report']}` and its citations file |
| `05_verification/` | `verification.json`: {verification['passed']} of {verification['total']} checks passed |

## Check this pack

```bash
sha256sum -c MANIFEST.sha256
```

## Reproduce it

From the Morrison Runtime Governance repository, with `agentdojo==0.1.35` installed:

```bash
python -m audit_demo.engagement --package {pkg} --output audit_demo/deliverables
```

The pipeline's compute time for this pack was {total} s (see `engagement_log.json`). In a real
engagement the time goes into scoping, modelling the client's agent and controls, and
review, not computation.
""")


def write_manifest(pack: Path) -> str:
    lines = []
    for f in sorted(p for p in pack.rglob("*") if p.is_file() and p.name not in ("MANIFEST.sha256", MARKER)):
        lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(pack).as_posix()}")
    (pack / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")
    return hashlib.sha256((pack / "MANIFEST.sha256").read_bytes()).hexdigest()


def write_zip(pack: Path) -> Path:
    z = pack.with_suffix(".zip")
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(p for p in pack.rglob("*") if p.is_file() and p.name != MARKER):
            zf.write(f, f"{pack.name}/{f.relative_to(pack).as_posix()}")
    return z


# ── pack self-check ───────────────────────────────────────────────────────
def pack_checks(pack: Path, scope: dict, recs: dict, cites: dict) -> list[tuple[str, bool, str]]:
    out = []
    missing = [i for i in cites["evidence_ids"] if i.startswith("EV-") and
               not (pack / "03_enforcement_evidence" / "records" / f"{i}.json").exists()]
    out.append(("every evidence ID cited in the report has a record file", not missing, str(missing)))
    index = (pack / "index.html").read_text()
    unanchored = [i for i in cites["evidence_ids"] if i.startswith("EV-") and f'id="{i}"' not in index]
    out.append(("every cited evidence ID is linked in index.html", not unanchored, str(unanchored)))
    in_scope = {s["id"] for s in scope["scenarios"]}
    ev = json.loads((pack / "02_assessment" / "evidence.json").read_text())
    got = {s["id"] for s in ev["scenarios"]}
    out.append(("assessment contains exactly the scoped scenarios", got == in_scope,
                f"extra={sorted(got - in_scope)} missing={sorted(in_scope - got)}"))
    out.append(("pack holds only this package's report",
                sorted(p.name for p in (pack / "04_report").glob("*.pdf")) == [scope["report"]], ""))
    return out


def build(pkg: str, output: Path) -> Path:
    pack = output / f"SCE-01_Package-{pkg}"
    _fresh(pack)
    log: list = []
    print(f"Package {pkg}: {PACKAGES[pkg]['name']} -> {pack}")
    scope = write_scope(pack, pkg)
    a = pack / "02_assessment"
    _step(log, "assessment run", ["-m", "audit_demo.run", "--package", pkg, "--output", str(a)])
    if pkg == "B":
        _step(log, "supporting experiments", ["-m", "audit_demo.supporting", "--output", str(a / "supporting")])
        shutil.copy(REPO_ROOT / "audit_demo" / "evidence" / "test_runs.json", a / "test_runs.json")
    ev = json.loads((a / "evidence.json").read_text())
    recs = write_evidence(pack, ev)
    _step(log, "report", ["-m", "audit_demo.report_pdf", "--evidence", str(a), "--out",
                          str(pack / "04_report"), "--only", pkg])
    _step(log, "independent verification", ["-m", "audit_demo.verify", "--evidence", str(a), "--reports",
                                            str(pack / "04_report"), "--replay", "--json",
                                            str(pack / "05_verification" / "verification.json")])
    verification = json.loads((pack / "05_verification" / "verification.json").read_text())
    cites = json.loads((pack / "04_report" / Path(scope["report"]).with_suffix(".citations.json").name).read_text())
    note = "Check integrity with: sha256sum -c MANIFEST.sha256"
    write_index(pack, pkg, ev, scope, recs, cites, verification, note)
    checks = pack_checks(pack, scope, recs, cites)
    verification["pack_checks"] = [{"check": n, "passed": ok, "detail": d} for n, ok, d in checks]
    (pack / "05_verification" / "verification.json").write_text(json.dumps(verification, indent=2))
    for n, ok, d in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  pack: {n}  {'' if ok else d}")
    (pack / "engagement_log.json").write_text(json.dumps(
        {"package": pkg, "steps": log, "total_compute_s": round(sum(s["duration_s"] for s in log), 2)},
        indent=2))
    write_readme(pack, pkg, scope, verification, log)
    digest = write_manifest(pack)
    z = write_zip(pack)
    ok = verification["passed"] == verification["total"] and all(c[1] for c in checks)
    print(f"  manifest sha256 {digest[:16]}…  zip {z.name}  -> {'COMPLETE' if ok else 'FAILED CHECKS'}")
    if not ok:
        raise SystemExit(1)
    return pack


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m audit_demo.engagement")
    p.add_argument("--package", choices=("A", "B"), action="append", required=True)
    p.add_argument("--output", type=Path, default=Path("audit_demo/deliverables"))
    a = p.parse_args(argv)
    for pkg in a.package:
        build(pkg, a.output.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
