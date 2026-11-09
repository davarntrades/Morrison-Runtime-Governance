"""Build the Independent Agent Exposure Audit deliverable pack end to end.

    python -m audit_demo.exposure --output audit_demo/deliverables

Pipeline: scope -> assessment (run twice, for reproducibility) -> evidence
records -> reports (assessment hashed before and after, to show reports cannot
alter results) -> independent verification -> audit self-tests -> offline
viewer -> offline check -> manifest -> zip.
"""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from audit_demo.packkit import CSS, MARKER, _e, _fresh, write_manifest, write_zip
from audit_demo.exposure import sce02
from audit_demo.exposure.findings_log import DEVELOPMENT_FINDINGS
from audit_demo.exposure.metrics import customer_metrics, morrison_metrics, residual_register
from audit_demo.exposure.report import REPORT_FILE, SUMMARY_FILE

REPO = Path(__file__).resolve().parents[2]
PACK_NAME = "SCE-02_Independent-Agent-Exposure-Audit"
OUT_LABEL = {"HELD": ("Held", "ok"), "FAILED": ("Failed", "bad"), "FAILED_MISREPORTED": ("Failed; misreported", "bad"),
             "INCONCLUSIVE": ("Inconclusive", "hold"), "ALLOWED": ("Allowed", "ok"), "REACHABLE": ("Reachable", "bad"),
             "NOT_REACHABLE": ("Not reachable", "ok"), "PREVENTED": ("Prevented", "ok"),
             "HELD_FOR_APPROVAL": ("Held for approval", "hold"), "REACHED": ("Reached", "bad"),
             "PREVENTED_BY_FAIL_CLOSED_ERROR": ("Prevented by error", "hold"),
             "BLOCKED_LEGITIMATE": ("Legitimate work blocked", "bad")}


def _oc(o):
    t, c = OUT_LABEL.get(o, (o, "na"))
    return f'<span class="{c}">{_e(t)}</span>'


def _sha_dir(d: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(p for p in d.rglob("*") if p.is_file()):
        h.update(f.relative_to(d).as_posix().encode())
        h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()


def _py(log, name, args, ok_codes=(0,)):
    t0 = time.perf_counter()
    p = subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=REPO, check=False)
    def _rel(x: str) -> str:
        x = x.replace(str(REPO) + "/", "")
        return "<temporary directory>" if x.startswith(tempfile.gettempdir()) else x
    shown = [_rel(x) for x in args]
    log.append({"step": name, "command": "python " + " ".join(shown), "exit_code": p.returncode,
                "duration_s": round(time.perf_counter() - t0, 2),
                "output_tail": [_rel(x) for x in p.stdout.strip().splitlines()[-2:]]})
    print(f"  {name:<34} exit {p.returncode}  {log[-1]['duration_s']:>6}s")
    if p.returncode not in ok_codes:
        raise SystemExit(f"step '{name}' failed\n{p.stdout[-1500:]}\n{p.stderr[-1500:]}")
    return p


ONBOARDING = """# Onboarding requirements and the 48-hour target

The 48-hour clock starts only when every item below is in place.

## The customer provides

1. **An authorised, isolated test environment** for the one agent and workflow in scope. Payment,
   messaging and identity calls must go to sandbox or inert endpoints. Production is never touched.
2. **A customer adapter** meeting `audit_demo/exposure/adapter.py`:
   - `declared_tools()`: the documented tool inventory.
   - `discover_operations()`: what the agent's credential can actually call (API gateway listing,
     service-account permissions).
   - `via_customer_controls()`: the path through the customer's own safeguards, returning what they
     report.
   - `direct()`: the same operation with no safeguard (test environment only).
   - `observe()`: read access to the systems of record (ledger, identity store, message logs, export
     logs).
   - `unobservable()`: state the audit cannot read, declared up front.
3. **The constraints** the organisation claims, in writing, and which control is meant to enforce
   each.
4. **Test approval credentials** for any approval workflow (so genuine approvals can be issued).
5. **A named technical contact** available during the 48 hours.

## Effort, as estimated from building this sample (SCE-02)

| Work | Before the clock (onboarding) | Inside the 48 hours |
|:--|:--|:--|
| Adapter wiring against the customer's sandbox | 1-3 days, depending on API maturity | Fixes only |
| Encode constraints as observable prohibited states | | 4-6 h |
| Write and dry-run ~25 scenarios | | 6-10 h |
| Run, verify, self-test, build pack | | under 1 h of compute |
| Interpret results, residual register, review | | 6-10 h |

## Verdict on the 48-hour target

The target is **credible only if the adapter exists before the clock starts.** The adapter is the
customer-specific part. Building one from scratch inside 48 hours is not credible for most
regulated environments, because it depends on sandbox access, permissions and API behaviour outside
the auditor's control. Price the adapter as a separate onboarding step, or limit eligibility to
customers whose agent framework already has an adapter.

Things that would stop the clock: no sandbox for external-state-changing tools; no read access to
the system of record (results become INCONCLUSIVE); approval systems with no test credentials;
tools discovered at runtime that were not in the agreed scope.
"""


def write_records(pack: Path, ev: dict) -> dict:
    d = pack / "03_enforcement_evidence"
    (d / "records").mkdir(parents=True)
    recs = {}
    for r in ev["scenarios"]:
        for arm, a in r["arms"].items():
            for s in a["steps"]:
                rec = {"evidence_id": s["evidence_id"], "scenario": r["id"], "title": r["title"],
                       "policy": r["policy"], "property": r["property"], "arm": arm,
                       "arm_role": {"customer": "PRIMARY: customer safeguards", "no_control": "reachability",
                                    "morrison": "COMPARISON ONLY", "morrison_feed": "COMPARISON ONLY"}[arm],
                       "arm_outcome": a["outcome"], **s}
                recs[s["evidence_id"]] = rec
                (d / "records" / f"{s['evidence_id']}.json").write_text(
                    json.dumps(rec, indent=2, sort_keys=True, default=str, ensure_ascii=False))
    cols = ["evidence_id", "scenario", "policy", "property", "arm", "step", "tool", "control_report",
            "control", "verdict", "rule", "executed", "state_changed"]
    with (d / "evidence_register.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for i, r in recs.items():
            w.writerow([i, r["scenario"], r["policy"], r["property"], r["arm"], r["step"], r["call"]["tool"],
                        r.get("reported", ""), r.get("control", ""), r.get("verdict", ""), r.get("rule", ""),
                        r.get("executed", ""), ";".join(r["state_changed"])])
    return recs


def write_index(pack, ev, recs, cites, verification, selftest, repro, immut):
    cm, mm_ = customer_metrics(ev), morrison_metrics(ev)
    val = {r["metric"]: r["value"] for r in cites["numbers"]}     # identical to the technical report
    D = val["X.decidable"]
    tiles = [(f"{val['X.reachable']} / {D}", "prohibited outcomes reachable with no control"),
             (f"{val['X.held']} / {D}", "held by the organisation's safeguards"),
             (f"{val['X.local.held']} / {val['X.local.n']}", "local constraints held"),
             (f"{val['X.global.held']} / {val['X.global.n']}", "global constraints held")]

    def rows_for(prop):
        out = []
        for r in ev["scenarios"]:
            if r["property"] != prop:
                continue
            a = r["arms"]
            cu = [s["evidence_id"] for s in a["customer"]["steps"]]
            out.append(f"<tr><td class=mono>{r['id']}</td><td>{_e(r['title'])}</td><td>{r['policy']}</td>"
                       f"<td>{'Allowed' if r['kind'] == 'benign' else 'Prevented'}</td>"
                       f"<td>{_oc(a['customer']['outcome'])}</td><td>{_e(a['customer'].get('held_by') or '-')}</td>"
                       f"<td>{_oc(a['no_control']['outcome'])}</td>"
                       f"<td>{' '.join(f'<a class=mono href=#{i}>{i}</a>' for i in cu)}</td></tr>")
        return "".join(out)

    head = ("<tr><th>ID</th><th>Attempt</th><th>Policy</th><th>Expected</th><th>Observed (customer)</th>"
            "<th>Stopped by</th><th>No control</th><th>Evidence</th></tr>")
    reg = "".join(f"<tr><td class=mono>{x['id']}</td><td>{x['severity']}</td><td>{_oc(x['status'])}</td>"
                  f"<td>{_e(x['title'])}</td><td>{' '.join(f'<a class=mono href=#{i}>{i}</a>' for i in x['evidence'])}</td>"
                  f"<td>{_e(' '.join(filter(None, [x['limitation'], x['action']])))}</td></tr>"
                  for x in residual_register(ev))
    def links(ids):
        return " ".join(f'<a class=mono href=#{i}>{i}</a>' for i in ids)

    mo = "".join(f"<tr><td class=mono>{r['id']}</td><td>{_e(r['title'])}</td>"
                 f"<td>{_oc(r['arms']['morrison']['outcome'])}</td>"
                 f"<td>{links(st['evidence_id'] for st in r['arms']['morrison']['steps'])}</td></tr>"
                 for r in ev["scenarios"] if r["kind"] == "adversarial")
    reach = ev["reachability"]
    ops = "".join(f"<tr><td class=mono>{n}</td><td>{'Yes' if o['documented'] else '<span class=bad>No</span>'}</td>"
                  f"<td>{'Yes' if o['mutates'] else 'No'}</td><td>{'Yes' if o['external'] else 'No'}</td>"
                  f"<td>{', '.join(o['exercised_in']) or '<span class=na>untested</span>'}</td></tr>"
                  for n, o in sorted(reach["operations"].items()))
    checks = "".join(f"<tr><td>{'<span class=ok>PASS</span>' if c['passed'] else '<span class=bad>FAIL</span>'}</td>"
                     f"<td>{_e(c['check'])}</td><td>{_e(c['detail'])}</td></tr>" for c in verification["checks"])
    muts = "".join(f"<tr><td>{'<span class=ok>CAUGHT</span>' if m['result'] == 'CAUGHT' else '<span class=bad>ESCAPED</span>'}</td>"
                   f"<td class=mono>{m['id']}</td><td>{_e(m['mutation'])}</td></tr>" for m in selftest["mutations"])
    dfs = "".join(f"<li><b>{d['id']}</b> ({_e(d['about'])}, {_e(d['scenario'])}): {_e(d['found'])} <i>{_e(d['action'])}</i></li>"
                  for d in DEVELOPMENT_FINDINGS)
    rec_html = "".join(
        f'<details class="rec" id="{i}"><summary>{i} — {_e(r["call"]["tool"])} — {_e(r["arm_role"])} — '
        f'{_e(r.get("reported") or r.get("verdict"))}; state changed: {_e(", ".join(r["state_changed"]) or "nothing")}</summary>'
        f'<p class="sans" style="font-size:12px">File: <a href="03_enforcement_evidence/records/{i}.json">records/{i}.json</a></p>'
        f'<pre>{_e(json.dumps(r, indent=2, sort_keys=True, default=str, ensure_ascii=False))}</pre></details>'
        for i, r in recs.items())
    files = [("01_scope/scope.md", "Scope, constraints, controls, assumptions and exclusions"),
             ("01_scope/onboarding_requirements.md", "What must exist before the 48-hour clock starts"),
             ("02_assessment/evidence.json", "The executed assessment: every step, arm and state transition"),
             ("03_enforcement_evidence/evidence_register.csv", f"One row per step ({len(recs)} records)"),
             (f"04_report/{REPORT_FILE}", "Technical report"),
             (f"04_report/{SUMMARY_FILE}", "Board executive summary"),
             ("05_verification/verification.json", "Independent consistency checks, including replay"),
             ("05_verification/audit_selftest.json", "Mutation tests of the audit itself"),
             ("05_verification/selftest_before_fix.json", "The first self-test result, before weaknesses were fixed"),
             ("05_verification/reproducibility.json", "Two independent runs compared"),
             ("05_verification/report_immutability.json", "Assessment hashed before and after report generation"),
             ("MANIFEST.sha256", "Checksums: sha256sum -c MANIFEST.sha256")]
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SCE-02 Agent Exposure Audit</title><style>{CSS}</style></head><body><div class="wrap">
<header><span class="brand">Resurrection Tech™</span><span class="eyebrow">Runtime Governance</span></header>
<div class="sample"><div class="eyebrow">Illustrative sample — not a customer audit</div>
The client is SCE-02, a fictional UK motor insurer whose claims agent was driven by a scripted adversary. No real organisation, model or payment was involved.</div>
<div class="eyebrow">Engagement pack · £5,000 bounded scope</div>
<h1>Independent Agent Exposure Audit</h1>
<p class="lede">What can the agent reach, do the organisation's safeguards enforce what they claim, and what remains exposed? Every answer links to the evidence behind it.</p>

<section><div class="eyebrow">Result</div><h2>What was found</h2>
<div class="tiles">{''.join(f'<div class="tile"><b>{_e(b)}</b><span>{_e(t)}</span></div>' for b, t in tiles)}</div>
<p class="lede" style="font-size:13px">Denominator: the {D} executed adversarial scenarios whose outcome could be observed. Not counted: {val['X.inconclusive']} inconclusive ({', '.join(cm['inconclusive'])}) and {val['X.unsupported']} unsupported or untested ({', '.join(cm['unsupported'])}). Figures come from the technical report's citation file, so they match the PDF exactly.</p>
<p>Reports: <a href="04_report/{REPORT_FILE}">technical report</a> · <a href="04_report/{SUMMARY_FILE}">executive summary</a> ·
Verification: <span class="{'ok' if verification['passed'] == verification['total'] else 'bad'}">{verification['passed']} of {verification['total']} checks passed</span> ·
Self-tests: <span class="{'ok' if selftest['caught'] == selftest['total'] else 'bad'}">{selftest['caught']} of {selftest['total']} tampering attempts caught</span></p>
<div class="panel" style="font-size:14px"><b>Disclosure of dual role.</b> Resurrection Tech provides this audit and also sells Morrison Runtime Governance. Findings about the organisation's safeguards do not depend on Morrison. Morrison appears only in the separately labelled comparison below, and the recommendations name no product.</div></section>

<section><div class="eyebrow">Local safety</div><h2>Single-action constraints</h2><div class="scroll"><table>{head}{rows_for('local')}</table></div></section>
<section><div class="eyebrow">Global safety</div><h2>Sequence constraints</h2><div class="scroll"><table>{head}{rows_for('global')}</table></div>
<h3 class="sans" style="font-size:15px">Local and global together</h3><div class="scroll"><table>{head}{rows_for('local+global')}</table></div></section>

<section><div class="eyebrow">Residual exposure</div><h2>Residual exposure register</h2>
<p class="lede" style="font-size:13px">Severity is assessor judgement of consequence, not a probability. Actions are vendor-neutral.</p>
<div class="scroll"><table><tr><th>ID</th><th>Severity</th><th>Status</th><th>Exposure</th><th>Evidence</th><th>Limitation / action</th></tr>{reg}</table></div></section>

<section><div class="eyebrow">Reachability</div><h2>What the agent could call</h2>
<p>Documented: {len(reach['documented'])}. Observed at runtime: {len(reach['observed'])}. Not documented: <b>{', '.join(reach['observed_not_documented'])}</b>. Not observable: {', '.join(reach['unobservable_state'])}.</p>
<div class="scroll"><table><tr><th>Operation</th><th>Documented</th><th>Changes state</th><th>External</th><th>Tested in</th></tr>{ops}</table></div></section>

<section><div class="eyebrow">Comparison only</div><h2>An explicitly configured Morrison boundary</h2>
<p class="lede" style="font-size:13px">Not evidence about the organisation's safeguards. Strictest verdict governed in {', '.join(s['scenario'] + ' (' + s['verdict'] + ')' for s in mm_['strictest'])}.</p>
<div class="scroll"><table><tr><th>ID</th><th>Attempt</th><th>Outcome</th><th>Evidence</th></tr>{mo}</table></div></section>

<section><div class="eyebrow">Verification</div><h2>Checks of the report against the evidence</h2>
<div class="scroll"><table><tr><th>Result</th><th>Check</th><th>Detail</th></tr>{checks}</table></div>
<p>Reproducibility: two independent runs gave {'identical' if repro['identical'] else '<span class=bad>different</span>'} assessment digests (<code>{repro['run_1'][:20]}…</code>). Report generation left the assessment {'unchanged' if immut['unchanged'] else '<span class=bad>CHANGED</span>'}.</p>
<h3 class="sans" style="font-size:15px">Self-tests: attempts to make the verifier accept a wrong result</h3>
<div class="scroll"><table><tr><th>Result</th><th>ID</th><th>Tampering attempted</th></tr>{muts}</table></div>
<p class="lede" style="font-size:13px">First run, before fixes: {selftest['before_fix_caught']} of {selftest['total']} caught. Weaknesses found in the audit itself:</p><ul style="font-size:13.5px">{dfs}</ul></section>

<section><div class="eyebrow">Contents</div><h2>What is in this pack</h2><ul class="files">
{''.join(f'<li><a href="{f}">{_e(f)}</a>: {_e(d)}</li>' for f, d in files)}</ul></section>

<section><div class="eyebrow">Evidence</div><h2>All {len(recs)} step records</h2>{rec_html}</section>
<div class="mark">ℛ(t)</div>
<footer><span>Resurrection Tech™</span><span>Independent Agent Exposure Audit · illustrative sample</span><span>Patent GB2600765.8</span></footer>
</div></body></html>"""
    (pack / "index.html").write_text(page)


def build(output: Path) -> Path:
    pack = output / PACK_NAME
    _fresh(pack)
    log: list = []
    print(f"Independent Agent Exposure Audit (SCE-02) -> {pack}")
    s = pack / "01_scope"
    s.mkdir()
    scope = {"label": "ILLUSTRATIVE SAMPLE — NOT A CUSTOMER AUDIT",
             "offering": "Independent Agent Exposure Audit", "fee": "£5,000 (proposed, qualifying bounded scope)",
             "client": sce02.LABEL, "agent": sce02.AGENT, "declared_tools": sce02.DECLARED_TOOLS,
             "policies": sce02.POLICIES, "customer_controls": sce02.CUSTOMER_CONTROLS,
             "seeded_weaknesses": sce02.SEEDED_WEAKNESSES,
             "assumptions": ["Scripted adversary; no model calls.", "Authorised isolated test environment.",
                             "Outcomes read from systems of record only.",
                             "Unobservable state yields INCONCLUSIVE, never 'prevented'."],
             "exclusions": ["Exhaustive verification", "Unrestricted penetration testing",
                            "Multi-agent estate, shared-resource concurrency, multiple environments",
                            "Production certification", "Remediation work"]}
    (s / "scope.json").write_text(json.dumps(scope, indent=2, ensure_ascii=False))
    (s / "scope.md").write_text(
        "# Scope: Independent Agent Exposure Audit (SCE-02)\n\n> ILLUSTRATIVE SAMPLE — NOT A CUSTOMER AUDIT\n\n"
        f"**Agent:** {sce02.AGENT_ID}. {sce02.AGENT['workflow']}\n\n## Constraints\n\n"
        + "\n".join(f"- **{p['id']}** ({p['kind']}): {p['text']}" for p in sce02.POLICIES)
        + "\n\n## Customer controls under test\n\n"
        + "\n".join(f"- **{c['id']}** ({', '.join(c['policies'])}): {c['claim']}" for c in sce02.CUSTOMER_CONTROLS)
        + "\n\n## Assumptions\n\n" + "\n".join(f"- {x}" for x in scope["assumptions"])
        + "\n\n## Exclusions\n\n" + "\n".join(f"- {x}" for x in scope["exclusions"]) + "\n")
    (s / "onboarding_requirements.md").write_text(ONBOARDING)
    shutil.copy(REPO / "audit_demo" / "exposure" / "adapter.py", s / "customer_adapter_contract.py")

    a = pack / "02_assessment"
    _py(log, "assessment (run 1)", ["-m", "audit_demo.exposure.run", "--output", str(a)])
    with tempfile.TemporaryDirectory() as tmp:
        _py(log, "assessment (run 2, reproducibility)", ["-m", "audit_demo.exposure.run", "--output", tmp])
        run2 = Path(tmp, "canonical.sha256").read_text().strip()
    ev = json.loads((a / "evidence.json").read_text())
    v = pack / "05_verification"
    v.mkdir()
    repro = {"run_1": ev["canonical_sha256"], "run_2": run2, "identical": run2 == ev["canonical_sha256"],
             "excluded_fields": ev["non_deterministic_fields_excluded_from_replay"]}
    (v / "reproducibility.json").write_text(json.dumps(repro, indent=2))
    recs = write_records(pack, ev)

    before = _sha_dir(a)
    _py(log, "reports", ["-m", "audit_demo.exposure.report", "--evidence", str(a), "--out", str(pack / "04_report")])
    immut = {"assessment_sha256_before_reports": before, "assessment_sha256_after_reports": _sha_dir(a)}
    immut["unchanged"] = immut["assessment_sha256_before_reports"] == immut["assessment_sha256_after_reports"]
    (v / "report_immutability.json").write_text(json.dumps(immut, indent=2))

    _py(log, "independent verification", ["-m", "audit_demo.exposure.verify", "--assessment", str(a), "--reports",
                                          str(pack / "04_report"), "--replay", "--json", str(v / "verification.json")],
        ok_codes=(0, 1))
    _py(log, "audit self-tests", ["-m", "audit_demo.exposure.selftest", "--assessment", str(a), "--reports",
                                  str(pack / "04_report"), "--json", str(v / "audit_selftest.json")], ok_codes=(0, 1))
    shutil.copy(REPO / "audit_demo" / "exposure" / "selftest_before_fix.json", v / "selftest_before_fix.json")
    verification = json.loads((v / "verification.json").read_text())
    selftest = json.loads((v / "audit_selftest.json").read_text())
    selftest["before_fix_caught"] = json.loads((v / "selftest_before_fix.json").read_text())["caught"]
    cites = json.loads((pack / "04_report" / Path(REPORT_FILE).with_suffix(".citations.json").name).read_text())
    write_index(pack, ev, recs, cites, verification, selftest, repro, immut)

    # The viewer links to MANIFEST.sha256, so write a first manifest before the
    # offline check; the final manifest (below) also covers the check results.
    write_manifest(pack)
    # pack-level checks, including offline viewer behaviour
    missing = [i for i in cites["evidence_ids"] if i.startswith("EV-")
               and not (pack / "03_enforcement_evidence" / "records" / f"{i}.json").exists()]
    t0 = time.perf_counter()
    try:
        oc = subprocess.run(["node", str(REPO / "audit_demo" / "exposure" / "offline_check.js"), str(pack)],
                            capture_output=True, text=True, timeout=120, check=False)
        offline = json.loads(oc.stdout.strip().splitlines()[-1]) if oc.returncode == 0 else {"error": oc.stderr[-400:]}
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        offline = {"error": f"offline check not run: {exc}"}
    log.append({"step": "offline viewer check", "duration_s": round(time.perf_counter() - t0, 2)})
    (v / "offline_check.json").write_text(json.dumps(offline, indent=2))
    pack_checks = {
        "every cited evidence ID has a record file": not missing,
        "index works offline: all links and anchors resolve, no network requests":
            ("error" not in offline and not offline["missing_files"] and not offline["missing_anchors"]
             and not offline["external_requests"]),
        "index has no horizontal scroll at phone width": offline.get("phone_width_horizontal_overflow") is False,
        "two runs reproduce the same assessment digest": repro["identical"],
        "report generation did not alter the assessment": immut["unchanged"],
        "verification passed": verification["passed"] == verification["total"],
        "all self-test mutations caught": selftest["caught"] == selftest["total"],
    }
    (v / "pack_checks.json").write_text(json.dumps(pack_checks, indent=2))
    for k, ok in pack_checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {k}")
    (pack / "engagement_log.json").write_text(json.dumps(
        {"steps": log, "total_compute_s": round(sum(x.get("duration_s", 0) for x in log), 2)}, indent=2))
    (pack / "README.md").write_text(
        "# Independent Agent Exposure Audit: engagement pack (SCE-02)\n\n"
        "> **ILLUSTRATIVE SAMPLE — NOT A CUSTOMER AUDIT.** The client is SCE-02, a fictional UK motor insurer.\n\n"
        "Open `index.html` first: results, local and global findings, the residual exposure register, "
        "reachability, the separately labelled Morrison comparison, verification and every step record, "
        "linked together. It works offline.\n\n"
        f"- `04_report/{SUMMARY_FILE}`: for the board\n- `04_report/{REPORT_FILE}`: full technical report\n"
        "- `01_scope/onboarding_requirements.md`: what must exist before the 48-hour clock starts\n\n"
        "Check integrity: `sha256sum -c MANIFEST.sha256`\n\n"
        "Reproduce from the repository: `python -m audit_demo.exposure --output audit_demo/deliverables`\n")
    digest = write_manifest(pack)
    z = write_zip(pack)
    ok = all(pack_checks.values())
    print(f"  manifest {digest[:16]}…  {z.name}  -> {'COMPLETE' if ok else 'COMPLETE WITH FAILED CHECKS'}")
    return pack


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="python -m audit_demo.exposure")
    p.add_argument("--output", type=Path, default=Path("audit_demo/deliverables"))
    a = p.parse_args(argv)
    pack = build(a.output.resolve())
    checks = json.loads((pack / "05_verification" / "pack_checks.json").read_text())
    return 0 if all(checks.values()) else 1


__all__ = ["build", "main", "MARKER"]
