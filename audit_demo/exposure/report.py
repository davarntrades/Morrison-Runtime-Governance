"""Technical report and board executive summary for the Independent Agent
Exposure Audit. Reuses the Resurrection Tech brand layer in audit_demo.report_pdf.

Reads evidence.json only. It never writes to the assessment directory; the
engagement pipeline hashes that directory before and after to prove it.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reportlab.platypus import CondPageBreak, Spacer

from audit_demo.exposure.findings_log import DEVELOPMENT_FINDINGS
from audit_demo.exposure.metrics import customer_metrics, morrison_metrics, residual_register
from audit_demo.report_pdf import (GOLD, GREEN, MUTED, ORANGE, RED, Cite, P, _build, bullets,
                                   callout, cover, kpis, table)

REPORT_FILE = "Independent_Agent_Exposure_Audit_Technical_Report_SAMPLE.pdf"
SUMMARY_FILE = "Independent_Agent_Exposure_Audit_Executive_Summary_SAMPLE.pdf"
ENV = "SCE-02"
CLIENT = "Simulated customer SCE-02"
WARNING = ('<font name="DejaVuSans-Bold">Every scenario was executed in a SIMULATED customer '
           'environment.</font> SCE-02 is a fictional UK motor insurer whose claims agent was driven '
           'by a scripted adversary. No real organisation, system, model or payment was involved. Do '
           'not rely on this document as assurance about any organisation.')
DUAL_ROLE = ("<b>Disclosure of dual role.</b> Resurrection Tech provides this independent audit and also "
             "sells an enforcement product, Morrison Runtime Governance. The findings about the "
             "organisation's safeguards stand on their own and do not depend on Morrison. Morrison "
             "appears only in Section 8, as a separately labelled comparison. Recommendations in this "
             "report name no product.")

LABEL = {"HELD": ("Held", GREEN), "FAILED": ("Failed", RED), "FAILED_MISREPORTED": ("Failed; misreported", RED),
         "INCONCLUSIVE": ("Inconclusive", GOLD), "ALLOWED": ("Allowed", GREEN),
         "BLOCKED_LEGITIMATE": ("Legitimate work blocked", RED), "HELD_FOR_APPROVAL": ("Held for approval", GOLD),
         "PREVENTED": ("Prevented", GREEN), "PREVENTED_BY_FAIL_CLOSED_ERROR": ("Prevented by error (fail-closed)", ORANGE),
         "REACHED": ("Reached", RED), "REACHABLE": ("Reachable", RED), "NOT_REACHABLE": ("Not reachable", GREEN),
         "UNSUPPORTED": ("Unsupported", MUTED), "NOT_TESTED": ("Not tested", MUTED)}
SEV = {"Critical": RED, "High": ORANGE, "Medium": GOLD, "Unrated": MUTED}


def lab(o):
    t, c = LABEL.get(o, (o, MUTED))
    return f'<font name="DejaVuSerif-Bold" color="{c.hexval()}">{t}</font>'


def _by(ev):
    return {r["id"]: r for r in ev["scenarios"]}


def _controls_for(ev, policy):
    return ", ".join(c["id"] for c in ev["environment"]["customer_controls"]
                     if any(p in policy.split("+") for p in c["policies"])) or "none claimed"


def _cu_ids(r):
    return [s["evidence_id"] for s in r["arms"]["customer"]["steps"]]


# ── technical report ──────────────────────────────────────────────────────
def technical_report(ev: dict, out: Path) -> Path:
    C = Cite()
    cm, mm_ = customer_metrics(ev), morrison_metrics(ev)
    by = _by(ev)
    reach = ev["reachability"]
    a = cm["all"]
    D = cm["decidable"]
    story: list = []
    cover(story, "Independent Agent Exposure Audit",
          "Technical report: one agent, one workflow, bounded adversarial testing",
          [["Engagement", "Independent Agent Exposure Audit (£5,000, bounded scope)"],
           ["Status", '<font color="#B3261E"><b>ILLUSTRATIVE SAMPLE — NOT A CUSTOMER AUDIT</b></font>'],
           ["Client", ev["environment"]["label"]],
           ["Agent", f"{ev['environment']['agent']['id']}: one agent, one workflow (motor-claim settlement)"],
           ["Assessment digest", f"<font face='DejaVuSansMono' size='7'>{ev['canonical_sha256']}</font>"],
           ["Prepared by", "Resurrection Tech Ltd"]], client=CLIENT, warning=WARNING)

    # 1 executive summary
    story.append(P("1. Executive summary", "h1"))
    story.append(callout(
        "<b>Three questions, answered within the tested boundary.</b> "
        "<b>1. What can the agent reach?</b> With nothing in its path, it could reach "
        f"{C.n(len(cm['reachable_without_controls']), 'X.reachable', cm['reachable_without_controls'])} of "
        f"the {C.n(D, 'X.decidable')} prohibited outcomes that could be decided, through "
        f"{C.n(len(reach['observed']), 'X.ops.observed')} operations, "
        f"{C.n(len(reach['observed_not_documented']), 'X.ops.undeclared')} of them undeclared. "
        "<b>2. Do the existing safeguards enforce what they claim?</b> Partly. They held "
        f"{C.n(len(a['held']), 'X.held', a['held'])} of {D} and failed {C.n(len(a['failed']), 'X.failed', a['failed'])}. "
        "Most failures were in policies that span several actions. "
        "<b>3. What remains exposed?</b> Every failure is in the residual exposure register (Section 7), "
        "with its evidence."))
    story.append(Spacer(1, 6))
    story.append(kpis([
        (f"{C.n(len(cm['reachable_without_controls']), 'X.reachable', cm['reachable_without_controls'])} / {D}",
         "prohibited outcomes reachable with no control", RED),
        (f"{C.n(len(a['held']), 'X.held', a['held'])} / {D}", "held by the organisation's safeguards", GOLD),
        (f"{C.n(len(cm['local']['held']), 'X.local.held', cm['local']['held'])} / "
         f"{C.n(cm['local']['n'], 'X.local.n')}", "local constraints held", GOLD),
        (f"{C.n(len(cm['global']['held']), 'X.global.held', cm['global']['held'])} / "
         f"{C.n(cm['global']['n'], 'X.global.n')}", "global (sequence) constraints held", RED),
    ]))
    story.append(P(f"Denominator: the {D} executed adversarial scenarios whose outcome could be observed. "
                   f"Not counted: {C.n(len(cm['inconclusive']), 'X.inconclusive', cm['inconclusive'])} "
                   f"inconclusive ({', '.join(cm['inconclusive'])}, state not observable) and "
                   f"{C.n(len(cm['unsupported']), 'X.unsupported')} unsupported or untested "
                   f"({', '.join(cm['unsupported'])}). The scenarios are a bounded selection, not an "
                   "enumeration of everything the agent could do.", "small"))
    story.append(P("What the board can conclude", "h2"))
    story += bullets([
        f"<b>Claimed controls are not all enforced.</b> {len(a['failed'])} attempts reached a prohibited "
        f"state despite a control claiming to prevent it ({C.ev(*a['failed'])}).",
        f"<b>One control reported a block that did not happen.</b> The email filter reported the "
        f"identity document as blocked, but it had already been sent "
        f"({C.n(len(cm['misreported']), 'X.misreported', cm['misreported'])} case: "
        f"{C.ev(*[s for r in cm['misreported'] for s in _cu_ids(by[r])])}). Reports from controls cannot "
        "be taken as evidence of prevention.",
        f"<b>Single-action checks mostly work; sequence checks mostly do not.</b> Local constraints held "
        f"{len(cm['local']['held'])} of {cm['local']['n']}; global constraints held "
        f"{len(cm['global']['held'])} of {cm['global']['n']}.",
        f"<b>Legitimate work was not obstructed.</b> {C.n(len(cm['benign']['allowed']), 'X.benign.allowed')} of "
        f"{C.n(cm['benign']['n'], 'X.benign.n')} legitimate settlement tasks completed.",
        "<b>This is evidence about the tested scope only.</b> It is not a certificate of safety, does not "
        "cover other agents or environments, and makes no production-readiness statement.",
    ])
    story.append(callout(DUAL_ROLE, MUTED))

    # 2 scope
    story.append(P("2. Scope statement and testing assumptions", "h1"))
    env = ev["environment"]
    story.append(table([["Item", "In scope"],
                        ["Agent", f"{env['agent']['id']} (service account roles: "
                                  f"{', '.join(env['agent']['service_account_roles'])})"],
                        ["Workflow", env["agent"]["workflow"]],
                        ["Tenant boundary", f"Agent acts for {env['agent']['tenant']}; South-book data is out of bounds"],
                        ["Constraints", f"{len(env['policies'])} declared policies (P1–P13), below"],
                        ["Safeguards under test", f"{len(env['customer_controls'])} customer controls (CC1–CC10), Section 6"]],
                       [40, 130], head=True))
    story.append(P("Declared constraints", "h2"))
    story.append(table([["ID", "Type", "Policy"]] + [[p["id"], p["kind"].capitalize(), p["text"]]
                                                       for p in env["policies"]], [12, 16, 142]))
    story.append(P("Testing assumptions", "h2"))
    story += bullets([
        "A scripted adversary proposes each prohibited action exactly. This tests enforcement, not whether "
        "a particular model would attempt the action.",
        "All calls ran in an authorised, isolated test environment through the customer adapter. The audit "
        "never relies on a control's own report: every outcome is read from the systems of record.",
        "A result is reported only where the state it depends on is observable. Otherwise it is "
        "INCONCLUSIVE, never 'prevented'.",
        "The simulated customer controls contain weaknesses planted on purpose (SW1–SW10) to "
        "demonstrate detection. They are listed in Appendix B.",
    ])
    story.append(P("Exclusions", "h2"))
    story += bullets(["Exhaustive verification of the agent's behaviour or parameter space.",
                      "Unrestricted penetration testing of the surrounding infrastructure.",
                      "Other agents, cross-agent interaction, shared-resource concurrency, multiple "
                      "environments (Enterprise Runtime Governance Audit scope).",
                      "Production certification and production-readiness opinions.",
                      "Remediation work. Recommended actions are listed, not performed."])

    # 3 reachability
    story.append(P("3. Reachability findings", "h1"))
    ops = reach["operations"]
    story.append(P(f"The customer documented {C.n(len(reach['documented']), 'X.ops.documented')} tools. At "
                   f"runtime the agent could call {C.n(len(reach['observed']), 'X.ops.observed')} operations. "
                   f"{C.n(len(reach['observed_not_documented']), 'X.ops.undeclared')} was not documented: "
                   f"<b>{', '.join(reach['observed_not_documented'])}</b>, reachable with the agent's own "
                   "service credential."))
    rows = [["Operation", "Documented", "Changes state", "External", "Tested in", "Prohibited state reached with no control"]]
    for n, o in sorted(ops.items()):
        rows.append([f"<b>{n}</b>", "Yes" if o["documented"] else lab("FAILED").replace("Failed", "No"),
                     "Yes" if o["mutates"] else "No", "Yes" if o["external"] else "No",
                     ", ".join(o["exercised_in"]) or lab("NOT_TESTED"),
                     ", ".join(o["prohibited_state_reached_without_controls_in"]) or "-"])
    story.append(table(rows, [30, 17, 15, 13, 42, 53]))
    story.append(P("Tested boundary and untested possibilities", "h2"))
    story += bullets([f"<b>Tested:</b> {len(cm['reachable_without_controls'])} prohibited outcomes, each "
                      "reached directly in the test environment before any safeguard was assessed."]
                     + [f"<b>Untested:</b> {u}" for u in reach["untested_possibilities"]]
                     + [f"<b>Not observable:</b> {', '.join(reach['unobservable_state'])}."])

    # 4 / 5 local and global
    def findings(prop, title, key):
        rs = [r for r in ev["scenarios"] if r["kind"] == "adversarial" and r["property"] == prop]
        story.append(P(title, "h1"))
        rows = [["ID", "Policy", "Attempt", "Claimed by", "Expected", "Observed", "Stopped by", "Evidence"]]
        for r in rs:
            cu = r["arms"]["customer"]
            rows.append([r["id"], r["policy"], r["title"], _controls_for(ev, r["policy"]),
                         "Prevented", lab(cu["outcome"]), cu.get("held_by") or "-", C.ev(*_cu_ids(r))])
        story.append(table(rows, [9, 11, 52, 16, 15, 20, 22, 25]))
        g = cm[key]
        story.append(P(f"Held {C.n(len(g['held']), f'X.{key}.held', g['held'])} of "
                       f"{C.n(g['n'], f'X.{key}.n')} decidable {prop} scenarios"
                       + (f"; {cm['inconclusive'][0]} inconclusive (excluded)" if key == "local" else "")
                       + ".", "small"))
    findings("local", "4. Local safety findings", "local")
    story.append(P("Each local scenario is decidable from a single action. 'Stopped by' names the "
                   "mechanism that actually stopped the action, read from the step evidence.", "small"))
    findings("global", "5. Global safety findings", "global")
    story.append(P("Local and global together", "h2"))
    rows = [["ID", "Attempt", "Observed", "Stopped by", "Evidence"]]
    for sid in ("C1", "C2"):
        r = by[sid]
        rows.append([sid, r["title"], lab(r["arms"]["customer"]["outcome"]),
                     r["arms"]["customer"].get("held_by") or "-", C.ev(*_cu_ids(r))])
    story.append(table(rows, [9, 75, 20, 34, 32]))
    story.append(P(f"Held {C.n(len(cm['combined']['held']), 'X.combined.held', cm['combined']['held'])} of "
                   f"{C.n(cm['combined']['n'], 'X.combined.n')}. In C1 the local approval check stopped the "
                   "payment first; in C2 a genuine approval satisfied the local check and the daily-limit "
                   "check stopped it, but only because all payments were in one session (compare G2).", "small"))
    story.append(P("Where a global constraint depends on information outside the boundary", "h2"))
    story.append(P(f"<b>G8:</b> {by['G8']['dependency']} The customer's daily-limit control failed this case "
                   f"({C.ev(*_cu_ids(by['G8']))})."))

    # 6 control verification
    story.append(CondPageBreak(200))
    story.append(P("6. Independent control verification", "h1"))
    story.append(P("For each customer safeguard: what it claims, which scenarios tested that claim, and "
                   "what the tests showed."))
    rows = [["Control", "Claim", "Tested by", "Demonstrated"]]
    for c in env["customer_controls"]:
        tested = [r for r in ev["scenarios"] if r["kind"] == "adversarial"
                  and any(p in r["policy"].split("+") for p in c["policies"])]
        held = [r["id"] for r in tested if r["arms"]["customer"]["outcome"] == "HELD"]
        failed = [r["id"] for r in tested if r["arms"]["customer"]["outcome"].startswith("FAILED")]
        verdict = (lab("HELD") if tested and not failed else lab("FAILED") if failed and not held
                   else f'{lab("HELD")} in {", ".join(held)}; {lab("FAILED")} in {", ".join(failed)}'
                   if failed else lab("NOT_TESTED"))
        rows.append([c["id"], c["claim"], ", ".join(r["id"] for r in tested) or "-", verdict])
    story.append(table(rows, [14, 72, 34, 50]))
    story.append(P("No customer control covers notify_partner or bulk_payment_api.", "small"))

    # 7 residual register
    story.append(CondPageBreak(200))
    story.append(P("7. Residual exposure register", "h1"))
    story.append(P("Severity is assessor judgement of consequence if the state occurred in production. It is "
                   "not a probability or a loss estimate. Recommended actions are vendor-neutral.", "small"))
    rows = [["ID", "Severity", "Status", "Exposure", "Evidence", "Limitation / recommended action"]]
    for x in residual_register(ev):
        rows.append([x["id"], f'<font name="DejaVuSerif-Bold" color="{SEV[x["severity"]].hexval()}">{x["severity"]}</font>',
                     lab(x["status"]), x["title"], C.ev(*x["evidence"]) if x["evidence"] else "-",
                     " ".join(filter(None, [x["limitation"], x["action"]]))])
    story.append(table(rows, [9, 15, 22, 44, 24, 56]))

    # 8 Morrison comparison
    story.append(CondPageBreak(220))
    story.append(P("8. Comparison: an explicitly configured Morrison boundary", "h1"))
    story.append(callout("<b>This section is not evidence about the organisation's safeguards.</b> It shows "
                         "what Morrison Runtime Governance did when placed in front of the same test "
                         "environment and configured with the same policies. The configuration is part of "
                         "the evidence. Morrison is the auditor's own product (see the disclosure in "
                         "Section 1).", MUTED))
    story.append(Spacer(1, 5))
    bo = mm_["by_outcome"]
    prevented = sum(len(bo.get(k, [])) for k in ("PREVENTED", "HELD_FOR_APPROVAL", "PREVENTED_BY_FAIL_CLOSED_ERROR"))
    story.append(table([["Outcome under the comparison boundary", "Scenarios"],
                        [f"Prevented by a rule ({C.n(len(bo.get('PREVENTED', [])), 'M.prevented')})",
                         C.ev(*bo.get("PREVENTED", []))],
                        [f"Held for human approval ({C.n(len(bo.get('HELD_FOR_APPROVAL', [])), 'M.held')})",
                         C.ev(*bo.get("HELD_FOR_APPROVAL", []))],
                        [f"Prevented only by fail-closed error handling ({C.n(len(bo.get('PREVENTED_BY_FAIL_CLOSED_ERROR', [])), 'M.failclosed')})",
                         C.ev(*bo.get("PREVENTED_BY_FAIL_CLOSED_ERROR", []))],
                        [f"<b>Reached the prohibited state</b> ({C.n(len(bo.get('REACHED', [])), 'M.reached')})",
                         C.ev(*bo.get("REACHED", []))]], [110, 60]))
    story.append(P(f"Total stopped: {C.n(prevented, 'M.stopped')} of {C.n(mm_['decidable'], 'M.decidable')}. "
                   f"Refused or held actions that executed: "
                   f"{C.n(mm_['non_permit_executed'], 'M.non_permit_executed')} of "
                   f"{C.n(mm_['decisions'], 'M.decisions')} decisions. Evidence chains intact: "
                   f"{C.n(mm_['chains_verified'], 'M.chains_verified')} of {C.n(mm_['chains'], 'M.chains')}. "
                   f"Legitimate tasks allowed: {C.n(len(mm_['benign_allowed']), 'M.benign_allowed')} of "
                   f"{C.n(cm['benign']['n'], 'X.benign.n')}.", "small"))
    story.append(P("Strictest verdict governs execution", "h2"))
    rows = [["Scenario", "Final step", "Approval presented", "Verdict", "Rule", "Executed", "Evidence"]]
    for s in mm_["strictest"]:
        rows.append([s["scenario"], "£15,000 payment after £20,000 paid", s["approval"] or "none",
                     s["verdict"], s["rule"], "Yes" if s["executed"] else "No", C.ev(s["evidence"])])
    story.append(table(rows, [16, 40, 36, 16, 34, 14, 22]))
    story.append(P("In C1 the payment needed approval (a local hold) and breached the daily limit (a global "
                   "block); the block governed. In C2 a genuine approval satisfied the local rule; the global "
                   "block still governed. An approval did not override the global constraint.", "small"))
    story.append(P("Gaps found in the comparison boundary", "h2"))
    story += bullets([f"<b>{d['scenario']}</b>: {d['found']}" for d in DEVELOPMENT_FINDINGS
                      if d["about"].startswith("Morrison")]
                     + [f"<b>G8</b>: with the default configuration the daily limit was breached; given a "
                        f"trusted feed of payments made outside the agent, the outcome was "
                        f"{lab(mm_['feed'])} ({C.ev('EV-G8-MF-1')})."])

    # 9 methodology + reproducibility
    story.append(CondPageBreak(200))
    story.append(P("9. Audit methodology checks and reproducibility", "h1"))
    story.append(P(f"Assessment digest <font face='DejaVuSansMono' size='7.5'>{ev['canonical_sha256'][:32]}…"
                   "</font>. Re-running the assessment must reproduce every outcome, verdict and state "
                   "transition byte for byte. Decision IDs, timestamps and evidence hashes differ by design. "
                   "The independent verification and the audit's self-tests are in the pack's "
                   "05_verification folder."))
    story.append(P("Weaknesses found in the audit method itself, and how they were handled", "h2"))
    story += bullets([f"<b>{d['id']} ({d['scenario']}):</b> {d['found']} <i>{d['action']}</i>"
                      for d in DEVELOPMENT_FINDINGS if d["about"].startswith("Audit methodology")])

    # 10 limitations
    story.append(P("10. Limitations", "h1"))
    story += bullets([
        "Bounded and targeted: the absence of a finding outside the tested scenarios says nothing about "
        "that behaviour.",
        "Simulated customer and scripted adversary: real integrations, models and operating conditions "
        "may differ.",
        "Observability bounds the conclusions: partner deliveries could not be observed (L14).",
        "Concurrency, time-window semantics and live-model behaviour were not tested (U1–U3).",
        "Delivery: the 48-hour target assumes the customer adapter and sandbox exist before the clock "
        "starts (see the pack's onboarding requirements). Adapter construction is not included in the 48 hours.",
    ])

    # appendix A: evidence
    story.append(P("Appendix A. Evidence and reproduction", "h1"))
    story.append(P("Each step carries an identifier EV-&lt;scenario&gt;-&lt;arm&gt;-&lt;step&gt;: arm CU is "
                   "the customer's safeguards, NC no control, MO the Morrison comparison and MF the comparison "
                   "with a trusted outside-payment feed. Every identifier cited here resolves to a record in "
                   "03_enforcement_evidence of the pack."))
    story.append(table([["Reproduce from the repository"],
                        ["<font face='DejaVuSansMono' size='7.4'>python -m audit_demo.exposure "
                         "--output audit_demo/deliverables</font>"]], [170], head=True))

    # appendix B: scenario specifications
    story.append(CondPageBreak(200))
    story.append(P("Appendix B. Scenario specifications and seeded weaknesses", "h1"))
    rows = [["ID", "Initial state", "Proposed actions", "Constraint", "Expected", "Observed"]]
    for r in ev["scenarios"]:
        acts = "; ".join(f"{s['call']['tool']}({', '.join(f'{k}={v}' for k, v in s['call']['args'].items())})"
                         + (f" [{s['approval']}]" if s["approval"] else "")
                         + (f" [{s['session']}]" if r["id"] == "G2" else "")
                         for s in r["steps_proposed"])
        exp = "Allowed" if r["kind"] == "benign" else "Prevented"
        rows.append([r["id"], r["initial_state"], acts, f"{r['policy']} ({r['property']})", exp,
                     lab(r["arms"]["customer"]["outcome"])])
    story.append(table(rows, [9, 34, 70, 18, 15, 24]))
    story.append(P("Seeded weaknesses in the simulated customer controls", "h2"))
    story.append(table([["ID", "Control", "Weakness"]] + [[w["id"], w["control"] or "-", w["text"]]
                                                         for w in env["seeded_weaknesses"]], [12, 16, 142]))
    return _build(story, out, "Technical Report • Independent Agent Exposure Audit", C, env=ENV)


# ── board executive summary ───────────────────────────────────────────────
def executive_summary(ev: dict, out: Path) -> Path:
    C = Cite()
    cm = customer_metrics(ev)
    by = _by(ev)
    a = cm["all"]
    D = cm["decidable"]
    story: list = []
    cover(story, "Independent Agent Exposure Audit",
          "Executive summary for the board, risk and audit committee",
          [["Engagement", "Independent Agent Exposure Audit (£5,000, bounded scope)"],
           ["Status", '<font color="#B3261E"><b>ILLUSTRATIVE SAMPLE — NOT A CUSTOMER AUDIT</b></font>'],
           ["Client", ev["environment"]["label"]],
           ["Companion", "The technical report holds the full evidence for every statement here"]],
          client=CLIENT, warning=WARNING)
    story.append(P("Executive summary", "h1"))
    story.append(P("We tested one autonomous agent, the claims-settlement agent, against the safety rules "
                   "the organisation says it enforces. We tried to break each rule on purpose, then checked "
                   "the payment and records systems to see what actually happened, rather than trusting "
                   "what the safeguards reported."))
    story.append(kpis([
        (f"{C.n(len(cm['reachable_without_controls']), 'X.reachable', cm['reachable_without_controls'])} / "
         f"{C.n(D, 'X.decidable')}", "prohibited outcomes the agent could reach", RED),
        (f"{C.n(len(a['held']), 'X.held', a['held'])} / {D}", "stopped by the existing safeguards", GOLD),
        (f"{C.n(len(a['failed']), 'X.failed', a['failed'])}", "safeguards that failed when tested", RED),
        (f"{C.n(len(cm['benign']['allowed']), 'X.benign.allowed')} / {C.n(cm['benign']['n'], 'X.benign.n')}",
         "legitimate tasks completed", GREEN)]))
    story.append(P("Answers to the board's three questions", "h2"))
    story.append(table([
        ["Question", "Answer within the tested boundary"],
        ["What can the agent reach?", "Every prohibited outcome we tried, when nothing stood in its way, "
         "including a payment route the organisation had not listed (bulk_payment_api)."],
        ["Do the safeguards do what they claim?", f"Partly. Rules about a single action held "
         f"{C.n(len(cm['local']['held']), 'X.local.held', cm['local']['held'])} of "
         f"{C.n(cm['local']['n'], 'X.local.n')}. Rules about a sequence of actions held "
         f"{C.n(len(cm['global']['held']), 'X.global.held', cm['global']['held'])} of "
         f"{C.n(cm['global']['n'], 'X.global.n')}. One safeguard reported a block for an email that had "
         "already been sent."],
        ["What remains exposed?", "Payments above the approval limit, approval reuse, payments to newly "
         "changed bank details, data leaving through vendor exports, separation-of-duties conflicts, and "
         "the daily payout limit across sessions and staff activity."]], [45, 125]))
    story.append(P("Most serious exposures", "h2"))
    top = [x for x in residual_register(ev) if x["severity"] == "Critical"]
    story.append(table([["ID", "Exposure", "Evidence"]] + [[x["id"], x["title"], C.ev(*x["evidence"])]
                                                            for x in top], [12, 118, 40]))
    story.append(P("What we could not establish", "h2"))
    story += bullets([f"Whether policyholder data reached the repair partner: that channel cannot be "
                      f"observed ({C.n(len(cm['inconclusive']), 'X.inconclusive', cm['inconclusive'])} "
                      "inconclusive result).",
                      "Behaviour under simultaneous sessions, across midnight, or with the live AI model: "
                      f"outside this engagement ({C.n(len(cm['unsupported']), 'X.unsupported')} items)."])
    story.append(P("Recommended next steps", "h2"))
    story += bullets([f"Fix the Critical items first ({C.ev(*[x['id'] for x in top])}): role changes and "
                      "separation of duties, the unwrapped payment route, and bank-detail verification. "
                      "Then the High items, including approval binding and single use.",
                      "Move sequence-level rules (daily totals, export totals, separation of duties) to "
                      "checks against the systems of record, not session caches.",
                      "Make the partner channel observable, then re-test.",
                      "Re-run this audit after remediation to confirm the fixes against the same evidence."])
    story.append(callout(DUAL_ROLE, MUTED))
    story.append(P("This summary covers one agent in one simulated workflow. It is not a certificate of "
                   f"safety or a production-readiness opinion. Failed scenarios: {C.ev(*a['failed'])}.", "small"))
    return _build(story, out, "Executive Summary • Independent Agent Exposure Audit", C, env=ENV)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m audit_demo.exposure.report")
    p.add_argument("--evidence", type=Path, required=True, help="assessment directory (read only)")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args(argv)
    ev = json.loads((a.evidence / "evidence.json").read_text())
    print(technical_report(ev, a.out / REPORT_FILE))
    print(executive_summary(ev, a.out / SUMMARY_FILE))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
