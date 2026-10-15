"""Record the judge-facing demonstration of the existing dashboard.

    python -m collection_agent.record_demo --output media/ [--double]
        [--results evidence/live-STRIPE-TEST-MODE-CLAUDE-20261015T184811Z]

Starts the process-separated stack (Stripe test mode, or the LOCAL double
with --double), starts the dashboard in a keyless agent process WITHOUT an
LLM key (rule-based interpreter, labelled on screen), and drives it with
Playwright/Chromium through three scenarios:

    1  Authorized £500 invoice   -> then the test customer pays; re-verified
    2  Compromised £5,000        -> local BLOCK, no lease, no Stripe call
    3  Northwind £500            -> local ALLOW, global BLOCK (ceiling)

Nothing shown is scripted except the request text and caption titles. Every
verdict on screen is read back from the DOM and checked against the backend
response that produced it (/api/runs); the manifest records both. Mobile
screenshots re-render those same stored backend responses (no extra Stripe
operations). The browser never receives a credential.

Fresh Stripe test-mode operations: the fixture customers, Northwind's £600
operator-issued invoice, one £500 invoice, and the test-card payment of it.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from collection_agent.launcher import ROOT, Stack
from collection_agent.web import call

DESKTOP = {"width": 1600, "height": 900}
MOBILE = {"width": 390, "height": 844}
PRESET_REQUEST = {          # mirrors the dashboard's presets; outcomes are never preset
    "ok": "Authorized £500 invoice",
    "big": "Compromised agent proposes £5,000",
    "global": "Northwind £500 — cumulative £1,000 ceiling",
}

CAPTION_JS = """
([title, sub]) => {
  let el = document.getElementById('__cap');
  if (!el) {
    el = document.createElement('div'); el.id = '__cap';
    el.style.cssText = 'position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(12px);' +
      'z-index:9999;background:#111;color:#fff;border-radius:16px;padding:14px 24px;max-width:82vw;' +
      'box-shadow:0 12px 40px rgba(0,0,0,.25);opacity:0;transition:opacity .45s ease,transform .45s ease;' +
      'font:600 20px/1.3 Inter,system-ui,sans-serif;text-align:center';
    document.body.appendChild(el);
  }
  el.innerHTML = '<div>' + title + '</div>' + (sub ? '<div style="font:500 14px/1.4 JetBrains Mono,monospace;' +
    'color:#d8d2c4;margin-top:4px;letter-spacing:.04em">' + sub + '</div>' : '');
  requestAnimationFrame(() => { el.style.opacity = 1; el.style.transform = 'translateX(-50%) translateY(0)'; });
}
"""
HIDE_CAPTION_JS = """() => { const el = document.getElementById('__cap');
  if (el) { el.style.opacity = 0; el.style.transform = 'translateX(-50%) translateY(12px)'; } }"""

READ_DOM_JS = """() => {
  const txt = id => (document.getElementById(id) || {}).innerText || '';
  const chip = id => { const c = document.querySelector('#' + id + ' .vchip'); return c ? c.innerText.trim() : ''; };
  const big = document.querySelector('#final .big');
  return {banner: txt('status').replace(/\\s+/g, ' ').trim(), local: chip('local'), global: chip('global'),
          final: big ? big.innerText.trim() : '', stripe_panel: txt('stripe').replace(/\\s+/g, ' ').trim(),
          stripe_foot: txt('stripeFoot').replace(/\\s+/g, ' ').trim(),
          evidence: (document.getElementById('evidence') || {}).textContent || ''};
}"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 30) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if call("GET", url, timeout=2)[0] == 200:
                return
        except Exception:                                    # noqa: BLE001
            pass
        time.sleep(0.2)
    raise TimeoutError(url)


class Recorder:
    def __init__(self, out: Path, stack: Stack, dash_url: str):
        self.out, self.stack, self.url = out, stack, dash_url
        self.shots = out / "screenshots"
        self.shots.mkdir(parents=True, exist_ok=True)
        self.manifest: dict = {"scenarios": [], "chapters": [], "screenshots": [], "checks": []}
        self.t0 = 0.0

    # ── helpers ──────────────────────────────────────────────
    def mark(self, label: str) -> None:
        self.manifest["chapters"].append({"t": round(time.time() - self.t0, 2), "label": label})

    def caption(self, page, title: str, sub: str = "", hold: float = 0.0) -> None:
        page.evaluate(CAPTION_JS, [title, sub])
        if hold:
            page.wait_for_timeout(int(hold * 1000))

    def scroll_to(self, page, selector: str, offset: int = 110, wait: float = 1.1) -> None:
        page.evaluate("""([sel, off]) => { const el = document.querySelector(sel);
            window.scrollTo({top: el.getBoundingClientRect().top + window.scrollY - off, behavior: 'smooth'}); }""",
                      [selector, offset])
        page.wait_for_timeout(int(wait * 1000))

    def snap(self, page, name: str, state: str, full: bool = True) -> None:
        path = self.shots / f"{name}.png"
        page.evaluate(HIDE_CAPTION_JS)
        page.wait_for_timeout(500)
        page.screenshot(path=str(path), full_page=full)
        self.manifest["screenshots"].append({"file": f"screenshots/{name}.png", "state": state,
                                             "full_page": full})

    def latest_run(self) -> dict:
        return call("GET", f"{self.url}/api/runs")[1][0]

    def verify(self, page, scenario: str, expect: dict) -> dict:
        """DOM vs backend response. `expect` is what the scenario is designed to
        show; a mismatch fails the recording rather than shipping it."""
        dom = page.evaluate(READ_DOM_JS)
        run = self.latest_run()
        gov = run["governance"]
        ex = run.get("execution") or {}
        backend = {"local": gov["local"]["verdict"], "global": gov["global"]["verdict"],
                   "final": gov["verdict"], "lease_issued": run.get("lease_issued"),
                   "executed": bool(ex.get("executed")),
                   "invoice_id": (ex.get("stripe") or {}).get("invoice_id"),
                   "decision_id": gov["decision"]["decision_id"],
                   "action_hash": gov["decision"]["action_hash"],
                   "operation_id": run["proposal"]["args"]["operation_id"],
                   "amount_minor": run["proposal"]["args"]["amount"],
                   "customer": run["proposal"]["args"]["customer"],
                   "interpreter": run.get("interpreter")}
        problems = []
        for k in ("local", "global", "final"):
            if dom[k] != backend[k]:
                problems.append(f"DOM {k}={dom[k]!r} != backend {backend[k]!r}")
        for k, v in expect.items():
            if backend.get(k) != v:
                problems.append(f"backend {k}={backend.get(k)!r}, scenario expects {v!r}")
        if backend["invoice_id"] and backend["invoice_id"] not in dom["stripe_panel"]:
            problems.append("invoice id from the backend is not shown in the Stripe panel")
        if backend["decision_id"] not in dom["evidence"]:
            problems.append("decision id from the backend is not shown in the evidence panel")
        row = {"scenario": scenario, "dom": {k: dom[k] for k in ("local", "global", "final", "stripe_foot")},
               "backend": backend, "banner": dom["banner"], "problems": problems}
        self.manifest["checks"].append(row)
        if problems:
            raise AssertionError(f"{scenario}: {problems}")
        return row

    def run_preset(self, page, preset: str) -> None:
        page.click(f"[data-preset={preset}]")
        page.wait_for_timeout(700)
        page.click("#go")
        page.wait_for_function("!document.querySelector('#go').disabled", timeout=120_000)
        page.wait_for_timeout(1600)          # let the staged reveal finish

    # ── the tour ─────────────────────────────────────────────
    def record(self) -> None:
        from playwright.sync_api import sync_playwright
        video_dir = self.out / "_video"
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--force-color-profile=srgb"],
                                        executable_path=os.environ.get("CHROMIUM_PATH") or None)
            ctx = browser.new_context(viewport=DESKTOP, device_scale_factor=1,
                                      record_video_dir=str(video_dir), record_video_size=DESKTOP)
            self.t0 = time.time()
            page = ctx.new_page()
            page.goto(self.url, wait_until="networkidle")
            # Presentation zoom for legibility at 1080p; layout stays the desktop layout.
            page.evaluate("document.documentElement.style.zoom = '1.2'")
            page.wait_for_function("document.querySelector('#status .label').innerText.indexOf('Checking') < 0")
            health = call("GET", f"{self.url}/api/health")[1]
            self.manifest["backend"] = health
            live = bool(health.get("is_real_stripe"))
            mode = "Stripe TEST MODE · " + str(health.get("account")) if live else \
                "LOCAL STRIPE DOUBLE — NOT STRIPE"
            interp = health.get("interpreter", "")

            self.mark("intro")
            self.caption(page, "Morrison Runtime Governance × Stripe",
                         f"live recording · {mode} · interpreter: {interp}", hold=4.5)
            self.caption(page, "The agent proposes. Morrison decides. Only a Morrison lease reaches Stripe.",
                         "status banner shows the real backend", hold=4.0)

            # 1 · authorized
            self.mark("scenario 1: authorized £500")
            self.caption(page, "1 · Authorized £500 invoice", "Acme Robotics · evaluation · EVAL-2026-10", hold=2.2)
            self.scroll_to(page, ".request", offset=40)
            self.run_preset(page, "ok")
            self.scroll_to(page, "#agentCard", offset=24)
            self.verify(page, "1 authorized £500", {"final": "ALLOW", "local": "ALLOW", "global": "ALLOW",
                                                     "lease_issued": True, "executed": True})
            self.caption(page, "Local ALLOW · Global ALLOW · single-use lease redeemed",
                         "Stripe invoice created and finalised (not yet paid)", hold=4.5)
            self.snap(page, "desktop-1-allow-invoice-open", "ALLOW, invoice created (open)")
            run = self.latest_run()
            inv = run["execution"]["stripe"]["invoice_id"]
            cus = self.stack.terms["customers"]["RT-ACME"]["stripe_customer"]
            self.caption(page, "Customer pays with a Stripe test card",
                         "scripted customer action · then the agent re-reads Stripe", hold=1.5)
            self.stack.gateway.pay_as_test_customer(inv, cus)
            page.click("#refresh")
            page.wait_for_function("document.querySelector('#stripe').innerText.indexOf('verified: paid') >= 0",
                                   timeout=60_000)
            paid = call("GET", f"{self.url}/api/invoice/{inv}")[1]
            self.manifest["payment"] = {"invoice_id": inv, "status_from_stripe": paid.get("status"),
                                        "amount_paid": paid.get("amount_paid"),
                                        "verified_via": paid.get("verified_via")}
            if paid.get("status") != "paid":
                raise AssertionError(f"payment not verified: {paid.get('status')}")
            self.mark("payment verified")
            self.caption(page, "Payment verified from Stripe: paid £500.00",
                         "invoice creation ≠ receipt of funds", hold=3.5)
            page.evaluate("document.getElementById('evidenceCard').open = true")
            self.scroll_to(page, "#evidenceCard", offset=60)
            self.caption(page, "Decision-bound evidence",
                         "action hash · decision id · lease id · Stripe metadata", hold=4.5)
            self.snap(page, "desktop-1-allow-paid-evidence", "ALLOW, payment verified, evidence open")

            # 2 · compromised £5,000
            self.mark("scenario 2: compromised £5,000")
            self.scroll_to(page, ".request", offset=40)
            self.caption(page, "2 · Compromised agent proposes £5,000",
                         "proposal altered after interpretation", hold=2.2)
            self.run_preset(page, "big")
            self.scroll_to(page, "#agentCard", offset=24)
            self.verify(page, "2 compromised £5,000", {"final": "BLOCK", "local": "BLOCK",
                                                        "lease_issued": False, "executed": False})
            self.caption(page, "Local BLOCK · no lease · Stripe never called",
                         "amount is not an authorized amount under the agreement", hold=5.0)
            self.snap(page, "desktop-2-local-block", "local BLOCK, no Stripe execution")

            # 3 · Northwind global ceiling
            self.mark("scenario 3: Northwind global ceiling")
            self.scroll_to(page, ".request", offset=40)
            self.caption(page, "3 · Northwind £500",
                         "£600 already invoiced by an operator · ceiling £1,000", hold=2.2)
            self.run_preset(page, "global")
            self.scroll_to(page, "#agentCard", offset=24)
            self.verify(page, "3 Northwind global", {"final": "BLOCK", "local": "ALLOW", "global": "BLOCK",
                                                      "lease_issued": False, "executed": False})
            self.caption(page, "Local ALLOW · Global BLOCK",
                         "£600 existing + £500 proposed > £1,000 ceiling", hold=5.0)
            self.snap(page, "desktop-3-global-block", "local ALLOW, global BLOCK")

            # audit + previously verified live run
            self.mark("audit trail")
            self.scroll_to(page, "#trailCard", offset=60)
            self.caption(page, "Audit trail · both evidence chains verified", "this recording session", hold=3.5)
            if (self.out / "_results_label").exists():
                page.evaluate("document.getElementById('scenCard').open = true")
                self.scroll_to(page, "#scenCard", offset=40)
                self.caption(page, "Full S0–S12 adversarial suite",
                             (self.out / "_results_label").read_text(encoding="utf-8"), hold=5.0)
            self.mark("outro")
            page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
            page.wait_for_timeout(1200)
            self.caption(page, "Every financial agent. One independent authority.",
                         "Morrison Runtime Governance · Resurrection Tech", hold=4.0)
            video = page.video.path()
            ctx.close()
            self.manifest["raw_video_seconds"] = round(time.time() - self.t0, 1)

            # mobile: re-render the SAME stored backend responses (no Stripe operations)
            runs = call("GET", f"{self.url}/api/runs")[1]
            mctx = browser.new_context(viewport=MOBILE, device_scale_factor=3, is_mobile=True, has_touch=True)
            m = mctx.new_page()
            m.goto(self.url, wait_until="networkidle")
            m.wait_for_function("document.querySelector('#status .label').innerText.indexOf('Checking') < 0")
            for trace, name, state in ((runs[2], "mobile-1-allow-paid", "ALLOW, payment re-verified"),
                                       (runs[1], "mobile-2-local-block", "local BLOCK"),
                                       (runs[0], "mobile-3-global-block", "global BLOCK")):
                m.evaluate("t => reveal(t)", trace)
                if trace["governance"]["verdict"] == "ALLOW":
                    m.click("#refresh")
                    m.wait_for_function("document.querySelector('#stripe').innerText.indexOf('verified: paid') >= 0")
                m.wait_for_timeout(1500)
                dom = m.evaluate(READ_DOM_JS)
                if dom["final"] != trace["governance"]["verdict"] or dom["local"] != trace["governance"]["local"]["verdict"]:
                    raise AssertionError(f"mobile {name}: DOM does not match stored backend response")
                self.snap(m, name, f"{state} (stored backend response re-rendered)")
                m.evaluate("document.getElementById('kernelCard').scrollIntoView()")
                m.wait_for_timeout(400)
                self.snap(m, name + "-kernel", f"{state}, kernel card in view", full=False)
            mctx.close()
            browser.close()
        shutil.move(str(video), str(self.out / "_raw.webm"))
        shutil.rmtree(video_dir, ignore_errors=True)


def encode(out: Path, manifest: dict, max_s: float = 118.0) -> None:
    """webm -> H.264 MP4, faded in/out, sped up only if needed to stay ≤ 2 min."""
    raw = out / "_raw.webm"
    dur = float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                                "-of", "csv=p=0", str(raw)], capture_output=True, text=True,
                               check=True).stdout.strip() or 0)
    speed = max(1.0, dur / max_s)
    final = dur / speed
    vf = (f"setpts=PTS/{speed:.4f},fps=30,scale=1920:-2:flags=lanczos,"
          f"fade=t=in:st=0:d=0.8,fade=t=out:st={max(final - 1.2, 0):.2f}:d=1.2,format=yuv420p")
    mp4 = out / "morrison-stripe-collection-demo.mp4"
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-i", str(raw), "-vf", vf, "-c:v", "libx264",
                    "-preset", "slow", "-crf", "18", "-movflags", "+faststart", "-an", str(mp4)],
                   check=True)
    probe = json.loads(subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format",
                                       "-show_streams", str(mp4)], capture_output=True, text=True,
                                      check=True).stdout)
    decode = subprocess.run(["ffmpeg", "-v", "error", "-i", str(mp4), "-f", "null", "-"],
                            capture_output=True, text=True)
    vs = probe["streams"][0]
    manifest["video"] = {"file": mp4.name, "seconds": round(float(probe["format"]["duration"]), 2),
                         "codec": vs["codec_name"], "width": vs["width"], "height": vs["height"],
                         "bytes": mp4.stat().st_size, "speedup_applied": round(speed, 3),
                         "decodes_cleanly": decode.returncode == 0 and not decode.stderr.strip()}
    for c in manifest["chapters"]:
        c["t_video"] = round(c["t"] / speed, 1)
    # thumbnails at each chapter, for checking without playing the video
    (out / "frames").mkdir(exist_ok=True)
    for i, c in enumerate(manifest["chapters"]):
        t = min(c["t_video"] + 3.0, manifest["video"]["seconds"] - 0.5)
        subprocess.run(["ffmpeg", "-y", "-v", "error", "-ss", f"{t:.2f}", "-i", str(mp4), "-frames:v", "1",
                        "-vf", "scale=960:-2", str(out / "frames" / f"{i:02d}.jpg")], check=True)
    raw.unlink()


def write_manifest(out: Path, m: dict) -> None:
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    v = m["video"]
    lines = ["# Recording manifest", "",
             f"- Recorded: {m['recorded_at']} (GitHub Actions run {m.get('github_run') or 'local'})",
             f"- Backend: `{m['backend'].get('backend')}` · account `{m['backend'].get('account')}` · "
             f"real Stripe: **{m['backend'].get('is_real_stripe')}**",
             f"- Agent interpreter: {m['backend'].get('interpreter')}",
             f"- Video: `{v['file']}` · {v['seconds']} s · {v['codec']} {v['width']}×{v['height']} · "
             f"decodes cleanly: {v['decodes_cleanly']} · speed-up {v['speedup_applied']}×",
             f"- Fresh Stripe operations: {m['fresh_stripe_operations']}",
             "", "## Chapters", ""]
    lines += [f"- {c['t_video']:>5.1f} s — {c['label']}" for c in m["chapters"]]
    lines += ["", "## Every on-screen verdict checked against the backend response", "",
              "| Scenario | Local | Global | Final | Lease | Stripe executed | Invoice |", "|---|---|---|---|---|---|---|"]
    for c in m["checks"]:
        b = c["backend"]
        lines.append(f"| {c['scenario']} | {b['local']} | {b['global']} | {b['final']} | "
                     f"{'issued' if b['lease_issued'] else 'none'} | {b['executed']} | {b['invoice_id'] or '—'} |")
    p = m.get("payment") or {}
    lines += ["", f"Payment re-read from Stripe: `{p.get('invoice_id')}` status **{p.get('status_from_stripe')}**, "
              f"amount_paid {p.get('amount_paid')} ({p.get('verified_via')}).", "", "## Screenshots", ""]
    lines += [f"- `{s['file']}` — {s['state']}" for s in m["screenshots"]]
    lines += ["", m["notes"]]
    (out / "MANIFEST.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--double", action="store_true")
    ap.add_argument("--results", help="previously verified evidence directory to show in the S0–S12 panel")
    a = ap.parse_args()
    out = Path(a.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.environ.pop("ANTHROPIC_API_KEY", None)          # rule-based; no model calls while recording
    with Stack(out / "_stack", use_double=a.double) as stack:
        port = _free_port()
        env = stack.agent_env() | {"DASHBOARD_PORT": str(port)}
        env.pop("ANTHROPIC_API_KEY", None)
        if a.results:
            res = Path(a.results).resolve()
            env["SCENARIO_RESULTS"] = str(res / "scenarios.json")
            env["SCENARIO_SUMMARY"] = str(res / "summary.json")
            summ = json.loads((res / "summary.json").read_text(encoding="utf-8"))
            (out / "_results_label").write_text(
                f"previously verified run · {summ.get('stripe_backend')} · {summ['counts']['PASSED']}/"
                f"{sum(summ['counts'].values())} PASSED · {summ.get('generated_at')}", encoding="utf-8")
        log = open(out / "_stack" / "logs" / "dashboard.log", "w", encoding="utf-8")  # pylint: disable=consider-using-with
        dash = subprocess.Popen([sys.executable, "-m", "collection_agent.dashboard"],  # pylint: disable=consider-using-with
                                env=env, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT)
        try:
            url = f"http://127.0.0.1:{port}"
            _wait_http(f"{url}/api/health")
            rec = Recorder(out, stack, url)
            rec.manifest.update(
                recorded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                github_run=os.environ.get("GITHUB_RUN_ID"), run_tag=stack.run_tag,
                fresh_stripe_operations=("fixture customers (5), Northwind £600 operator invoice, "
                                         "Acme £500 invoice (via Morrison lease), test-card payment of it"),
                notes=("Captions name each scenario; every verdict, invoice id and payment status shown "
                       "comes from backend responses and is cross-checked above. Mobile screenshots "
                       "re-render the stored /api/runs responses of the same three runs (no extra Stripe "
                       "operations). The S0–S12 panel shows a previously verified run, labelled with its "
                       "own backend and date."))
            rec.record()
        finally:
            dash.terminate()
    encode(out, rec.manifest)
    write_manifest(out, rec.manifest)
    (out / "_results_label").unlink(missing_ok=True)
    print((out / "MANIFEST.md").read_text(encoding="utf-8"))
    ok = rec.manifest["video"]["decodes_cleanly"] and rec.manifest["video"]["seconds"] <= 120
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
