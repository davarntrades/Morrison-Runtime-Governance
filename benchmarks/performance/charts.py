"""Static SVG charts for the benchmark report (no plotting dependency).

Palette: categorical slots 1-3 of the dataviz reference palette (blue,
orange, aqua), stepped separately for light and dark surfaces through CSS
variables. Every mark carries a <title> tooltip; multi-series charts have a
legend; text uses ink tokens, never series colour. A 1 ms reference line is
drawn where the target is 1 ms.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from benchmarks.performance.common import RESULTS

CSS = """<style>
.v{--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--grid:#e4e3df;
--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--ref:#e34948}
@media (prefers-color-scheme: dark){.v{--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;
--grid:#3a3a37;--s1:#3987e5;--s2:#d95926;--s3:#199e70;--ref:#e66767}}
.v text{font:12px system-ui,-apple-system,Segoe UI,sans-serif;fill:var(--ink2)}
.v .t{font-size:14px;font-weight:600;fill:var(--ink)}
</style>"""
W, H = 720, 380
L, R, T, B = 72, 160, 44, 52


def _svg(title: str, body: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" class="v" viewBox="0 0 {W} {H}" '
            f'role="img" aria-label="{title}">{CSS}'
            f'<rect width="{W}" height="{H}" fill="var(--surface)"/>'
            f'<text class="t" x="{L}" y="24">{title}</text>{body}</svg>')


def _ticks_log(lo, hi):
    out, e = [], math.floor(math.log10(lo))
    while 10 ** e <= hi * 1.0001:
        for m in (1, 2, 5):
            v = m * 10 ** e
            if lo <= v <= hi:
                out.append(v)
        e += 1
    return out


def _fmt(v):
    return f"{v / 1000:g} ms" if v >= 1000 else f"{v:g} µs"


def line_chart(path: Path, title: str, xs: list, series: list[tuple[str, list]],
               xlabel: str, ylabel: str, logx=True, logy=True, ref=None, yfmt=_fmt):
    allv = [v for _, ys in series for v in ys if v is not None and v > 0]
    lo, hi = min(allv + ([ref] if ref else [])), max(allv + ([ref] if ref else []))
    if logy:
        lo, hi = 10 ** math.floor(math.log10(lo)), 10 ** math.ceil(math.log10(hi))
    else:
        lo, hi = 0, hi * 1.1
    xv = [x if x > 0 else 0.5 for x in xs]
    xlo, xhi = min(xv), max(xv)

    def X(x):
        x = x if x > 0 else 0.5
        f = (math.log(x) - math.log(xlo)) / ((math.log(xhi) - math.log(xlo)) or 1) if logx \
            else (x - xlo) / ((xhi - xlo) or 1)
        return L + f * (W - L - R)

    def Y(y):
        f = (math.log(y) - math.log(lo)) / (math.log(hi) - math.log(lo)) if logy \
            else (y - lo) / (hi - lo)
        return H - B - f * (H - T - B)
    body = []
    ticks = _ticks_log(lo, hi) if logy else [hi * i / 5 for i in range(6)]
    for t in ticks:
        body.append(f'<line x1="{L}" x2="{W - R}" y1="{Y(t):.1f}" y2="{Y(t):.1f}" stroke="var(--grid)"/>'
                    f'<text x="{L - 6}" y="{Y(t) + 4:.1f}" text-anchor="end">{yfmt(t)}</text>')
    for x in xs:
        body.append(f'<text x="{X(x):.1f}" y="{H - B + 18}" text-anchor="middle">{x}</text>')
    body.append(f'<text x="{(L + W - R) / 2}" y="{H - 12}" text-anchor="middle">{xlabel}</text>'
                f'<text x="16" y="{(T + H - B) / 2}" transform="rotate(-90 16 {(T + H - B) / 2})" '
                f'text-anchor="middle">{ylabel}</text>')
    if ref:
        body.append(f'<line x1="{L}" x2="{W - R}" y1="{Y(ref):.1f}" y2="{Y(ref):.1f}" '
                    f'stroke="var(--ref)" stroke-dasharray="5 4" stroke-width="1.5"/>'
                    f'<text x="{W - R + 6}" y="{Y(ref) + 4:.1f}">1 ms target</text>')
    for k, (name, ys) in enumerate(series):
        col = f"var(--s{k + 1})"
        pts = [(X(x), Y(y), x, y) for x, y in zip(xs, ys) if y is not None and y > 0]
        body.append('<polyline fill="none" stroke-width="2" stroke="%s" points="%s"/>' % (
            col, " ".join(f"{a:.1f},{b:.1f}" for a, b, _, _ in pts)))
        for a, b, x, y in pts:
            body.append(f'<circle cx="{a:.1f}" cy="{b:.1f}" r="4" fill="{col}" stroke="var(--surface)" '
                        f'stroke-width="2"><title>{name} @ {x}: {yfmt(y)}</title></circle>')
        if pts:
            ly = T + 14 + 18 * k
            body.append(f'<rect x="{W - R + 8}" y="{ly - 9}" width="12" height="3" rx="1" fill="{col}"/>'
                        f'<text x="{W - R + 26}" y="{ly - 4}">{name}</text>')
    path.write_text(_svg(title, "".join(body)))


def stacked_bars(path: Path, title: str, xs: list, parts: list[tuple[str, list]],
                 xlabel: str, ylabel: str):
    totals = [sum(p[1][i] for p in parts) for i in range(len(xs))]
    hi = max(totals) or 1
    bw = (W - L - R) / len(xs) * 0.6
    body = []
    for i in range(6):
        v = 100 * i / 5
        y = H - B - (v / 100) * (H - T - B)
        body.append(f'<line x1="{L}" x2="{W - R}" y1="{y:.1f}" y2="{y:.1f}" stroke="var(--grid)"/>'
                    f'<text x="{L - 6}" y="{y + 4:.1f}" text-anchor="end">{v:g}%</text>')
    for i, x in enumerate(xs):
        cx = L + (i + 0.5) * (W - L - R) / len(xs)
        y0 = H - B
        for k, (name, vals) in enumerate(parts):
            share = vals[i] / totals[i] if totals[i] else 0
            h = share * (H - T - B)
            if h > 0:
                body.append(f'<rect x="{cx - bw / 2:.1f}" y="{y0 - h:.1f}" width="{bw:.1f}" '
                            f'height="{max(h - 2, 0.5):.1f}" fill="var(--s{k + 1})">'
                            f'<title>{name} @ {x}: {vals[i]} of {totals[i]} ({100 * share:.1f}%)</title></rect>')
            y0 -= h
        body.append(f'<text x="{cx:.1f}" y="{H - B + 18}" text-anchor="middle">{x}</text>')
    for k, (name, _) in enumerate(parts):
        ly = T + 14 + 18 * k
        body.append(f'<rect x="{W - R + 8}" y="{ly - 10}" width="12" height="10" rx="2" '
                    f'fill="var(--s{k + 1})"/><text x="{W - R + 26}" y="{ly - 1}">{name}</text>')
    body.append(f'<text x="{(L + W - R) / 2}" y="{H - 12}" text-anchor="middle">{xlabel}</text>'
                f'<text x="16" y="{(T + H - B) / 2}" transform="rotate(-90 16 {(T + H - B) / 2})" '
                f'text-anchor="middle">{ylabel}</text>')
    path.write_text(_svg(title, "".join(body)))


def main() -> int:
    out = RESULTS / "charts"
    out.mkdir(parents=True, exist_ok=True)
    lat = json.loads((RESULTS / "latency.json").read_text())
    sw = lat["history_sweep_full_decision"]
    hs = sorted(int(h) for h in sw)
    line_chart(out / "history_sweep.svg",
               "Full kernel decision latency vs session history length",
               hs, [(f"p{q}", [sw[str(h)][f"p{q}_us"] for h in hs]) for q in (50, 95, 99)],
               "prior steps in the principal's governed history (0 plotted at 0.5)",
               "latency (log)", ref=1000)
    for model in ("threads", "processes"):
        f = RESULTS / f"load-{model}-inprocess-isolated.json"
        if not f.exists():
            continue
        S = json.loads(f.read_text())["summaries"]
        ws = [s["workers"] for s in S]
        line_chart(out / f"concurrency_latency_{model}.svg",
                   f"Verdict latency vs concurrency ({model})", ws,
                   [(f"p{q}", [s["verdict_latency"][f"p{q}_us"] for s in S]) for q in (50, 95, 99)],
                   "concurrent workers", "proposal-to-verdict latency (log)", ref=1000)
        line_chart(out / f"throughput_{model}.svg", f"Throughput vs concurrency ({model})", ws,
                   [("proposals/s", [s["throughput_per_s"] for s in S])],
                   "concurrent workers", "completed proposals per second", logy=False,
                   yfmt=lambda v: f"{v:,.0f}")
        stacked_bars(out / f"blocking_{model}.svg",
                     f"Verdicts on prohibited proposals ({model})", ws,
                     [("BLOCK", [s["prohibited"]["block"] for s in S]),
                      ("ESCALATE", [s["prohibited"]["escalate"] for s in S]),
                      ("PERMIT (failure)", [s["prohibited"]["permit"] for s in S])],
                     "concurrent workers", "share of prohibited proposals")
        line_chart(out / f"legit_completion_{model}.svg",
                   f"Legitimate proposals executed ({model})", ws,
                   [("executed %", [100 * s["legitimate"]["executed"] / s["legitimate"]["total"]
                                    for s in S])],
                   "concurrent workers", "% of legitimate proposals executed", logy=False,
                   yfmt=lambda v: f"{v:.0f}%")
    print("charts written to", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
