"""Shared delivery primitives for engagement packs: offline-viewer CSS in the
Resurrection Tech palette, the safe-overwrite guard, checksummed manifest and zip.
No dependency on any particular audit or customer environment."""

from __future__ import annotations

import hashlib
import html
import shutil
import zipfile
from pathlib import Path

MARKER = ".engagement-pack"


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
a{color:var(--ink);overflow-wrap:anywhere}td a.mono{white-space:nowrap;overflow-wrap:normal}code,.mono{font-family:"DejaVu Sans Mono",Menlo,monospace;font-size:12.5px}
.files li{margin:4px 0}
details.rec{border-bottom:1px solid var(--rule);padding:6px 0}
details.rec summary{cursor:pointer;overflow-wrap:anywhere;font-family:"DejaVu Sans",sans-serif;font-size:13px}
details.rec:target,details.rec:target summary{background:#FFF8E6}
pre{background:var(--pale);padding:10px;overflow-x:auto;font-size:12px;line-height:1.4}
footer{margin-top:40px;border-top:1px solid var(--srule);padding-top:8px;display:flex;justify-content:space-between;color:var(--muted);font-family:"DejaVu Sans",sans-serif;font-size:12px;flex-wrap:wrap;gap:8px}
.mark{color:var(--gold);font-family:"DejaVu Sans",sans-serif;font-weight:700;font-size:30px;text-align:center;margin-top:30px}
"""


def _e(x) -> str:
    return html.escape(str(x))


def _fresh(pack: Path) -> None:
    """Replace a previous pack only if this tool created it."""
    if pack.exists():
        if not (pack / MARKER).exists():
            raise SystemExit(f"{pack} exists and was not created by this tool; refusing to overwrite")
        shutil.rmtree(pack)
    pack.mkdir(parents=True)
    (pack / MARKER).write_text("created by audit_demo.engagement\n")


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
